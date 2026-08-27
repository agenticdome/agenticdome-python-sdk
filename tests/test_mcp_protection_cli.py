import json
import asyncio
from pathlib import Path

from agenticdome_sdk import onboarding_cli
from agenticdome_sdk.mcp_verification import run_mcp_transport_verification
from agenticdome_sdk.mcp_http_gateway import MCPHTTPGatewayConfig, _review_sse_event


def test_mcp_inspection_is_source_free_and_finds_role_transport_and_bypass(tmp_path: Path):
    (tmp_path / "gateway.py").write_text(
        "from mcp import ClientSession\n"
        "from mcp.client.stdio import stdio_client\n"
        "async def forward(session, request, agent_id, session_id, user_id, business_purpose):\n"
        "    return await session.call_tool(request)\n",
        encoding="utf-8",
    )

    report = onboarding_cli.inspect_repository(tmp_path)
    mcp = report["mcp_protection"]

    assert mcp["source_upload"] is False
    assert mcp["detected"] is True
    assert "client" in mcp["roles"]
    assert "stdio" in mcp["transports"]
    assert mcp["identity_context"]["complete"] is True
    assert mcp["bypass_findings"][0]["classification"] == "raw_mcp_forwarding_requires_review"
    serialized = json.dumps(mcp)
    assert "session.call_tool(request)" not in serialized


def test_mcp_scaffold_contains_python_typescript_and_registry_contracts():
    plan = {
        "languages": ["python", "typescript/javascript"],
        "mcp_protection": {
            "detected": True,
            "servers": [{"id": "server-safe", "path": "gateway.py", "line": 1}],
            "bypass_findings": [],
        },
        "coverage": {"gaps": []},
        "hook_catalog": {"schema": "test", "digest": "sha256:test", "verified_at": "test"},
        "framework_hook_plans": [],
        "semantic_analysis": {},
        "semantic_gate": {},
    }
    files = onboarding_cli._scaffold_files({"frameworks": ["mcp"]}, plan)

    assert "agenticdome_mcp_gateway.py" in files
    assert "AgenticDomeMCPGateway" in files["agenticdome_mcp_gateway.ts"]
    assert "MCP-SERVER-REGISTRY.json" in files
    assert "REQUIRED_SECRET_MANAGER_REFERENCE" in files["MCP-SERVER-REGISTRY.json"]
    assert "Silently" not in files["MCP-REVIEW.md"]


def test_real_stdio_transport_rehearsal_proves_all_mcp_cases():
    result = run_mcp_transport_verification()

    assert result["real_transport_rehearsal"] is True
    assert result["transport"] == "stdio_and_streamable_http_sse"
    assert result["ready"] is True
    assert result["transport_contracts"]["stdio"]["ready"] is True
    assert result["transport_contracts"]["streamable_http"]["ready"] is True
    assert {item["case"] for item in result["cases"]} == {
        "allowed_exactly_once",
        "dangerous_arguments_sanitized",
        "response_redacted",
        "blocked_never_forwarded",
        "tool_list_filtered",
        "poisoned_response_redacted",
        "policy_outage_fail_closed",
    }


def test_low_code_gateway_requires_fixed_upstream_and_real_identity(monkeypatch):
    values = {
        "AGENTICDOME_MCP_UPSTREAM_URL": "https://mcp.customer.example/rpc",
        "AGENTICDOME_MCP_SERVER_ID": "customer-mcp",
        "AGENTICDOME_MCP_AGENT_ID": "order-assistant",
        "AGENTICDOME_MCP_BUSINESS_PURPOSE": "look_up_customer_orders",
        "AGENTICDOME_MCP_TRUST_IDENTITY_HEADERS": "true",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    config = MCPHTTPGatewayConfig.from_env()

    assert config.upstream_url == values["AGENTICDOME_MCP_UPSTREAM_URL"]
    assert config.agent_id == "order-assistant"
    assert config.business_purpose == "look_up_customer_orders"


def test_low_code_gateway_reviews_json_rpc_inside_sse_event():
    class Firewall:
        async def review_forwarded_response(self, **kwargs):
            response = dict(kwargs["response"])
            response["result"] = {"content": "[REDACTED]"}
            return response

        @staticmethod
        def jsonrpc_error(request_id, code, message):
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    reviewed = asyncio.run(_review_sse_event(
        Firewall(),
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}},
        ["event: message", 'data: {"jsonrpc":"2.0","id":1,"result":{"content":"secret"}}'],
        {"agent_id": "agent", "session_id": "session"},
    ))

    assert "secret" not in "\n".join(reviewed)
    assert "[REDACTED]" in "\n".join(reviewed)


def test_low_code_gateway_blocks_legacy_sse_endpoint_advertisement():
    class Firewall:
        @staticmethod
        def jsonrpc_error(request_id, code, message):
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    reviewed = asyncio.run(_review_sse_event(
        Firewall(),
        {},
        ["event: endpoint", "data: https://upstream.example/messages"],
        {"agent_id": "agent", "session_id": "session"},
    ))

    assert "upstream.example" not in "\n".join(reviewed)
    assert "requires a reviewed local adapter" in "\n".join(reviewed)
