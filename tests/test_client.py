import json
from unittest.mock import patch

import pytest

from agenticdome_sdk.client import (
    AgenticDomeClient,
    AgenticDomeHTTPError,
)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload

        if text is not None:
            self.text = text
        elif payload is None:
            self.text = ""
        else:
            self.text = json.dumps(payload)

        self.ok = 200 <= status_code < 300

    def json(self):
        if self._payload is None:
            raise ValueError("No JSON body")
        return self._payload


def make_response(status_code=200, payload=None, text=None):
    return FakeResponse(status_code=status_code, payload=payload, text=text)


@pytest.mark.parametrize(
    ("field", "kwargs"),
    [
        ("api_base", {"api_base": "", "api_key": "test-api-key", "tenant_id": "tenant-1"}),
        ("api_key", {"api_base": "https://api.example.test", "api_key": "", "tenant_id": "tenant-1"}),
        ("tenant_id", {"api_base": "https://api.example.test", "api_key": "test-api-key", "tenant_id": ""}),
    ],
)
def test_client_requires_api_base_key_and_tenant(field, kwargs):
    with pytest.raises(ValueError, match=field):
        AgenticDomeClient(**kwargs)


@pytest.fixture
def client():
    return AgenticDomeClient(
        api_base="https://api.example.test",
        api_key="test-api-key",
        tenant_id="tenant-1",
        timeout=5,
        max_retries=0,
    )


@patch("agenticdome_sdk.client.requests.Session.request")
def test_guardrail_validate_success(mock_request, client):
    mock_request.return_value = make_response(
        200,
        {
            "verdict": "ALLOWED",
            "reason": "ok",
            "text": "ok",
        },
    )

    result = client.guardrail_validate(
        text="hello",
        agent_id="agent-1",
        direction="outbound",
        platform="microsoft",
        session_id="session-1",
    )

    assert result["verdict"] == "ALLOWED"
    assert result["reason"] == "ok"

    _, kwargs = mock_request.call_args
    assert kwargs["method"] == "POST"
    assert kwargs["url"] == "https://api.example.test/tools/guardrail/validate"

    payload = kwargs["json"]
    assert payload["direction"] == "output"  # SDK normalizes outbound -> output
    assert payload["text"] == "hello"
    assert payload["agent_id"] == "agent-1"
    assert payload["platform"] == "microsoft"


@patch("agenticdome_sdk.client.requests.Session.request")
def test_registered_tool_provenance_is_forwarded_without_runtime_hashing(mock_request, client):
    digest = "sha256:" + "a" * 64
    mock_request.return_value = make_response(200, {"verdict": "ALLOWED"})
    client.register_tool_provenance("crm.lookup", tool_version="4.2.1", tool_digest=digest, tool_platform="mcp")

    client.guardrail_validate(
        text="lookup customer",
        agent_id="support-agent",
        direction="outbound",
        platform="langgraph",
        tool_platform="mcp",
        tool_name="crm.lookup",
        tool_args={"customer_id": "42"},
    )

    payload = mock_request.call_args.kwargs["json"]
    assert payload["tool_version"] == "4.2.1"
    assert payload["tool_digest"] == digest
    assert payload["policy_context"]["tool_digest"] == digest


@patch("agenticdome_sdk.client.requests.Session.request")
def test_registered_provenance_is_bound_to_authorize_and_verify(mock_request, client):
    digest = "sha256:" + "b" * 64
    mock_request.return_value = make_response(200, {"jsonrpc": "2.0", "id": "1", "result": {"verdict": "ALLOWED", "valid": True}})
    client.register_tool_provenance("payments.refund", tool_version="2.0.0", tool_digest=digest)

    client.a2a_authorize_tool(
        text="delegate refund",
        agent_id="billing-agent",
        platform="autogen",
        source_agent_id="manager-agent",
        source_platform="autogen",
        tool_name="payments.refund",
        tool_args={"amount": 25},
    )
    authorize = mock_request.call_args.kwargs["json"]["params"]["arguments"]
    assert authorize["tool_version"] == "2.0.0"
    assert authorize["tool_digest"] == digest

    client.a2a_verify_decision_token_rpc(
        "decision-token",
        tool_name="payments.refund",
        tool_args={"amount": 25},
        agent_id="billing-agent",
        source_agent_id="manager-agent",
        platform="autogen",
    )
    verify = mock_request.call_args.kwargs["json"]["params"]["arguments"]
    assert verify["tool_version"] == "2.0.0"
    assert verify["tool_digest"] == digest


def test_invalid_registered_tool_digest_fails_before_network(client):
    with pytest.raises(ValueError, match="tool_digest"):
        client.register_tool_provenance("unsafe.tool", tool_digest="sha256:not-a-real-digest")


@patch("agenticdome_sdk.client.requests.Session.request")
def test_guardrail_validate_blocks_invalid_tool_pairing(mock_request, client):
    with pytest.raises(ValueError, match="'tool_args' is required"):
        client.guardrail_validate(
            text="execute tool",
            agent_id="agent-1",
            direction="outbound",
            platform="openclaw",
            tool_name="some_tool",
            tool_args=None,
            session_id="session-1",
        )

    mock_request.assert_not_called()


@patch("agenticdome_sdk.client.requests.Session.request")
def test_a2a_authorize_tool(mock_request, client):
    mock_request.return_value = make_response(
        200,
        {
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "verdict": "BLOCKED",
                "reason": "policy blocked",
            },
        },
    )

    result = client.a2a_authorize_tool(
        text="Research Agent requests a refund",
        agent_id="A2A_Billing_Agent",
        platform="crewai",
        source_agent_id="A2A_Research_Agent",
        source_platform="crewai",
        tool_platform="salesforce",
        tool_name="salesforce.billing.refund.issue",
        tool_args={"amount": "5000"},
        session_id="session-a2a-1",
        policy_context={
            "request_purpose": "delegated_task",
            "source_agent_role": "research",
            "target_agent_role": "billing",
        },
    )

    assert "result" in result
    assert result["result"]["verdict"] == "BLOCKED"

    _, kwargs = mock_request.call_args
    assert kwargs["method"] == "POST"
    assert kwargs["url"] == "https://api.example.test/a2a"

    payload = kwargs["json"]
    assert payload["method"] == "actions/call"
    assert payload["params"]["name"] == "security.tool.authorize"

    arguments = payload["params"]["arguments"]
    assert arguments["source_agent_id"] == "A2A_Research_Agent"
    assert arguments["source_platform"] == "crewai"
    assert arguments["agent_id"] == "A2A_Billing_Agent"
    assert arguments["tool_name"] == "salesforce.billing.refund.issue"


@patch("agenticdome_sdk.client.requests.Session.request")
def test_a2a_verify_decision_token_rpc(mock_request, client):
    mock_request.return_value = make_response(
        200,
        {
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "valid": True,
                "reason": "ok",
            },
        },
    )

    result = client.a2a_verify_decision_token_rpc(
        token="decision-token-123",
        tool_name="execute_sql",
        tool_args={"query": "SELECT 1;"},
        agent_id="database-agent",
        source_agent_id="manager-agent",
        platform="openclaw",
        require_allowed=True,
    )

    assert result["result"]["valid"] is True

    _, kwargs = mock_request.call_args
    payload = kwargs["json"]

    assert payload["method"] == "actions/call"
    assert payload["params"]["name"] == "security.decision.verify"
    assert payload["params"]["arguments"]["token"] == "decision-token-123"


@patch("agenticdome_sdk.client.requests.Session.request")
def test_protocol_proof_and_management_endpoints(mock_request, client):
    mock_request.return_value = make_response(200, {"ok": True})

    client.a2a_verify_decision_token(
        "decision-token-123",
        proof_token="signed-dpop-proof",
    )
    _, verify_kwargs = mock_request.call_args
    assert verify_kwargs["url"] == "https://api.example.test/a2a/decision/verify"
    assert verify_kwargs["json"]["proof_token"] == "signed-dpop-proof"
    assert verify_kwargs["json"]["consume"] is True

    client.get_decision_token_status("decision-1")
    _, status_kwargs = mock_request.call_args
    assert status_kwargs["method"] == "GET"
    assert status_kwargs["url"] == "https://api.example.test/a2a/decision/status/decision-1"

    client.revoke_decision_token(user_id="human-1", reason="offboarded")
    _, revoke_kwargs = mock_request.call_args
    assert revoke_kwargs["url"] == "https://api.example.test/a2a/decision/revoke"
    assert revoke_kwargs["json"] == {"user_id": "human-1", "reason": "offboarded"}

    client.get_behavioral_attestation("agent-1")
    _, behavior_kwargs = mock_request.call_args
    assert behavior_kwargs["url"] == "https://api.example.test/trust/behavior/agent-1"

    client.get_behavioral_summary(limit=75)
    _, summary_kwargs = mock_request.call_args
    assert summary_kwargs["url"] == "https://api.example.test/trust/behavior-summary?limit=75"

    client.get_threat_signature_status()
    _, signature_kwargs = mock_request.call_args
    assert signature_kwargs["url"] == "https://api.example.test/security/threat-signatures/status"


@patch("agenticdome_sdk.client.requests.Session.request")
def test_protected_routes_prefer_service_token_and_fall_back_to_bearer(mock_request):
    mock_request.return_value = make_response(200, {"ok": True})
    service_client = AgenticDomeClient(
        api_base="https://api.example.test",
        api_key="test-api-key",
        tenant_id="tenant-1",
        service_token="service-secret",
    )

    service_client.get_behavioral_attestation("agent-1")
    _, service_kwargs = mock_request.call_args
    assert service_kwargs["headers"]["X-Service-Token"] == "service-secret"

    with patch.dict("os.environ", {"AGENTICDOME_SERVICE_TOKEN": "", "SERVICE_SECRET": ""}):
        bearer_client = AgenticDomeClient(
            api_base="https://api.example.test",
            api_key="test-api-key",
            tenant_id="tenant-1",
            bearer_token="bearer-token",
        )
    bearer_client.get_threat_signature_status()
    _, bearer_kwargs = mock_request.call_args
    assert bearer_kwargs["headers"]["Authorization"] == "Bearer bearer-token"
    assert "X-Service-Token" not in bearer_kwargs["headers"]


@patch("agenticdome_sdk.client.requests.Session.request")
def test_mcp_guardrail_validate(mock_request, client):
    mock_request.return_value = make_response(
        200,
        {
            "jsonrpc": "2.0",
            "id": "1",
            "result": {
                "verdict": "BLOCKED",
                "reason": "remote patch blocked",
            },
        },
    )

    result = client.mcp_guardrail_validate(
        text="Download and execute patch from evil url",
        agent_id="MCP_Agent_1",
        direction="outbound",
        platform="mcp",
        tool_platform="mcp",
        tool_name="mcp.execute_remote_patch",
        tool_args={
            "url": "https://evil.example/patch.ps1",
            "execute": True,
        },
        policy_context={
            "request_purpose": "mcp_tool_execution",
        },
    )

    assert "result" in result
    assert result["result"]["verdict"] == "BLOCKED"

    _, kwargs = mock_request.call_args
    payload = kwargs["json"]

    assert payload["method"] == "tools/call"
    assert payload["params"]["name"] == "guardrail.validate"

    arguments = payload["params"]["arguments"]
    assert arguments["direction"] == "output"
    assert arguments["platform"] == "mcp"
    assert arguments["tool_name"] == "mcp.execute_remote_patch"


@patch("agenticdome_sdk.client.requests.Session.request")
def test_mcp_guardrail_uses_registered_tool_provenance(mock_request, client):
    digest = "sha256:" + "d" * 64
    mock_request.return_value = make_response(200, {"jsonrpc": "2.0", "id": "1", "result": {"verdict": "ALLOWED"}})
    client.register_tool_provenance("mcp.customer.lookup", tool_version="1.8.0", tool_digest=digest, tool_platform="mcp")

    client.mcp_guardrail_validate(
        text="lookup customer",
        agent_id="mcp-agent",
        platform="mcp",
        tool_platform="mcp",
        tool_name="mcp.customer.lookup",
        tool_args={"customer_id": "42"},
    )

    arguments = mock_request.call_args.kwargs["json"]["params"]["arguments"]
    assert arguments["tool_version"] == "1.8.0"
    assert arguments["tool_digest"] == digest


@patch("agenticdome_sdk.client.requests.Session.request")
def test_mesh_validate(mock_request, client):
    mock_request.return_value = make_response(
        200,
        {
            "verdict": "REDACTED",
            "reason": "Sensitive content redacted",
            "sanitized_text": "SSN [REDACTED]",
        },
    )

    result = client.mesh_validate(
        agent_id="Meshy1_Output_Agent",
        text="SSN 111-22-3333",
        direction="output",
        platform="openclaw",
        session_id="mesh-session-1",
        policy_context={
            "redact_pii": True,
            "redact_secrets": True,
        },
        redact_pii=True,
        redact_secrets=True,
    )

    assert result["verdict"] == "REDACTED"
    assert result["sanitized_text"] == "SSN [REDACTED]"

    _, kwargs = mock_request.call_args
    assert kwargs["url"] == "https://api.example.test/mesh/validate"

    payload = kwargs["json"]
    assert payload["direction"] == "output"
    assert payload["platform"] == "openclaw"
    assert payload["policy_context"]["platform"] == "openclaw"


@patch("agenticdome_sdk.client.requests.Session.request")
def test_http_error_raises_agenticdome_http_error(mock_request, client):
    mock_request.return_value = make_response(
        403,
        {
            "detail": "Forbidden by policy",
        },
    )

    with pytest.raises(AgenticDomeHTTPError) as exc_info:
        client.guardrail_validate(
            text="hello",
            agent_id="agent-1",
            direction="input",
            platform="openclaw",
            session_id="session-1",
        )

    assert exc_info.value.status_code == 403
    assert "Forbidden by policy" in str(exc_info.value)


@patch("agenticdome_sdk.client.requests.Session.request")
def test_empty_json_response_returns_empty_dict(mock_request, client):
    mock_request.return_value = make_response(
        204,
        payload=None,
        text="",
    )

    result = client.get_mesh_topology()

    assert result == {}
