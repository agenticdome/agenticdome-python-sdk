import asyncio

from agenticdome_sdk.mcp_host import AgenticDomeMCPHostFirewall, FirewallConfig


class FakeClient:
    def __init__(self):
        self.calls = []
        self.mcp_response = {"result": {"verdict": "ALLOWED", "reason": "ok"}}
        self.guardrail_response = {"result": {"verdict": "ALLOWED", "reason": "ok"}}
        self.mesh_response = {"result": {"verdict": "ALLOWED"}}
        self.verify_response = {"result": {"valid": True, "reason": "ok"}}
        self.raise_on_mcp = False

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        return self.guardrail_response

    def mcp_guardrail_validate(self, **kwargs):
        self.calls.append(("mcp_guardrail_validate", kwargs))
        if self.raise_on_mcp:
            raise RuntimeError("service down")
        return self.mcp_response

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        return self.mesh_response

    def a2a_verify_decision_token_rpc(self, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", kwargs))
        return self.verify_response

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        self.calls.append(("close", {}))


def make_firewall(client=None, **overrides):
    config = FirewallConfig(
        api_base="https://example.test",
        api_key="key",
        tenant_id="tenant",
        **overrides,
    )
    return AgenticDomeMCPHostFirewall(config=config, client=client or FakeClient())


def tools_call(arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {"name": "search_crm", "arguments": arguments or {"query": "alice"}},
    }


def test_preflight_non_tool_request_passthrough():
    firewall = make_firewall()
    request = {"jsonrpc": "2.0", "id": 1, "method": "resources/list"}

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert result is request


def test_preflight_authorizes_tools_call_and_strips_internal_args():
    client = FakeClient()
    firewall = make_firewall(client=client)
    request = tools_call({"query": "alice", "_AgenticDome_private": "secret"})

    result = asyncio.run(
        firewall.preflight_request(
            mcp_request=request,
            context={"session_id": "s1", "user_prompt": "find customer", "host_id": "host-a"},
        )
    )

    assert result["params"]["arguments"] == {"query": "alice"}
    assert [name for name, _ in client.calls] == ["guardrail_validate", "mcp_guardrail_validate"]
    mcp_call = client.calls[-1][1]
    assert mcp_call["tool_name"] == "search_crm"
    assert mcp_call["tool_args"] == {"query": "alice"}
    assert mcp_call["agent_id"] == "host-a"


def test_preflight_blocks_tools_call_as_jsonrpc_error():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "BLOCKED", "reason": "not allowed"}}
    firewall = make_firewall(client=client)

    result = asyncio.run(firewall.preflight_request(mcp_request=tools_call(), context={"session_id": "s1"}))

    assert result["error"]["code"] == -32000
    assert "not allowed" in result["error"]["message"]
    assert ("report_incident",) == tuple([client.calls[-1][0]])


def test_forward_with_firewall_does_not_forward_when_blocked():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "BLOCKED", "reason": "blocked"}}
    firewall = make_firewall(client=client)
    forwarded = {"called": False}

    async def forward(_request):
        forwarded["called"] = True
        return {"jsonrpc": "2.0", "id": "req-1", "result": {}}

    result = asyncio.run(
        firewall.forward_with_firewall(
            mcp_request=tools_call(),
            context={"session_id": "s1"},
            forward_to_third_party=forward,
        )
    )

    assert "error" in result
    assert forwarded["called"] is False


def test_decision_token_is_verified_and_stripped_before_forwarding():
    client = FakeClient()
    firewall = make_firewall(client=client)
    request = tools_call(
        {
            "customer_id": "c1",
            "_AgenticDome_decision_token": "tok",
            "_AgenticDome_source_agent_id": "manager",
        }
    )

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert result["params"]["arguments"] == {"customer_id": "c1"}
    verify_call = client.calls[0]
    assert verify_call[0] == "a2a_verify_decision_token_rpc"
    assert verify_call[1]["token"] == "tok"
    assert verify_call[1]["source_agent_id"] == "manager"
    assert verify_call[1]["tool_args"] == {"customer_id": "c1"}


def test_partial_decision_token_blocks_request():
    firewall = make_firewall()
    request = tools_call({"customer_id": "c1", "_AgenticDome_decision_token": "tok"})

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert "error" in result
    assert "decision token" in result["error"]["message"]


def test_forward_with_firewall_sanitizes_mcp_text_content():
    client = FakeClient()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "email [REDACTED]"}}
    firewall = make_firewall(client=client)

    async def forward(request):
        assert request["params"]["arguments"] == {"query": "alice"}
        return {
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {"content": [{"type": "text", "text": "email alice@example.com"}]},
        }

    result = asyncio.run(
        firewall.forward_with_firewall(
            mcp_request=tools_call(),
            context={"session_id": "s1"},
            forward_to_third_party=forward,
        )
    )

    assert result["result"]["content"][0]["text"] == "email [REDACTED]"
    assert any(name == "mesh_validate" for name, _ in client.calls)


def test_structured_result_is_preserved_when_sanitizer_returns_same_json():
    client = FakeClient()
    structured = {"structuredContent": {"ok": True, "count": 1}}
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": '{"structuredContent": {"count": 1, "ok": true}}'}}
    firewall = make_firewall(client=client)

    result = asyncio.run(firewall.sanitize_mcp_result(tool_output=structured, context={"session_id": "s1"}))

    assert result == structured


def test_fail_open_returns_original_request_on_authorization_error():
    client = FakeClient()
    client.raise_on_mcp = True
    firewall = make_firewall(client=client, fail_closed=False)
    request = tools_call({"query": "alice"})

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert result == request


def test_invalid_request_returns_jsonrpc_invalid_request():
    firewall = make_firewall()

    result = asyncio.run(firewall.preflight_request(mcp_request=[], context={}))

    assert result["error"]["code"] == -32600
