import asyncio
from types import SimpleNamespace

import pytest

from agenticdome_sdk.openai_agents import (
    AgenticDomeOpenAIAgentsFirewall,
    DecisionTokenRecord,
    FirewallConfig,
    InMemoryDecisionTokenStore,
    OpenAIAgentsFirewallDenied,
)


class FakeClient:
    def __init__(self):
        self.guardrail_verdict = "ALLOWED"
        self.guardrail_response = None
        self.mesh_response = None
        self.verify_valid = True
        self.raise_guardrail = None
        self.guardrail_failures_remaining = 0
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if self.guardrail_failures_remaining > 0:
            self.guardrail_failures_remaining -= 1
            raise RuntimeError("temporary network down")
        if self.raise_guardrail:
            raise self.raise_guardrail
        if self.guardrail_response is not None:
            return self.guardrail_response
        return {"verdict": self.guardrail_verdict, "reason": "test policy"}

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        if self.mesh_response is not None:
            return self.mesh_response
        return {"verdict": "ALLOWED", "sanitized_text": kwargs["text"]}

    def a2a_authorize_tool(self, **kwargs):
        self.calls.append(("a2a_authorize_tool", kwargs))
        return {"result": {"verdict": "ALLOWED", "decision_token": "token-ok", "reason": "ok"}}

    def a2a_verify_decision_token_rpc(self, token, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", {"token": token, **kwargs}))
        return {"result": {"valid": self.verify_valid and token == "token-ok", "reason": "verified"}}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        return None


def make_firewall(*, fail_closed=True, **overrides):
    client = FakeClient()
    config_kwargs = dict(
        api_base="https://demo-sidecar.agenticdome.io",
        api_key="test-key",
        tenant_id="test-tenant",
        fail_closed=fail_closed,
        report_incidents=False,
        retry_backoff_s=0,
        audit_logging=False,
        otel_enabled=False,
    )
    config_kwargs.update(overrides)
    fw = AgenticDomeOpenAIAgentsFirewall(
        FirewallConfig(**config_kwargs),
        client=client,
        token_store=InMemoryDecisionTokenStore("test-tenant"),
    )
    return fw, client


def test_screen_input_blocks_prompt():
    fw, client = make_firewall()
    client.guardrail_verdict = "BLOCKED"

    with pytest.raises(OpenAIAgentsFirewallDenied):
        asyncio.run(fw.screen_input(session_id="s1", agent_id="agent-a", text="bad"))


def test_production_mode_requires_stable_session_id_in_context():
    fw, _ = make_firewall(production_mode=True, require_stable_session_id_in_prod=True)

    secured = fw.wrap_tool_handler(tool_name="crm.customer.read", handler=lambda ctx, args: args)

    with pytest.raises(OpenAIAgentsFirewallDenied):
        asyncio.run(secured(SimpleNamespace(agent_id="agent-a"), {"customer_id": "cust_123"}))


def test_wrap_tool_handler_authorizes_and_preserves_structured_output():
    fw, client = make_firewall()

    def handler(ctx, args):
        return {"customer_id": args["customer_id"], "ok": True}

    secured = fw.wrap_tool_handler(tool_name="crm.customer.read", handler=handler, tool_platform="crm")
    result = asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"customer_id": "cust_123"}))

    assert result == {"customer_id": "cust_123", "ok": True}
    assert client.calls[0][0] == "guardrail_validate"
    assert client.calls[0][1]["tool_name"] == "crm.customer.read"
    assert client.calls[1][0] == "mesh_validate"


def test_wrap_tool_handler_does_not_execute_blocked_tool():
    fw, client = make_firewall()
    client.guardrail_verdict = "BLOCKED"
    executed = {"value": False}

    def handler(ctx, args):
        executed["value"] = True
        return "should not happen"

    secured = fw.wrap_tool_handler(tool_name="blocked", handler=handler)

    with pytest.raises(OpenAIAgentsFirewallDenied):
        asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {}))

    assert executed["value"] is False


def test_direct_tool_authorization_strips_private_args():
    fw, client = make_firewall()

    asyncio.run(fw.authorize_direct_tool_call(
        session_id="s1",
        agent_id="agent-a",
        source_agent_id=None,
        tool_name="crm.lookup",
        tool_args={"customer_id": "cust_123", "_AgenticDome_decision_token": "secret"},
        text="lookup",
    ))

    assert client.calls[0][1]["tool_args"] == {"customer_id": "cust_123"}


def test_wrap_tool_handler_applies_sanitized_args():
    fw, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"customer_id": "safe", "_AgenticDome_decision_token": "drop"}}}

    def handler(ctx, args):
        return {"customer_id": args["customer_id"]}

    original = {"customer_id": "unsafe"}
    secured = fw.wrap_tool_handler(tool_name="crm.customer.read", handler=handler, tool_platform="crm")
    result = asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), original))

    assert result == {"customer_id": "safe"}
    assert original == {"customer_id": "safe"}


def test_tool_schema_validation_blocks_bad_args():
    fw, _ = make_firewall()
    secured = fw.wrap_tool_handler(
        tool_name="crm.customer.read",
        handler=lambda ctx, args: args,
        tool_schema={"required": ["customer_id"], "properties": {"customer_id": {"type": "string"}}},
    )

    with pytest.raises(OpenAIAgentsFirewallDenied):
        asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"customer_id": 123}))


def test_authorize_manager_handoff_stores_token_with_hmac():
    fw, client = make_firewall(token_hmac_secret="secret")

    result = asyncio.run(fw.authorize_manager_handoff(
        session_id="s1",
        manager_agent_id="manager",
        specialist_agent_id="specialist",
        tool_name="refund.create",
        tool_args={"amount": 250, "_AgenticDome_decision_token": "old"},
        text="delegate refund",
        tool_platform="payments",
    ))

    assert result["decision_token"] == "token-ok"
    assert client.calls[0][0] == "a2a_authorize_tool"
    assert client.calls[0][1]["tool_args"] == {"amount": 250}
    pending = fw.token_store.get(session_id="s1", target_agent_id="specialist", tool_name="refund.create", tool_args={"amount": 250})
    assert pending is not None
    assert pending.token_hmac


def test_wrap_delegated_tool_handler_verifies_token_consumes_store_and_sanitizes():
    fw, client = make_firewall(token_hmac_secret="secret")
    record = DecisionTokenRecord("token-ok", "manager", 1.0, token_hmac=fw._token_hmac("token-ok"))
    fw.token_store.put(session_id="s1", target_agent_id="specialist", tool_name="refund.create", tool_args={"amount": 250}, record=record, ttl_s=900)

    def handler(ctx, args):
        return {"refund": True}

    secured = fw.wrap_delegated_tool_handler(tool_name="refund.create", handler=handler)
    result = asyncio.run(secured(SimpleNamespace(agent_id="specialist", session_id="s1"), {"amount": 250}))

    assert result == {"refund": True}
    assert client.calls[0][0] == "a2a_verify_decision_token_rpc"
    assert fw.token_store.get(session_id="s1", target_agent_id="specialist", tool_name="refund.create", tool_args={"amount": 250}) is None


def test_sanitize_output_returns_redacted_text():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "email [REDACTED]"}

    result = asyncio.run(fw.sanitize_output(session_id="s1", agent_id="agent-a", text="email alice@example.com"))

    assert result == "email [REDACTED]"


def test_structured_output_parses_sanitized_json():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "ALLOWED", "sanitized_text": '{"email":"[REDACTED]"}'}

    result = asyncio.run(fw._sanitize_result(raw_result={"email": "a@example.com"}, session_id="s1", agent_id="agent-a", policy_context={}, preserve_structured_output=True))

    assert result == {"email": "[REDACTED]"}


def test_run_agent_securely_wraps_runner_and_updates_result():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "final [REDACTED]"}

    class Runner:
        async def run(self, agent, input, session_id, **kwargs):
            return SimpleNamespace(final_output=f"final {input}")

    result = asyncio.run(fw.run_agent_securely(runner=Runner(), agent=SimpleNamespace(name="agent-a"), input_text="secret", session_id="s1"))

    assert result.final_output == "final [REDACTED]"
    assert client.calls[0][0] == "guardrail_validate"
    assert client.calls[1][0] == "mesh_validate"


def test_streaming_sanitization_blocks_on_chunk():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "BLOCKED", "reason": "secret"}

    async def chunks():
        yield "secret"
        yield "more"

    async def collect():
        out = []
        async for chunk in fw.sanitize_streaming_response(chunks(), session_id="s1", agent_id="agent-a"):
            out.append(chunk)
        return out

    assert asyncio.run(collect()) == ["[OUTPUT BLOCKED BY AgenticDome]"]


def test_guardrail_helpers_screen_and_sanitize():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "safe"}

    input_guardrail = fw.create_input_guardrail()
    output_guardrail = fw.create_output_guardrail()

    asyncio.run(input_guardrail(SimpleNamespace(session_id="s1"), SimpleNamespace(name="agent-a"), "hello"))
    result = asyncio.run(output_guardrail(SimpleNamespace(session_id="s1"), SimpleNamespace(name="agent-a"), "unsafe"))

    assert result == "safe"


def test_rate_limit_blocks_excess_input_calls():
    fw, _ = make_firewall(rate_limit_per_minute=1)

    asyncio.run(fw.screen_input(session_id="s1", agent_id="agent-a", text="hello"))
    with pytest.raises(OpenAIAgentsFirewallDenied):
        asyncio.run(fw.screen_input(session_id="s1", agent_id="agent-a", text="again"))


def test_size_limit_blocks_large_tool_args():
    fw, _ = make_firewall(max_tool_arg_chars=10)
    secured = fw.wrap_tool_handler(tool_name="large", handler=lambda ctx, args: args)

    with pytest.raises(OpenAIAgentsFirewallDenied):
        asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"payload": "x" * 100}))


def test_retry_allows_transient_guardrail_failure():
    fw, client = make_firewall(retry_attempts=2)
    client.guardrail_failures_remaining = 1

    asyncio.run(fw.screen_input(session_id="s1", agent_id="agent-a", text="hello"))

    assert len([call for call in client.calls if call[0] == "guardrail_validate"]) == 2


def test_fail_open_allows_guardrail_error():
    fw, client = make_firewall(fail_closed=False)
    client.raise_guardrail = RuntimeError("network down")

    result = asyncio.run(fw.screen_input(session_id="s1", agent_id="agent-a", text="hello"))

    assert result == {}


def test_secure_tool_decorator_wraps_handler():
    fw, _ = make_firewall()

    @fw.secure_tool(tool_name="crm.lookup", tool_platform="crm")
    def lookup(ctx, args):
        return {"ok": args["ok"]}

    result = asyncio.run(lookup(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"ok": True}))

    assert result == {"ok": True}
