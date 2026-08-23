import asyncio
from types import SimpleNamespace

import pytest

from agenticdome_sdk.google_adk import AgenticDomeGoogleADKFirewall, FirewallConfig, GoogleADKDenied


class FakeClient:
    def __init__(self):
        self.guardrail_response = {"result": {"verdict": "ALLOWED", "reason": "ok"}}
        self.mesh_response = None
        self.calls = []
        self.raise_on_guardrail = None
        self.guardrail_failures_remaining = 0

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if self.guardrail_failures_remaining > 0:
            self.guardrail_failures_remaining -= 1
            raise RuntimeError("temporary network down")
        if self.raise_on_guardrail:
            raise self.raise_on_guardrail
        return self.guardrail_response

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        if self.mesh_response is not None:
            return self.mesh_response
        return {"result": {"verdict": "ALLOWED", "sanitized_text": kwargs["text"]}}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}


def make_firewall(*, fail_closed=True, **overrides):
    client = FakeClient()
    config_kwargs = dict(
        api_base="https://demo-sidecar.agenticdome.io",
        api_key="key",
        tenant_id="tenant",
        fail_closed=fail_closed,
        report_incidents=False,
        retry_backoff_s=0,
        audit_logging=False,
        otel_enabled=False,
    )
    config_kwargs.update(overrides)
    fw = AgenticDomeGoogleADKFirewall(config=FirewallConfig(**config_kwargs), client=client)
    return fw, client


def test_before_model_screens_request():
    fw, client = make_firewall()
    ctx = SimpleNamespace(agent_name="agent-a", session_id="s1")
    request = SimpleNamespace(contents=[{"parts": [{"text": "hello"}]}])

    result = asyncio.run(fw.before_model(ctx, request))

    assert result is None
    assert client.calls[0][0] == "guardrail_validate"
    assert client.calls[0][1]["direction"] == "input"
    assert client.calls[0][1]["agent_id"] == "agent-a"


def test_before_model_blocks_request():
    fw, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "BLOCKED", "reason": "bad prompt"}}

    with pytest.raises(GoogleADKDenied):
        asyncio.run(fw.before_model(SimpleNamespace(agent_name="agent-a", session_id="s1"), {"text": "bad"}))


def test_production_mode_requires_stable_session_id():
    fw, _ = make_firewall(production_mode=True, require_stable_session_id_in_prod=True)

    with pytest.raises(GoogleADKDenied):
        asyncio.run(fw.before_model(SimpleNamespace(agent_name="agent-a"), {"text": "hello"}))


def test_after_model_sanitizes_nested_response_object():
    fw, client = make_firewall()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "safe output"}}
    response = SimpleNamespace(content=SimpleNamespace(parts=[SimpleNamespace(text="unsafe alice@example.com")]))

    result = asyncio.run(fw.after_model(SimpleNamespace(agent_name="agent-a", session_id="s1"), response))

    assert result.content.parts[0].text == "safe output"
    assert client.calls[-1][0] == "mesh_validate"


def test_before_tool_authorizes_tool_and_strips_internal_args():
    fw, client = make_firewall()
    tool = SimpleNamespace(name="crm.lookup")

    result = asyncio.run(fw.before_tool(tool, {"customer_id": "cust_123", "_agenticdome_decision_token": "secret"}, SimpleNamespace(agent_name="agent-a", session_id="s1")))

    assert result is None
    call = client.calls[0][1]
    assert call["direction"] == "delegated_execution"
    assert "_agenticdome_decision_token" not in call["tool_args"]


def test_direct_tool_authorization_strips_internal_metadata():
    fw, client = make_firewall()

    asyncio.run(fw.authorize_tool_call(
        tool_name="crm.lookup",
        tool_args={"customer_id": "cust_123", "_agenticdome_source_agent_id": "manager"},
        tool_context=SimpleNamespace(agent_name="agent-a", session_id="s1"),
    ))

    call = client.calls[0][1]
    assert call["direction"] == "outbound"
    assert call["tool_args"] == {"customer_id": "cust_123"}


def test_before_tool_uses_token_store_fallback_without_private_args():
    fw, client = make_firewall(token_hmac_secret="secret")
    record = asyncio.run(fw.authorize_manager_handoff(
        source_agent_id="manager",
        target_agent_id="specialist",
        target_tool_name="crm.lookup",
        target_tool_args={"customer_id": "1"},
        tool_context=SimpleNamespace(agent_name="manager", session_id="s1"),
    ))
    assert record.decision_token
    client.calls.clear()

    asyncio.run(fw.before_tool("crm.lookup", {"customer_id": "1"}, SimpleNamespace(agent_name="specialist", session_id="s1")))

    assert client.calls[0][1]["direction"] == "delegated_execution"
    assert client.calls[0][1]["decision_token"] == record.decision_token


def test_before_tool_applies_sanitized_args_in_place():
    fw, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"query": "safe", "_agenticdome_decision_token": "drop"}}}
    args = {"query": "unsafe"}

    asyncio.run(fw.before_tool(SimpleNamespace(name="search"), args, SimpleNamespace(agent_name="agent-a", session_id="s1")))

    assert args == {"query": "safe"}


def test_tool_schema_validation_blocks_bad_args():
    fw, _ = make_firewall()
    tool = SimpleNamespace(name="search", schema={"required": ["query"], "properties": {"query": {"type": "string"}}})

    with pytest.raises(GoogleADKDenied):
        asyncio.run(fw.before_tool(tool, {"query": 123}, SimpleNamespace(agent_name="agent-a", session_id="s1")))


def test_after_tool_preserves_structured_result_when_unchanged():
    fw, _ = make_firewall()
    result = asyncio.run(fw.after_tool("crm.lookup", {}, SimpleNamespace(agent_name="agent-a", session_id="s1"), {"ok": True}))

    assert result == {"ok": True}


def test_after_tool_parses_sanitized_structured_json():
    fw, client = make_firewall()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": '{"email":"[REDACTED]"}'}}

    result = asyncio.run(fw.after_tool("crm.lookup", {}, SimpleNamespace(agent_name="agent-a", session_id="s1"), {"email": "a@example.com"}))

    assert result == {"email": "[REDACTED]"}


def test_install_on_agent_sets_callbacks():
    fw, _ = make_firewall()
    agent = SimpleNamespace()

    result = fw.install_on_agent(agent, prefer_async=True)

    assert result is agent
    assert agent.before_model_callback == fw.before_model
    assert agent.after_tool_callback == fw.after_tool
    assert agent.before_agent_callback == fw.before_agent


def test_build_callback_kwargs_and_plugin_object():
    fw, _ = make_firewall()

    callbacks = fw.build_callback_kwargs()
    plugin = fw.create_plugin()

    assert callbacks["before_model_callback"] == fw.before_model
    assert plugin.before_tool_callback == fw.before_tool
    assert plugin.name == "agenticdome_google_adk_firewall"


def test_secure_tool_decorator_wraps_handler_with_sanitized_args():
    fw, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"ok": True}}}

    @fw.secure_tool(tool_name="crm.lookup", tool_platform="crm")
    def lookup(ctx, args):
        return {"ok": args["ok"]}

    result = asyncio.run(lookup(SimpleNamespace(agent_name="agent-a", session_id="s1"), {"ok": False}))

    assert result == {"ok": True}


def test_fail_open_allows_guardrail_error():
    fw, client = make_firewall(fail_closed=False)
    client.raise_on_guardrail = RuntimeError("network down")

    result = asyncio.run(fw.screen_model_request(callback_context=SimpleNamespace(agent_name="agent-a", session_id="s1"), llm_request="hello"))

    assert result == {}


def test_size_limit_blocks_large_tool_args():
    fw, _ = make_firewall(max_tool_arg_chars=10)

    with pytest.raises(GoogleADKDenied):
        asyncio.run(fw.before_tool("large", {"payload": "x" * 100}, SimpleNamespace(agent_name="agent-a", session_id="s1")))


def test_rate_limit_blocks_excess_calls():
    fw, _ = make_firewall(rate_limit_per_minute=1)
    ctx = SimpleNamespace(agent_name="agent-a", session_id="s1")

    asyncio.run(fw.before_model(ctx, "hello"))
    with pytest.raises(GoogleADKDenied):
        asyncio.run(fw.before_model(ctx, "hello again"))


def test_retry_allows_transient_guardrail_failure():
    fw, client = make_firewall(retry_attempts=2)
    client.guardrail_failures_remaining = 1

    asyncio.run(fw.before_model(SimpleNamespace(agent_name="agent-a", session_id="s1"), "hello"))

    assert len([call for call in client.calls if call[0] == "guardrail_validate"]) == 2


def test_handoff_stores_clean_args_and_injects_token():
    fw, client = make_firewall(token_hmac_secret="secret")
    client.guardrail_response = {"result": {"verdict": "ALLOWED", "decision_token": "token-1"}}
    args = {
        "target_agent_id": "specialist",
        "target_tool_name": "filesystem.read",
        "target_tool_args": {"path": "/tmp/a", "_agenticdome_decision_token": "old"},
    }

    asyncio.run(fw.before_tool("handoff", args, SimpleNamespace(agent_name="manager", session_id="s1")))
    record = fw.token_store.consume(session_id="s1", target_agent_id="specialist", tool_name="filesystem.read", tool_args={"path": "/tmp/a"})

    assert args["_agenticdome_decision_token"] == "token-1"
    assert args["target_tool_args"]["_agenticdome_decision_token"] == "token-1"
    assert record is not None
    assert record.decision_token == "token-1"


def test_verify_delegated_execution_uses_token_store_fallback():
    fw, client = make_firewall(token_hmac_secret="secret")
    record = asyncio.run(fw.authorize_manager_handoff(
        source_agent_id="manager",
        target_agent_id="specialist",
        target_tool_name="crm.lookup",
        target_tool_args={"customer_id": "1"},
        tool_context=SimpleNamespace(agent_name="manager", session_id="s1"),
    ))
    assert record.decision_token
    client.calls.clear()

    asyncio.run(fw.verify_delegated_execution(
        target_agent_id="specialist",
        tool_name="crm.lookup",
        tool_args={"customer_id": "1"},
        tool_context=SimpleNamespace(agent_name="specialist", session_id="s1"),
    ))

    assert client.calls[0][1]["direction"] == "delegated_execution"
    assert client.calls[0][1]["decision_token"] == record.decision_token


def test_streaming_sanitization_blocks_on_chunk():
    fw, client = make_firewall()
    client.mesh_response = {"result": {"verdict": "BLOCKED", "reason": "secret"}}

    async def chunks():
        yield "secret"
        yield "more"

    async def collect():
        out = []
        async for chunk in fw.sanitize_streaming_response(chunks(), agent_id="agent-a", session_id="s1"):
            out.append(chunk)
        return out

    assert asyncio.run(collect()) == ["[OUTPUT BLOCKED BY AgenticDome]"]
