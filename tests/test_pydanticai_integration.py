import asyncio
import sys
import types
from types import SimpleNamespace

import pytest


try:
    import pydantic_ai  # noqa: F401
except Exception:
    pydantic_ai = types.ModuleType("pydantic_ai")
    pydantic_ai.Agent = object
    pydantic_ai.RunContext = object
    models = types.ModuleType("pydantic_ai.models")
    models.ModelResponse = object

    class _HookOn:
        def __getattr__(self, name):
            def decorator(fn=None, **kwargs):
                if fn is None:
                    return lambda real_fn: real_fn
                return fn
            return decorator

    class Hooks:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            self.on = _HookOn()

    capabilities = types.ModuleType("pydantic_ai.capabilities")
    capabilities.Hooks = Hooks
    sys.modules["pydantic_ai"] = pydantic_ai
    sys.modules["pydantic_ai.models"] = models
    sys.modules["pydantic_ai.capabilities"] = capabilities


from agenticdome_sdk.pydantic import (
    CyberSecFirewall,
    DecisionTokenRecord,
    FirewallConfig,
    InMemoryDecisionTokenStore,
    PydanticAIFirewallConfigurationError,
    PydanticAIFirewallDenied,
)


class FakeClient:
    def __init__(self):
        self.guardrail_response = {"verdict": "ALLOWED"}
        self.mesh_response = None
        self.a2a_response = {"result": {"verdict": "ALLOWED", "decision_token": "tok-1"}}
        self.verify_response = {"valid": True, "allowed": True}
        self.failures_remaining = 0
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise RuntimeError("temporary")
        return self.guardrail_response

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        if self.mesh_response is not None:
            return self.mesh_response
        return {"verdict": "ALLOWED", "sanitized_text": kwargs["text"]}

    def a2a_authorize_tool(self, **kwargs):
        self.calls.append(("a2a_authorize_tool", kwargs))
        return self.a2a_response

    def a2a_verify_decision_token_rpc(self, token, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", {"token": token, **kwargs}))
        return self.verify_response

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}


def make_firewall(**overrides):
    client = FakeClient()
    config = FirewallConfig(
        api_base="https://au.agenticdome.io",
        api_key="test-key",
        tenant_id="test-tenant",
        retry_backoff_s=0,
        audit_logging=False,
        otel_enabled=False,
        report_incidents=False,
        **overrides,
    )
    firewall = CyberSecFirewall(config=config, client=client)
    firewall.token_store = InMemoryDecisionTokenStore("test-tenant")
    return firewall, client


def ctx(**kwargs):
    data = {"agent_name": "agent-a", "session_id": "s1"}
    data.update(kwargs)
    return SimpleNamespace(**data)


def test_pydanticai_firewall_imports():
    firewall, _ = make_firewall()

    assert firewall.config.api_base == "https://au.agenticdome.io"
    assert firewall.config.platform == "pydanticai"
    assert hasattr(firewall, "secure_tool")
    assert hasattr(firewall, "attach_to_agent")
    assert hasattr(firewall, "create_hooks")


def test_requires_config():
    with pytest.raises(PydanticAIFirewallConfigurationError):
        CyberSecFirewall(config=FirewallConfig(api_base="", api_key="", tenant_id=""))


def test_production_requires_stable_session_id():
    firewall, _ = make_firewall(production_mode=True)

    with pytest.raises(PydanticAIFirewallDenied):
        asyncio.run(firewall._pre_execute_tool_check(SimpleNamespace(agent_name="agent-a"), "tool", {}))


def test_block_on_sensitive_output_does_not_block_allowed_redaction():
    firewall, client = make_firewall(block_on_sensitive_output=True)
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "email [REDACTED]"}

    result = asyncio.run(firewall.sanitize_text(text="email alice@example.com", agent_id="agent-a", session_id="s1"))

    assert result == "email [REDACTED]"


def test_blocked_output_returns_marker():
    firewall, client = make_firewall(block_on_sensitive_output=True)
    client.mesh_response = {"verdict": "BLOCKED", "reason": "secret"}

    result = asyncio.run(firewall.sanitize_text(text="secret", agent_id="agent-a", session_id="s1"))

    assert result == "[BLOCKED BY AGENTICDOME ACTION LAYER DLP]"


def test_structured_output_sanitization_parses_json():
    firewall, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": '{"email":"[REDACTED]"}'}

    result = asyncio.run(firewall._post_execute_tool_sanitize(ctx(), {"email": "alice@example.com"}))

    assert result == {"email": "[REDACTED]"}


def test_direct_tool_uses_sanitized_args_and_strips_private_args():
    firewall, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"limit": 100}}}

    @firewall.secure_tool(tool_name="query", sanitize_output=False)
    def query_tool(run_ctx, *, limit, **kwargs):
        return {"limit": limit, "private": kwargs}

    result = query_tool(ctx(), limit=10000, _AgenticDome_private="x")

    assert result == {"limit": 100, "private": {}}
    assert client.calls[0][1]["tool_args"] == {"limit": 10000}


def test_schema_validation_blocks_bad_args():
    firewall, _ = make_firewall()

    @firewall.secure_tool(tool_name="lookup", tool_schema={"required": ["customer_id"], "properties": {"customer_id": {"type": "string"}}})
    def lookup(run_ctx, *, customer_id):
        return customer_id

    with pytest.raises(PydanticAIFirewallDenied):
        lookup(ctx(), customer_id=123)


def test_manager_handoff_stores_clean_args_before_token_injection():
    firewall, client = make_firewall(token_hmac_secret="secret")

    clean_args, _ = asyncio.run(firewall._pre_execute_tool_check(
        ctx(agent_name="manager"),
        "delegate_to_specialist",
        {"target_agent_id": "specialist", "target_tool_name": "lookup", "target_tool_args": {"q": "x"}},
    ))

    assert clean_args["target_tool_args"]["_AgenticDome_decision_token"] == "tok-1"
    assert client.calls[0][1]["tool_args"] == {"q": "x"}
    stored = firewall.token_store.get(session_id="s1", target_agent_id="specialist", tool_name="lookup", tool_args={"q": "x"})
    assert stored is not None
    assert stored.token_hmac


def test_specialist_verification_uses_token_store_fallback_once():
    firewall, client = make_firewall(token_hmac_secret="secret")
    token = "tok-1"
    firewall.token_store.put(
        session_id="s1",
        target_agent_id="agent-a",
        tool_name="lookup",
        tool_args={"q": "x"},
        record=DecisionTokenRecord(token, "manager", 1.0, firewall._token_hmac(token)),
        ttl_s=900,
    )

    clean_args, delegated = asyncio.run(firewall._pre_execute_tool_check(ctx(), "lookup", {"q": "x"}))

    assert clean_args == {"q": "x"}
    assert delegated is True
    assert client.calls[0][0] == "a2a_verify_decision_token_rpc"
    assert client.calls[0][1]["token"] == "tok-1"
    assert firewall.token_store.get(session_id="s1", target_agent_id="agent-a", tool_name="lookup", tool_args={"q": "x"}) is None


def test_rate_limit_blocks_second_tool_call():
    firewall, _ = make_firewall(rate_limit_per_minute=1)

    asyncio.run(firewall._pre_execute_tool_check(ctx(), "lookup", {"q": "x"}))
    with pytest.raises(PydanticAIFirewallDenied):
        asyncio.run(firewall._pre_execute_tool_check(ctx(), "lookup", {"q": "x"}))


def test_size_limit_blocks_large_tool_args():
    firewall, _ = make_firewall(max_tool_arg_chars=5)

    with pytest.raises(PydanticAIFirewallDenied):
        asyncio.run(firewall._pre_execute_tool_check(ctx(), "lookup", {"query": "abcdef"}))


def test_retry_allows_transient_policy_failure():
    firewall, client = make_firewall(retry_attempts=2)
    client.failures_remaining = 1

    asyncio.run(firewall._pre_execute_tool_check(ctx(), "lookup", {"q": "x"}))

    assert [name for name, _ in client.calls].count("guardrail_validate") == 2


def test_streaming_response_sanitizes_chunks():
    firewall, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "[REDACTED]"}

    async def collect():
        return [chunk async for chunk in firewall.sanitize_streaming_response(chunks=["secret", "more"], agent_id="agent-a", session_id="s1")]

    assert asyncio.run(collect()) == ["[REDACTED]", "[REDACTED]"]


def test_install_native_hooks_attaches_fallback_attribute():
    firewall, _ = make_firewall()
    agent = SimpleNamespace()

    result = firewall.install_native_hooks(agent)

    assert result is agent
    assert hasattr(agent, "agenticdome_hooks")
