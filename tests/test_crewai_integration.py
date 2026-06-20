import importlib
import json
import sys
import types
from dataclasses import replace
from types import SimpleNamespace


def install_crewai_hook_stubs():
    crewai = types.ModuleType("crewai")
    hooks = types.ModuleType("crewai.hooks")

    def register(fn):
        return fn

    hooks.register_after_tool_call_hook = register
    hooks.register_before_llm_call_hook = register
    hooks.register_before_tool_call_hook = register
    sys.modules["crewai"] = crewai
    sys.modules["crewai.hooks"] = hooks


class FakeCrewAIClient:
    def __init__(self):
        self.guardrail_verdict = "ALLOWED"
        self.guardrail_response = None
        self.mesh_response = None
        self.guardrail_failures_remaining = 0
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if self.guardrail_failures_remaining > 0:
            self.guardrail_failures_remaining -= 1
            raise RuntimeError("temporary network down")
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
        return {"result": {"valid": token == "token-ok", "allowed": token == "token-ok", "reason": "ok"}}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}


def load_module():
    install_crewai_hook_stubs()
    sys.modules.pop("agenticdome_sdk.crewai", None)
    module = importlib.import_module("agenticdome_sdk.crewai")
    module.CLIENT = FakeCrewAIClient()
    module.CONFIG = replace(
        module.CONFIG,
        api_base="https://au.agenticdome.io",
        api_key="test-key",
        tenant_id="test-tenant",
        fail_closed=True,
        report_incidents=False,
        retry_backoff_s=0,
        audit_logging=False,
        otel_enabled=False,
    )
    module.TOKEN_STORE = module.InMemoryDecisionTokenStore()
    return module


def test_before_tool_call_blocks_when_policy_blocks_direct_tool():
    module = load_module()
    module.CLIENT.guardrail_verdict = "BLOCKED"
    ctx = SimpleNamespace(session_id="s1", agent_id="agent-a", tool_name="danger", tool_input={})

    assert module.AgenticDome_before_tool_call(ctx) is False


def test_handoff_authorization_injects_decision_token_into_nested_args():
    module = load_module()
    ctx = SimpleNamespace(
        session_id="s1",
        agent_id="manager",
        tool_name="delegate_to_specialist",
        tool_input={
            "target_agent_id": "specialist",
            "target_tool_name": "lookup",
            "target_tool_args": {"query": "alpha"},
        },
    )

    assert module.AgenticDome_before_tool_call(ctx) is True
    assert ctx.tool_input["_AgenticDome_decision_token"] == "token-ok"
    assert ctx.tool_input["target_tool_args"]["_AgenticDome_decision_token"] == "token-ok"


def test_delegated_execution_verifies_decision_token():
    module = load_module()
    ctx = SimpleNamespace(
        session_id="s1",
        agent_id="specialist",
        tool_name="lookup",
        tool_input={"query": "alpha", "_decision_token": "token-ok", "_source_agent_id": "manager"},
    )

    assert module.AgenticDome_before_tool_call(ctx) is True
    assert module.CLIENT.calls[0][0] == "a2a_verify_decision_token_rpc"


def test_after_tool_call_preserves_structured_result_when_unchanged():
    module = load_module()
    tool_result = {"ok": True, "count": 1}
    ctx = SimpleNamespace(session_id="s1", agent_id="agent-a", tool_result=tool_result)

    result = module.AgenticDome_after_tool_call(ctx)

    assert result == tool_result
    assert ctx.tool_result == tool_result
    assert module.CLIENT.calls[0][1]["text"] == json.dumps(tool_result, sort_keys=True, separators=(",", ":"))


def test_after_tool_call_returns_redacted_text_when_policy_changes_output():
    module = load_module()
    module.CLIENT.mesh_response = {"verdict": "REDACTED", "sanitized_text": "secret [REDACTED]"}
    ctx = SimpleNamespace(session_id="s1", agent_id="agent-a", tool_result="secret 1234")

    result = module.AgenticDome_after_tool_call(ctx)

    assert result == "secret [REDACTED]"
    assert ctx.tool_result == "secret [REDACTED]"


def test_production_mode_requires_stable_session_id():
    module = load_module()
    module.CONFIG = replace(module.CONFIG, production_mode=True, require_stable_session_id_in_prod=True)
    ctx = SimpleNamespace(agent_id="agent-a", prompt="hello")

    assert module.AgenticDome_before_llm_call(ctx) is False


def test_direct_tool_sanitized_args_are_written_back():
    module = load_module()
    module.CLIENT.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"query": "safe", "_AgenticDome_decision_token": "drop"}}}
    ctx = SimpleNamespace(session_id="s1", agent_id="agent-a", tool_name="lookup", tool_input={"query": "unsafe"})

    assert module.AgenticDome_before_tool_call(ctx) is True
    assert ctx.tool_input == {"query": "safe"}


def test_tool_schema_validation_blocks_bad_args():
    module = load_module()
    ctx = SimpleNamespace(
        session_id="s1",
        agent_id="agent-a",
        tool_name="lookup",
        tool_input={"query": 123},
        tool_schema={"required": ["query"], "properties": {"query": {"type": "string"}}},
    )

    assert module.AgenticDome_before_tool_call(ctx) is False


def test_stored_token_is_consumed_once_with_hmac():
    module = load_module()
    module.CONFIG = replace(module.CONFIG, token_hmac_secret="secret")
    record = module.DecisionTokenRecord("token-ok", "manager", 1.0, token_hmac=module._token_hmac("token-ok"))
    module.TOKEN_STORE.put(session_id="s1", target_agent_id="specialist", tool_name="lookup", tool_args={"query": "alpha"}, record=record, ttl_s=900)
    ctx = SimpleNamespace(session_id="s1", agent_id="specialist", tool_name="lookup", tool_input={"query": "alpha"})

    assert module.AgenticDome_before_tool_call(ctx) is True
    assert module.CLIENT.calls[0][0] == "a2a_verify_decision_token_rpc"
    assert module.TOKEN_STORE.get(session_id="s1", target_agent_id="specialist", tool_name="lookup", tool_args={"query": "alpha"}) is None


def test_after_tool_call_parses_sanitized_structured_json():
    module = load_module()
    module.CLIENT.mesh_response = {"verdict": "ALLOWED", "sanitized_text": '{"email":"[REDACTED]"}'}
    ctx = SimpleNamespace(session_id="s1", agent_id="agent-a", tool_result={"email": "a@example.com"})

    result = module.AgenticDome_after_tool_call(ctx)

    assert result == {"email": "[REDACTED]"}
    assert ctx.tool_result == {"email": "[REDACTED]"}


def test_rate_limit_blocks_excess_prompt_calls():
    module = load_module()
    module.CONFIG = replace(module.CONFIG, rate_limit_per_minute=1)

    assert module.AgenticDome_before_llm_call(SimpleNamespace(session_id="s1", agent_id="agent-a", prompt="hello")) is True
    assert module.AgenticDome_before_llm_call(SimpleNamespace(session_id="s1", agent_id="agent-a", prompt="again")) is False


def test_size_limit_blocks_large_tool_args():
    module = load_module()
    module.CONFIG = replace(module.CONFIG, max_tool_arg_chars=10)
    ctx = SimpleNamespace(session_id="s1", agent_id="agent-a", tool_name="large", tool_input={"payload": "x" * 100})

    assert module.AgenticDome_before_tool_call(ctx) is False


def test_retry_allows_transient_guardrail_failure():
    module = load_module()
    module.CONFIG = replace(module.CONFIG, retry_attempts=2, retry_backoff_s=0)
    module.CLIENT.guardrail_failures_remaining = 1

    assert module.AgenticDome_before_llm_call(SimpleNamespace(session_id="s1", agent_id="agent-a", prompt="hello")) is True
    assert len([call for call in module.CLIENT.calls if call[0] == "guardrail_validate"]) == 2


def test_class_facade_attach_unregister_and_secure_tool():
    module = load_module()
    fw = module.AgenticDomeCrewAIFirewall(config=module.CONFIG, client=module.CLIENT, token_store=module.TOKEN_STORE)
    crew = SimpleNamespace()

    assert fw.attach(crew) is crew
    assert len(crew.before_tool_call_hooks) == 1
    assert fw.unregister(crew) is crew
    assert crew.before_tool_call_hooks is None

    module.CLIENT.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"query": "safe"}}}

    @fw.secure_tool(tool_name="lookup", sanitize_output=False)
    def lookup(agent, query):
        return {"query": query}

    result = lookup(SimpleNamespace(session_id="s1", agent_id="agent-a"), query="unsafe")
    assert result == {"query": "safe"}


def test_streaming_sanitization_blocks_chunk():
    module = load_module()
    module.CLIENT.mesh_response = {"verdict": "BLOCKED", "reason": "secret"}

    async def chunks():
        yield "secret"
        yield "more"

    async def collect():
        out = []
        async for chunk in module.sanitize_streaming_response(chunks(), agent_id="agent-a", session_id="s1"):
            out.append(chunk)
        return out

    import asyncio
    assert asyncio.run(collect()) == ["[OUTPUT BLOCKED BY AGENTICDOME SECURITY POLICY]"]
