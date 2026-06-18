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
        self.mesh_response = None
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
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
        return {"result": {"valid": token == "token-ok", "reason": "ok"}}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}


def load_module():
    install_crewai_hook_stubs()
    sys.modules.pop("agenticdome_sdk.crewai", None)
    module = importlib.import_module("agenticdome_sdk.crewai")
    module.CLIENT = FakeCrewAIClient()
    module.CONFIG = replace(module.CONFIG, fail_closed=True, report_incidents=False, tenant_id="test-tenant")
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
