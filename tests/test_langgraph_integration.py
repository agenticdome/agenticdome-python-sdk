import asyncio
from types import SimpleNamespace

import pytest

from agenticdome_sdk.langgraph import (
    AgenticDomeDenied,
    AgenticDomeLangGraphFirewall,
    FirewallConfig,
    InMemoryDecisionTokenStore,
)


class FakeLangGraphClient:
    def __init__(self):
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if kwargs.get("tool_name") == "blocked_tool" or "blocked prompt" in kwargs.get("text", ""):
            return {"verdict": "BLOCKED", "reason": "blocked by test policy"}
        return {"verdict": "ALLOWED", "reason": "ok"}

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        return {"verdict": "ALLOWED", "sanitized_text": kwargs["text"].replace("secret", "[REDACTED]")}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        return None


def make_firewall():
    fw = AgenticDomeLangGraphFirewall(
        config=FirewallConfig(
            api_base="https://au.agenticdome.io",
            api_key="test-key",
            tenant_id="test-tenant",
            fail_closed=True,
            require_explicit_session_id=False,
            report_incidents=False,
        )
    )
    fw.client = FakeLangGraphClient()
    fw.token_store = InMemoryDecisionTokenStore("test-tenant")
    return fw


def test_screen_input_blocks_bad_prompt_state():
    fw = make_firewall()
    state = {"messages": [{"role": "user", "content": "blocked prompt"}], "session_id": "s1"}

    result = asyncio.run(fw.screen_input(state, agent_id="agent-a"))

    assert result["AgenticDome"]["blocked"] is True
    assert result["risk_score"] >= 90


def test_authorize_transition_blocks_tool_call():
    fw = make_firewall()
    state = {
        "messages": [{"role": "assistant", "content": "call tool", "tool_calls": [{"name": "blocked_tool", "args": {}}]}],
        "session_id": "s1",
    }

    result = asyncio.run(fw.authorize_transition(state, agent_id="agent-a"))

    assert result["AgenticDome"]["blocked"] is True
    assert "blocked by test policy" in result["AgenticDome"]["reason"]


def test_wrap_tool_node_authorizes_and_sanitizes_tool_output():
    fw = make_firewall()

    async def tool_node(state):
        return {"messages": [("tool", "secret value")]}

    wrapped = fw.wrap_tool_node(tool_node, agent_id="agent-a")
    state = {
        "messages": [{"role": "assistant", "content": "call", "tool_calls": [{"name": "allowed_tool", "args": {}}]}],
        "session_id": "s1",
    }

    result = asyncio.run(wrapped(state))

    assert result["messages"][-1][1] == "[REDACTED] value"


def test_wrap_tool_node_does_not_execute_blocked_tool():
    fw = make_firewall()
    executed = {"value": False}

    def tool_node(state):
        executed["value"] = True
        return {"messages": [("tool", "should not happen")]}

    wrapped = fw.wrap_tool_node(tool_node, agent_id="agent-a")
    state = {
        "messages": [{"role": "assistant", "content": "call", "tool_calls": [{"name": "blocked_tool", "args": {}}]}],
        "session_id": "s1",
    }

    result = asyncio.run(wrapped(state))

    assert executed["value"] is False
    assert result["AgenticDome"]["blocked"] is True


def test_langchain_middleware_authorizes_tool_and_preserves_structured_result():
    fw = make_firewall()
    middleware = fw.as_langchain_middleware(agent_id="agent-a")

    def handler(request):
        return {"ok": True}

    request = SimpleNamespace(
        tool_call={"name": "allowed_tool", "args": {"value": 1}},
        session_id="s1",
        agent_id="agent-a",
    )

    result = asyncio.run(middleware.wrap_tool_call(request, handler))

    assert result == {"ok": True}


def test_langchain_middleware_raises_for_blocked_tool():
    fw = make_firewall()
    middleware = fw.as_langchain_middleware(agent_id="agent-a")

    def handler(request):
        raise AssertionError("handler should not run")

    request = SimpleNamespace(tool_call={"name": "blocked_tool", "args": {}}, session_id="s1")

    with pytest.raises(AgenticDomeDenied):
        asyncio.run(middleware.wrap_tool_call(request, handler))
