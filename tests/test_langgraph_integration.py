import asyncio
from types import SimpleNamespace

import pytest

from agenticdome_sdk.langgraph import (
    AgenticDomeDenied,
    AgenticDomeLangGraphFirewall,
    FirewallConfig,
    DecisionTokenRecord,
    InMemoryDecisionTokenStore,
)


class FakeLangGraphClient:
    def __init__(self):
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if kwargs.get("tool_name") == "blocked_tool" or "blocked prompt" in kwargs.get("text", ""):
            return {"verdict": "BLOCKED", "reason": "blocked by test policy"}
        if kwargs.get("tool_name") == "sanitize_tool":
            return {
                "verdict": "ALLOWED",
                "reason": "ok",
                "decision_id": "dec-123",
                "sanitized_tool_args": {"query": "safe"},
            }
        if kwargs.get("tool_name") == "langgraph.transition" and kwargs.get("tool_args", {}).get("to_node") == "blocked_node":
            return {"verdict": "BLOCKED", "reason": "transition blocked"}
        return {"verdict": "ALLOWED", "reason": "ok", "decision_id": "dec-ok"}

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        if "blocked stream" in kwargs.get("text", ""):
            return {"verdict": "BLOCKED", "reason": "blocked stream"}
        return {"verdict": "ALLOWED", "sanitized_text": kwargs["text"].replace("secret", "[REDACTED]")}

    def a2a_verify_decision_token_rpc(self, token, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", {"token": token, **kwargs}))
        return {"valid": token == "token-1", "allowed": token == "token-1", "reason": "ok"}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        return None


def make_firewall():
    fw = AgenticDomeLangGraphFirewall(
        config=FirewallConfig(
            api_base="https://demo-sidecar.agenticdome.io",
            api_key="test-key",
            tenant_id="test-tenant",
            fail_closed=True,
            require_explicit_session_id=False,
            report_incidents=False,
            audit_logging=False,
            otel_enabled=False,
            retry_backoff_s=0,
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


def test_authorize_transition_applies_sanitized_tool_args():
    fw = make_firewall()
    state = {
        "messages": [{"role": "assistant", "content": "call", "tool_calls": [{"name": "sanitize_tool", "args": {"query": "unsafe"}}]}],
        "session_id": "s1",
    }

    result = asyncio.run(fw.authorize_transition(state, agent_id="agent-a"))

    assert result["messages"][-1]["tool_calls"][0]["args"] == {"query": "safe"}
    assert result["AgenticDome"]["last_policy_decision_id"] == "dec-123"


def test_rate_limit_blocks_excess_input():
    fw = make_firewall()
    fw.config = FirewallConfig(
        api_base="https://demo-sidecar.agenticdome.io",
        api_key="test-key",
        tenant_id="test-tenant",
        fail_closed=True,
        require_explicit_session_id=False,
        report_incidents=False,
        audit_logging=False,
        otel_enabled=False,
        rate_limit_per_minute=1,
        retry_backoff_s=0,
    )

    state = {"messages": [{"role": "user", "content": "hello"}], "session_id": "s1"}
    asyncio.run(fw.screen_input(state, agent_id="agent-a"))
    blocked = asyncio.run(fw.screen_input(state, agent_id="agent-a"))

    assert blocked["AgenticDome"]["blocked"] is True
    assert "rate limit" in blocked["AgenticDome"]["reason"]


def test_size_limit_blocks_large_tool_args():
    fw = make_firewall()
    fw.config = FirewallConfig(
        api_base="https://demo-sidecar.agenticdome.io",
        api_key="test-key",
        tenant_id="test-tenant",
        fail_closed=True,
        require_explicit_session_id=False,
        report_incidents=False,
        audit_logging=False,
        otel_enabled=False,
        max_tool_arg_chars=8,
        retry_backoff_s=0,
    )
    state = {
        "messages": [{"role": "assistant", "content": "call", "tool_calls": [{"name": "allowed_tool", "args": {"value": "too-long"}}]}],
        "session_id": "s1",
    }

    result = asyncio.run(fw.authorize_transition(state, agent_id="agent-a"))

    assert result["AgenticDome"]["blocked"] is True
    assert "exceed max size" in result["AgenticDome"]["reason"]


def test_production_mode_requires_stable_session_id():
    fw = make_firewall()
    fw.config = FirewallConfig(
        api_base="https://demo-sidecar.agenticdome.io",
        api_key="test-key",
        tenant_id="test-tenant",
        fail_closed=True,
        production_mode=True,
        require_explicit_session_id=False,
        report_incidents=False,
        audit_logging=False,
        otel_enabled=False,
        retry_backoff_s=0,
    )
    state = {"messages": [{"role": "user", "content": "hello"}]}

    result = asyncio.run(fw.screen_input(state, agent_id="agent-a"))

    assert result["AgenticDome"]["blocked"] is True
    assert "Missing session_id" in result["AgenticDome"]["reason"]


def test_token_store_consumes_once_with_hmac():
    fw = make_firewall()
    fw.config = FirewallConfig(
        api_base="https://demo-sidecar.agenticdome.io",
        api_key="test-key",
        tenant_id="test-tenant",
        fail_closed=True,
        require_explicit_session_id=False,
        report_incidents=False,
        audit_logging=False,
        otel_enabled=False,
        token_hmac_secret="secret",
        retry_backoff_s=0,
    )
    args = {"value": 1}
    from agenticdome_sdk.langgraph import _token_hmac
    fw.token_store.put(
        session_id="s1",
        target_agent_id="specialist",
        tool_name="allowed_tool",
        tool_args=args,
        record=DecisionTokenRecord(
            decision_token="token-1",
            source_agent_id="manager",
            created_at=1.0,
            token_hmac=_token_hmac(
                "secret",
                token="token-1",
                source_agent_id="manager",
                target_agent_id="specialist",
                tool_name="allowed_tool",
                tool_args=args,
            ),
        ),
        ttl_s=60,
    )
    state = {
        "messages": [{"role": "assistant", "content": "call", "tool_calls": [{"name": "allowed_tool", "args": args}]}],
        "session_id": "s1",
    }

    first = asyncio.run(fw.authorize_transition(state, agent_id="specialist"))
    second = asyncio.run(fw.authorize_transition(state, agent_id="specialist"))

    assert first.get("AgenticDome", {}).get("blocked") is not True
    assert second.get("AgenticDome", {}).get("blocked") is not True
    verify_calls = [c for c in fw.client.calls if c[0] == "a2a_verify_decision_token_rpc"]
    assert len(verify_calls) == 1


def test_graph_transition_block_sets_security_route():
    fw = make_firewall()
    state = {"messages": [{"role": "user", "content": "go"}], "session_id": "s1"}

    result = asyncio.run(fw.authorize_graph_transition(state, from_node="agent", to_node="blocked_node", agent_id="agent-a"))

    assert result["AgenticDome"]["blocked"] is True
    assert fw.security_route(result) == "security_block"


def test_retrieval_documents_are_sanitized():
    fw = make_firewall()
    docs = [{"page_content": "secret document"}]

    result = asyncio.run(fw.sanitize_retrieval_documents(docs, state={"session_id": "s1"}, agent_id="agent-a"))

    assert result[0]["page_content"] == "[REDACTED] document"


def test_streaming_events_block_sensitive_chunk():
    fw = make_firewall()

    async def events():
        yield {"content": "safe"}
        yield {"content": " blocked stream"}

    async def run():
        out = []
        async for event in fw.sanitize_streaming_events(events(), state={"session_id": "s1"}, agent_id="agent-a"):
            out.append(event)
        return out

    with pytest.raises(AgenticDomeDenied):
        asyncio.run(run())


def test_langchain_middleware_applies_sanitized_args_to_request():
    fw = make_firewall()
    middleware = fw.as_langchain_middleware(agent_id="agent-a", sanitize_tool_output=False)
    seen = {}

    def handler(request):
        seen["tool_call"] = request.tool_call
        return "ok"

    request = SimpleNamespace(
        tool_call={"name": "sanitize_tool", "args": {"query": "unsafe"}},
        session_id="s1",
        agent_id="agent-a",
    )

    result = asyncio.run(middleware.wrap_tool_call(request, handler))

    assert result == "ok"
    assert seen["tool_call"]["args"] == {"query": "safe"}
