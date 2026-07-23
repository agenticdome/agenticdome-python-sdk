import sys
import types
from types import SimpleNamespace

import anyio
import pytest

from agenticdome_sdk.claude import (
    AgenticDomeClaudeFirewall,
    ClaudeFirewallDenied,
    FirewallConfig,
    load_config,
)


class FakeClient:
    def __init__(self):
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if "blocked" in kwargs["text"].lower() or kwargs.get("tool_name") == "danger":
            return {"verdict": "BLOCKED", "reason": "test policy"}
        return {"verdict": "ALLOWED", "sanitized_tool_args": kwargs.get("tool_args")}

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        text = kwargs["text"]
        if "hard-secret" in text:
            return {"verdict": "BLOCKED", "reason": "secret"}
        return {"verdict": "REDACTED", "text": text.replace("alice@example.com", "[EMAIL_REDACTED]")}

    def a2a_authorize_tool(self, **kwargs):
        self.calls.append(("a2a_authorize_tool", kwargs))
        return {"result": {"verdict": "ALLOWED", "decision_token": "token-1"}}

    def a2a_verify_decision_token_rpc(self, token, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", {"token": token, **kwargs}))
        return {"result": {"valid": token == "token-1", "allowed": token == "token-1"}}

    def close(self):
        pass


def make_firewall(**overrides):
    values = {
        "api_base": "https://sidecar.test",
        "api_key": "key",
        "tenant_id": "tenant",
        "audit_logging": False,
        "otel_enabled": False,
        "retry_backoff_s": 0,
        **overrides,
    }
    return AgenticDomeClaudeFirewall(FirewallConfig(**values), client=FakeClient())


def test_claude_config_reads_framework_limits(monkeypatch):
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.test")
    monkeypatch.setenv("AGENTICDOME_API_KEY", "key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "tenant")
    monkeypatch.setenv("AGENTICDOME_CLAUDE_AGENT_ID", "support-agent")
    monkeypatch.setenv("AGENTICDOME_CLAUDE_MAX_TOOL_ARG_CHARS", "1234")
    config = load_config()
    assert config.agent_id == "support-agent"
    assert config.max_tool_arg_chars == 1234
    assert config.platform == "claude_agent_sdk"


def test_claude_prompt_and_tool_block_before_execution():
    firewall = make_firewall()
    executed = False

    def handler(args):
        nonlocal executed
        executed = True
        return args

    secured = firewall.wrap_tool_handler(tool_name="danger", handler=handler, session_id="session-1")
    with pytest.raises(ClaudeFirewallDenied):
        firewall.screen_input(session_id="session-1", agent_id="agent", text="blocked prompt")
    with pytest.raises(ClaudeFirewallDenied):
        secured({"value": 1})
    assert executed is False


def test_claude_native_hooks_allow_and_deny():
    firewall = make_firewall()

    async def authorize(**kwargs):
        return firewall.authorize_tool_call(**kwargs)

    firewall.aauthorize_tool_call = authorize
    hooks = firewall.create_hooks(session_id="session-1", agent_id="agent")
    allowed = anyio.run(lambda: hooks["PreToolUse"][0]({"tool_name": "safe", "tool_input": {"x": 1}}, None, {}))
    denied = anyio.run(lambda: hooks["PreToolUse"][0]({"tool_name": "danger", "tool_input": {}}, None, {}))
    assert allowed["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_post_tool_hook_redacts_before_model_consumes_output():
    firewall = make_firewall()

    async def review(value, **kwargs):
        return firewall.review_value(value, **kwargs)

    firewall.areview_value = review
    hook = firewall.create_hooks(session_id="session-1")["PostToolUse"][0]
    result = anyio.run(lambda: hook({"tool_name": "lookup", "tool_response": "alice@example.com"}, None, {}))
    assert result["hookSpecificOutput"]["updatedToolOutput"] == "[EMAIL_REDACTED]"


def test_claude_secure_query_screens_and_redacts_messages():
    firewall = make_firewall()

    async def screen(**kwargs):
        return firewall.screen_input(**kwargs)

    async def sanitize(**kwargs):
        return firewall.sanitize_output(**kwargs)

    firewall.ascreen_input = screen
    firewall.asanitize_output = sanitize

    async def query_fn(**kwargs):
        assert kwargs["prompt"] == "hello"
        yield SimpleNamespace(content=[SimpleNamespace(text="alice@example.com")])

    async def collect():
        return [
            message
            async for message in firewall.secure_query("hello", session_id="session-1", query_fn=query_fn)
        ]

    messages = anyio.run(collect)
    assert messages[0].content[0].text == "[EMAIL_REDACTED]"
    assert [call[0] for call in firewall.client.calls] == ["guardrail_validate", "mesh_validate"]


def test_claude_options_hook_install_is_idempotent(monkeypatch):
    sdk = types.ModuleType("claude_agent_sdk")

    class HookMatcher:
        def __init__(self, matcher=None, hooks=None):
            self.matcher = matcher
            self.hooks = hooks or []

    sdk.HookMatcher = HookMatcher
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", sdk)
    firewall = make_firewall()
    options = SimpleNamespace(hooks={})

    firewall.install_on_options(options, session_id="session-1", agent_id="agent")
    firewall.install_on_options(options, session_id="session-1", agent_id="agent")

    assert set(options.hooks) == {"UserPromptSubmit", "PreToolUse", "PostToolUse"}
    assert all(len(matchers) == 1 for matchers in options.hooks.values())


def test_claude_secure_query_installs_tool_hooks_on_supplied_options(monkeypatch):
    sdk = types.ModuleType("claude_agent_sdk")

    class HookMatcher:
        def __init__(self, matcher=None, hooks=None):
            self.matcher = matcher
            self.hooks = hooks or []

    sdk.HookMatcher = HookMatcher
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", sdk)
    firewall = make_firewall()
    options = SimpleNamespace(hooks={})

    async def screen(**kwargs):
        return firewall.screen_input(**kwargs)

    firewall.ascreen_input = screen

    async def query_fn(**kwargs):
        assert kwargs["options"] is options
        assert "PreToolUse" in options.hooks
        yield SimpleNamespace(content=[])

    async def collect():
        return [
            item
            async for item in firewall.secure_query(
                "hello",
                session_id="session-1",
                options=options,
                query_fn=query_fn,
            )
        ]

    assert len(anyio.run(collect)) == 1


def test_claude_subagent_tool_hook_preserves_actor_lineage():
    firewall = make_firewall()

    async def authorize(**kwargs):
        return firewall.authorize_tool_call(**kwargs)

    firewall.aauthorize_tool_call = authorize
    hook = firewall.create_hooks(session_id="session-1", agent_id="manager")["PreToolUse"][0]

    result = anyio.run(
        lambda: hook(
            {
                "tool_name": "safe",
                "tool_input": {"customer_id": "123"},
                "agent_id": "subagent-42",
                "agent_type": "researcher",
            },
            "tool-use-1",
            {},
        )
    )

    assert result["hookSpecificOutput"]["permissionDecision"] == "allow"
    call = firewall.client.calls[-1][1]
    assert call["agent_id"] == "subagent-42"
    assert call["source_agent_id"] == "manager"
    assert call["policy_context"]["delegation_chain"] == ["manager", "subagent-42"]


def test_claude_handoff_token_is_bound_and_consumed():
    firewall = make_firewall(token_hmac_secret="hmac-key")
    args = {"customer_id": "123"}
    firewall.authorize_manager_handoff(
        session_id="session-1",
        manager_agent_id="manager",
        specialist_agent_id="specialist",
        tool_name="crm.read",
        tool_args=args,
    )
    result = firewall.verify_specialist_execution(
        session_id="session-1", specialist_agent_id="specialist", tool_name="crm.read", tool_args=args
    )
    assert result["valid"] is True
    with pytest.raises(ClaudeFirewallDenied):
        firewall.verify_specialist_execution(
            session_id="session-1", specialist_agent_id="specialist", tool_name="crm.read", tool_args=args
        )
