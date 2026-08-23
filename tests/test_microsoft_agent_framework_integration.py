import asyncio
import json
from types import SimpleNamespace

import pytest

from agenticdome_sdk.microsoft_agent_framework import (
    AgenticDomeMicrosoftAgentFirewall,
    FirewallConfig,
    InMemoryDecisionTokenStore,
    MicrosoftAgentFirewallDenied,
)


class FakePolicyClient:
    def __init__(self):
        self.guardrail_verdict = "ALLOWED"
        self.guardrail_response = None
        self.mesh_response = None
        self.copilot_response = {"result": {"verdict": "ALLOWED", "reason": "ok"}}
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if self.guardrail_response is not None:
            return self.guardrail_response
        return {"verdict": self.guardrail_verdict, "reason": "policy result"}

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        if self.mesh_response is not None:
            return self.mesh_response
        return {"verdict": "ALLOWED", "sanitized_text": kwargs["text"]}

    def a2a_authorize_tool(self, **kwargs):
        self.calls.append(("a2a_authorize_tool", kwargs))
        return {"result": {"verdict": "ALLOWED", "decision_token": "token-ok", "reason": "handoff ok"}}

    def a2a_verify_decision_token_rpc(self, token, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", {"token": token, **kwargs}))
        return {"result": {"valid": token == "token-ok", "allowed": token == "token-ok", "reason": "token result"}}

    def copilot_validate(self, payload, api_version="2025-09-01"):
        self.calls.append(("copilot_validate", {"payload": payload, "api_version": api_version}))
        return self.copilot_response

    def copilot_analyze_tool_execution(self, payload, api_version="2025-09-01"):
        self.calls.append(("copilot_analyze_tool_execution", {"payload": payload, "api_version": api_version}))
        return self.copilot_response

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        return None


def make_firewall(fail_closed=True, **overrides):
    fw = AgenticDomeMicrosoftAgentFirewall(
        config=FirewallConfig(
            api_base="https://demo-sidecar.agenticdome.io",
            api_key="test-key",
            tenant_id="test-tenant",
            fail_closed=fail_closed,
            report_incidents=False,
            **overrides,
        )
    )
    fw.client = FakePolicyClient()
    fw.token_store = InMemoryDecisionTokenStore("test-tenant")
    return fw


def test_microsoft_agent_framework_firewall_imports():
    fw = make_firewall(fail_closed=False)

    assert fw.config.platform == "microsoft_agent_framework_v1"
    assert hasattr(fw, "screen_input")
    assert hasattr(fw, "authorize_direct_tool_call")
    assert hasattr(fw, "authorize_manager_handoff")
    assert hasattr(fw, "verify_specialist_execution")
    assert hasattr(fw, "sanitize_text")
    assert hasattr(fw, "wrap_tool_handler")
    assert hasattr(fw, "wrap_delegated_tool_handler")
    assert hasattr(fw, "secure_tool")
    assert hasattr(fw, "secure_delegated_tool")


def test_wrap_tool_handler_preserves_structured_result_when_unchanged():
    fw = make_firewall()

    def handler(ctx, args):
        return {"count": 2, "ok": True}

    secured = fw.wrap_tool_handler(tool_name="inventory_lookup", handler=handler)
    result = asyncio.run(secured(SimpleNamespace(session_id="s1", agent_id="agent-a"), {"sku": "A1"}))

    assert result == {"count": 2, "ok": True}
    assert fw.client.calls[0][0] == "guardrail_validate"
    assert fw.client.calls[1][0] == "mesh_validate"
    assert fw.client.calls[1][1]["text"] == json.dumps(result, sort_keys=True, separators=(",", ":"))


def test_wrap_tool_handler_returns_sanitized_text_when_policy_redacts():
    fw = make_firewall()
    fw.client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "secret [REDACTED]"}

    def handler(ctx, args):
        return "secret 1234"

    secured = fw.wrap_tool_handler(tool_name="notes", handler=handler)
    result = asyncio.run(secured(SimpleNamespace(session_id="s1", agent_id="agent-a"), {}))

    assert result == "secret [REDACTED]"


def test_wrap_tool_handler_raises_when_direct_tool_is_blocked():
    fw = make_firewall()
    fw.client.guardrail_verdict = "BLOCKED"

    def handler(ctx, args):
        raise AssertionError("handler should not run")

    secured = fw.wrap_tool_handler(tool_name="dangerous_tool", handler=handler)

    with pytest.raises(MicrosoftAgentFirewallDenied):
        asyncio.run(secured(SimpleNamespace(session_id="s1", agent_id="agent-a"), {}))


def test_wrap_delegated_tool_handler_verifies_token_and_preserves_result():
    fw = make_firewall()

    def handler(ctx, args):
        return {"delegated": True}

    secured = fw.wrap_delegated_tool_handler(tool_name="specialist_lookup", handler=handler)
    result = asyncio.run(secured(
        SimpleNamespace(session_id="s1", agent_id="specialist", source_agent_id="manager"),
        {"query": "x", "_decision_token": "token-ok"},
    ))

    assert result == {"delegated": True}
    assert fw.client.calls[0][0] == "a2a_verify_decision_token_rpc"


def test_secure_tool_decorator_wraps_function():
    fw = make_firewall()

    @fw.secure_tool(tool_name="decorated_lookup")
    def decorated(ctx, args):
        return {"decorated": args["value"]}

    result = asyncio.run(decorated(SimpleNamespace(session_id="s1", agent_id="agent-a"), {"value": 7}))

    assert result == {"decorated": 7}


def test_direct_tool_authorization_strips_internal_args():
    fw = make_firewall()

    asyncio.run(fw.authorize_direct_tool_call(
        text="execute",
        agent_id="agent-a",
        session_id="s1",
        tool_name="payments.refund",
        tool_args={"amount": 10, "_agenticdome_decision_token": "secret"},
    ))

    call = fw.client.calls[0][1]
    assert call["tool_args"] == {"amount": 10}


def test_wrap_tool_handler_uses_sanitized_policy_args():
    fw = make_firewall()
    fw.client.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"limit": 100}}}
    seen = {}

    def handler(ctx, args):
        seen.update(args)
        return {"ok": True}

    secured = fw.wrap_tool_handler(tool_name="query_database", handler=handler)
    result = asyncio.run(secured(SimpleNamespace(session_id="s1", agent_id="agent-a"), {"limit": 100000}))

    assert seen == {"limit": 100}
    assert result == {"ok": True}


def test_structured_output_preserved_when_sanitizer_returns_json():
    fw = make_firewall()
    fw.client.mesh_response = {"verdict": "ALLOWED", "sanitized_text": '{"ok":true,"count":1}'}

    def handler(ctx, args):
        return {"ok": True, "count": 99}

    secured = fw.wrap_tool_handler(tool_name="structured", handler=handler)
    result = asyncio.run(secured(SimpleNamespace(session_id="s1", agent_id="agent-a"), {}))

    assert result == {"ok": True, "count": 1}


def test_production_mode_requires_stable_session_id():
    fw = make_firewall(production_mode=True)

    with pytest.raises(MicrosoftAgentFirewallDenied):
        fw._session_id(SimpleNamespace(agent_id="agent-a"))


def test_rate_limit_blocks_repeated_tool_authorization():
    fw = make_firewall(rate_limit_per_minute=1)

    asyncio.run(fw.authorize_direct_tool_call(
        text="execute",
        agent_id="agent-a",
        session_id="s1",
        tool_name="tool-a",
        tool_args={},
    ))

    with pytest.raises(MicrosoftAgentFirewallDenied):
        asyncio.run(fw.authorize_direct_tool_call(
            text="execute",
            agent_id="agent-a",
            session_id="s1",
            tool_name="tool-a",
            tool_args={},
        ))


def test_identity_context_included_in_tool_policy_context():
    fw = make_firewall()

    def handler(ctx, args):
        return "ok"

    secured = fw.wrap_tool_handler(tool_name="identity_tool", handler=handler, sanitize_output=False)
    asyncio.run(secured(
        SimpleNamespace(session_id="s1", agent_id="agent-a", entra_tenant_id="tid", oid="oid-1", upn="alice@example.com"),
        {},
    ))

    policy_context = fw.client.calls[0][1]["policy_context"]
    assert policy_context["entra_tenant_id"] == "tid"
    assert policy_context["oid"] == "oid-1"
    assert policy_context["upn"] == "alice@example.com"


def test_handoff_token_is_consumed_once_from_store():
    fw = make_firewall(token_hmac_secret="secret")

    asyncio.run(fw.authorize_manager_handoff(
        text="delegate",
        manager_agent_id="manager",
        specialist_agent_id="specialist",
        tool_name="lookup",
        tool_args={"q": "x"},
        session_id="s1",
    ))

    result = asyncio.run(fw.verify_specialist_execution(
        specialist_agent_id="specialist",
        tool_name="lookup",
        tool_args={"q": "x"},
        session_id="s1",
    ))

    assert result["valid"] is True
    with pytest.raises(MicrosoftAgentFirewallDenied):
        asyncio.run(fw.verify_specialist_execution(
            specialist_agent_id="specialist",
            tool_name="lookup",
            tool_args={"q": "x"},
            session_id="s1",
        ))


def test_middleware_before_tool_call_returns_sanitized_args_and_install_on_agent():
    fw = make_firewall()
    fw.client.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"safe": True}}}
    middleware = fw.create_middleware()

    args = asyncio.run(middleware.before_tool_call(
        SimpleNamespace(session_id="s1", agent_id="agent-a"),
        "tool-a",
        {"safe": False},
    ))

    assert args == {"safe": True}
    agent = SimpleNamespace()
    assert fw.install_on_agent(agent) is agent
    assert len(agent.agenticdome_middleware) == 1


def test_streaming_response_sanitization():
    fw = make_firewall()
    fw.client.mesh_response = {"verdict": "ALLOWED", "sanitized_text": "safe chunk"}

    async def chunks():
        yield "secret chunk"

    async def run():
        out = []
        async for chunk in fw.sanitize_streaming_response(chunks=chunks(), agent_id="agent-a", session_id="s1"):
            out.append(chunk)
        return out

    assert asyncio.run(run()) == ["safe chunk"]


def test_copilot_enforcement_blocks_tool():
    fw = make_firewall(enable_copilot_threat_api=True, enforce_copilot_threat_api=True)
    fw.client.copilot_response = {"result": {"verdict": "BLOCKED", "reason": "threat"}}

    def handler(ctx, args):
        return "should not run"

    secured = fw.wrap_tool_handler(tool_name="danger", handler=handler)

    with pytest.raises(MicrosoftAgentFirewallDenied):
        asyncio.run(secured(SimpleNamespace(session_id="s1", agent_id="agent-a"), {}))
