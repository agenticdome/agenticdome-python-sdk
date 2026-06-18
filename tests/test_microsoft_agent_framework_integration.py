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
        self.mesh_response = None
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        return {"verdict": self.guardrail_verdict, "reason": "policy result"}

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        if self.mesh_response is not None:
            return self.mesh_response
        return {"verdict": "ALLOWED", "sanitized_text": kwargs["text"]}

    def a2a_verify_decision_token_rpc(self, token, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", {"token": token, **kwargs}))
        return {"result": {"valid": token == "token-ok", "reason": "token result"}}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        return None


def make_firewall(fail_closed=True):
    fw = AgenticDomeMicrosoftAgentFirewall(
        config=FirewallConfig(
            api_base="https://au.agenticdome.io",
            api_key="test-key",
            tenant_id="test-tenant",
            fail_closed=fail_closed,
            report_incidents=False,
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
