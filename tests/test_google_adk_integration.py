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

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
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


def make_firewall(*, fail_closed=True):
    client = FakeClient()
    fw = AgenticDomeGoogleADKFirewall(
        config=FirewallConfig(
            api_base="https://au.agenticdome.io",
            api_key="key",
            tenant_id="tenant",
            fail_closed=fail_closed,
            report_incidents=False,
        ),
        client=client,
    )
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


def test_after_model_sanitizes_response_object():
    fw, client = make_firewall()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "safe output"}}
    response = SimpleNamespace(text="unsafe alice@example.com")

    result = asyncio.run(fw.after_model(SimpleNamespace(agent_name="agent-a", session_id="s1"), response))

    assert result.text == "safe output"
    assert client.calls[-1][0] == "mesh_validate"


def test_before_tool_authorizes_tool():
    fw, client = make_firewall()
    tool = SimpleNamespace(name="crm.lookup")

    result = asyncio.run(fw.before_tool(tool, {"customer_id": "cust_123"}, SimpleNamespace(agent_name="agent-a", session_id="s1")))

    assert result is None
    assert client.calls[0][1]["direction"] == "outbound"
    assert client.calls[0][1]["tool_name"] == "crm.lookup"


def test_after_tool_sanitizes_structured_result_when_changed():
    fw, client = make_firewall()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "redacted"}}

    result = asyncio.run(fw.after_tool("crm.lookup", {}, SimpleNamespace(agent_name="agent-a", session_id="s1"), {"email": "a@example.com"}))

    assert result == "redacted"


def test_install_on_agent_sets_callbacks():
    fw, _ = make_firewall()
    agent = SimpleNamespace()

    result = fw.install_on_agent(agent, prefer_async=True)

    assert result is agent
    assert agent.before_model_callback == fw.before_model
    assert agent.after_tool_callback == fw.after_tool


def test_secure_tool_decorator_wraps_handler():
    fw, _ = make_firewall()

    @fw.secure_tool(tool_name="crm.lookup", tool_platform="crm")
    def lookup(ctx, args):
        return {"ok": args["ok"]}

    result = asyncio.run(lookup(SimpleNamespace(agent_name="agent-a", session_id="s1"), {"ok": True}))

    assert result == {"ok": True}


def test_fail_open_allows_guardrail_error():
    fw, client = make_firewall(fail_closed=False)
    client.raise_on_guardrail = RuntimeError("network down")

    result = asyncio.run(fw.screen_model_request(callback_context=SimpleNamespace(agent_name="agent-a", session_id="s1"), llm_request="hello"))

    assert result == {}
