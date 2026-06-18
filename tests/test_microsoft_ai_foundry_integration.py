import asyncio
from types import SimpleNamespace

import pytest

from agenticdome_sdk.microsoft_ai_foundry import (
    AgenticDomeMicrosoftAIFoundryFirewall,
    FirewallConfig,
    MicrosoftAIFoundryDenied,
)


class FakeFoundryClient:
    def __init__(self):
        self.prompt_response = {"allowed": True, "reason": "ok"}
        self.tool_response = {"allowed": True, "reason": "ok"}
        self.mesh_response = None
        self.raise_on_prompt = None
        self.calls = []

    def copilot_validate(self, payload, *, api_version="2025-09-01", timeout=None):
        self.calls.append(("copilot_validate", {"payload": payload, "api_version": api_version, "timeout": timeout}))
        if self.raise_on_prompt:
            raise self.raise_on_prompt
        return self.prompt_response

    def copilot_analyze_tool_execution(self, payload, *, api_version="2025-09-01", timeout=None):
        self.calls.append(("copilot_analyze_tool_execution", {"payload": payload, "api_version": api_version, "timeout": timeout}))
        return self.tool_response

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        if self.mesh_response is not None:
            return self.mesh_response
        return {"verdict": "ALLOWED", "sanitized_text": kwargs["text"]}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        return None


def make_firewall(*, api_key="mesh-key", fail_closed=True):
    client = FakeFoundryClient()
    fw = AgenticDomeMicrosoftAIFoundryFirewall(
        config=FirewallConfig(
            api_base="https://au.agenticdome.io",
            bearer_token="bearer-token",
            api_key=api_key,
            tenant_id="tenant-1",
            fail_closed=fail_closed,
            report_incidents=False,
        ),
        client=client,
    )
    return fw, client


def test_prompt_contract_allows_payload():
    fw, client = make_firewall()

    result = asyncio.run(fw.validate_prompt_contract(payload={"input": {"text": "hello"}}, agent_id="agent-a"))

    assert result == {"allowed": True, "reason": "ok"}
    assert client.calls[0][0] == "copilot_validate"
    assert client.calls[0][1]["api_version"] == "2025-09-01"


def test_prompt_contract_blocks_payload():
    fw, client = make_firewall()
    client.prompt_response = {"blocked": True, "reason": "prompt injection"}

    with pytest.raises(MicrosoftAIFoundryDenied):
        asyncio.run(fw.validate_prompt_contract(payload={"input": {"text": "bad"}}, agent_id="agent-a"))


def test_wrap_tool_executor_analyzes_tool_and_preserves_structured_result():
    fw, client = make_firewall()

    def handler(ctx, args):
        return {"customer_id": args["customer_id"], "status": "active"}

    secured = fw.wrap_tool_executor(tool_name="crm.customer.read", handler=handler, tool_platform="crm")
    ctx = SimpleNamespace(agent_id="agent-a", session_id="s1", prompt="read customer")

    result = asyncio.run(secured(ctx, {"customer_id": "cust_123"}))

    assert result == {"customer_id": "cust_123", "status": "active"}
    assert client.calls[0][0] == "copilot_analyze_tool_execution"
    assert client.calls[0][1]["payload"]["tool"]["name"] == "crm.customer.read"
    assert client.calls[1][0] == "mesh_validate"


def test_wrap_tool_executor_blocks_before_handler_runs():
    fw, client = make_firewall()
    client.tool_response = {"decision": {"verdict": "BLOCKED", "reason": "not allowed"}}
    executed = {"value": False}

    def handler(ctx, args):
        executed["value"] = True
        return "should not happen"

    secured = fw.wrap_tool_executor(tool_name="dangerous", handler=handler)

    with pytest.raises(MicrosoftAIFoundryDenied):
        asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {}))

    assert executed["value"] is False


def test_sanitize_text_skips_mesh_without_api_key():
    fw, client = make_firewall(api_key="")

    result = asyncio.run(fw.sanitize_text(text="email alice@example.com", agent_id="agent-a", session_id="s1"))

    assert result == "email alice@example.com"
    assert client.calls == []


def test_sanitize_text_returns_redacted_output_with_api_key():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "email [REDACTED]"}

    result = asyncio.run(fw.sanitize_text(text="email alice@example.com", agent_id="agent-a", session_id="s1"))

    assert result == "email [REDACTED]"


def test_run_secure_validates_prompt_runs_callable_and_sanitizes_output():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "final [REDACTED]"}

    def run_callable(input_text, session_id):
        return {"answer": f"final {input_text}", "session_id": session_id}

    result = asyncio.run(fw.run_secure(
        run_callable=run_callable,
        input_text="secret",
        ctx=SimpleNamespace(agent_id="agent-a", session_id="s1", user_id="user-a"),
    ))

    assert result == "final [REDACTED]"
    assert client.calls[0][0] == "copilot_validate"
    assert client.calls[1][0] == "mesh_validate"


def test_fail_open_allows_prompt_validation_errors():
    fw, client = make_firewall(fail_closed=False)
    client.raise_on_prompt = RuntimeError("network down")

    result = asyncio.run(fw.validate_prompt_contract(payload={}, agent_id="agent-a"))

    assert result == {}


def test_secure_tool_decorator_wraps_handler():
    fw, _ = make_firewall()

    @fw.secure_tool(tool_name="crm.lookup", tool_platform="crm")
    def lookup(ctx, args):
        return {"ok": args["ok"]}

    result = asyncio.run(lookup(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"ok": True}))

    assert result == {"ok": True}
