import asyncio

import pytest

from agenticdome_sdk.llamaindex import AgenticDomeLlamaIndexFirewall, FirewallConfig, LlamaIndexDenied


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
    fw = AgenticDomeLlamaIndexFirewall(
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


def test_screen_input_allows_query():
    fw, client = make_firewall()

    result = asyncio.run(fw.screen_input(text="query customer", agent_id="agent-a", session_id="s1"))

    assert result == {"result": {"verdict": "ALLOWED", "reason": "ok"}}
    assert client.calls[0][1]["direction"] == "input"


def test_screen_input_blocks_query():
    fw, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "BLOCKED", "reason": "bad"}}

    with pytest.raises(LlamaIndexDenied):
        asyncio.run(fw.screen_input(text="bad", agent_id="agent-a", session_id="s1"))


def test_wrap_tool_function_authorizes_and_preserves_structured_output():
    fw, client = make_firewall()

    def lookup(customer_id: str):
        return {"customer_id": customer_id, "status": "active"}

    secured = fw.wrap_tool_function(lookup, tool_name="crm.lookup", tool_platform="crm", agent_id="agent-a", session_id="s1")
    result = asyncio.run(secured("cust_123"))

    assert result == {"customer_id": "cust_123", "status": "active"}
    assert client.calls[0][1]["tool_name"] == "crm.lookup"
    assert client.calls[0][1]["tool_args"] == {"customer_id": "cust_123"}


def test_wrap_tool_function_blocks_before_execution():
    fw, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "BLOCKED", "reason": "not allowed"}}
    executed = {"value": False}

    def dangerous():
        executed["value"] = True
        return "bad"

    secured = fw.wrap_tool_function(dangerous, tool_name="dangerous", agent_id="agent-a", session_id="s1")

    with pytest.raises(LlamaIndexDenied):
        asyncio.run(secured())

    assert executed["value"] is False


def test_run_query_securely_screens_and_sanitizes_output():
    fw, client = make_firewall()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "safe answer"}}

    def query_engine(query: str):
        return f"answer for {query} alice@example.com"

    result = asyncio.run(fw.run_query_securely(query_callable=query_engine, query_text="hello", agent_id="agent-a", session_id="s1"))

    assert result == "safe answer"
    assert [name for name, _ in client.calls] == ["guardrail_validate", "mesh_validate"]


def test_sanitize_retrieval_result_preserves_structured_result_when_unchanged():
    fw, _ = make_firewall()
    retrieval = {"nodes": [{"text": "safe"}]}

    result = asyncio.run(fw.sanitize_retrieval_result(retrieval_result=retrieval, agent_id="agent-a", session_id="s1"))

    assert result == retrieval


def test_secure_tool_decorator_wraps_function():
    fw, _ = make_firewall()

    @fw.secure_tool(tool_name="crm.lookup", agent_id="agent-a", session_id="s1")
    def lookup(customer_id: str):
        return {"customer_id": customer_id}

    result = asyncio.run(lookup("cust_123"))

    assert result == {"customer_id": "cust_123"}


def test_fail_open_allows_guardrail_error():
    fw, client = make_firewall(fail_closed=False)
    client.raise_on_guardrail = RuntimeError("network down")

    result = asyncio.run(fw.screen_input(text="hello", agent_id="agent-a", session_id="s1"))

    assert result == {}
