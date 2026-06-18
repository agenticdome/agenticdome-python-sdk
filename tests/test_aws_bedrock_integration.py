import asyncio
import json
from types import SimpleNamespace

import pytest

from agenticdome_sdk.aws_bedrock import AgenticDomeAWSBedrockFirewall, AWSBedrockDenied, FirewallConfig


class FakeAgenticDomeClient:
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

    def close(self):
        self.calls.append(("close", {}))


class FakeBedrockRuntimeClient:
    def __init__(self):
        self.calls = []
        self.converse_response = {
            "output": {"message": {"role": "assistant", "content": [{"text": "hello alice@example.com"}]}}
        }
        self.invoke_response = {"body": json.dumps({"completion": "hello alice@example.com"}).encode("utf-8")}

    def converse(self, **kwargs):
        self.calls.append(("converse", kwargs))
        return self.converse_response

    def invoke_model(self, **kwargs):
        self.calls.append(("invoke_model", kwargs))
        return self.invoke_response


def make_firewall(*, fail_closed=True):
    client = FakeAgenticDomeClient()
    firewall = AgenticDomeAWSBedrockFirewall(
        config=FirewallConfig(
            api_base="https://au.agenticdome.io",
            api_key="key",
            tenant_id="tenant",
            fail_closed=fail_closed,
            report_incidents=False,
        ),
        client=client,
    )
    return firewall, client


def test_converse_securely_screens_prompt_calls_bedrock_and_sanitizes_output():
    firewall, client = make_firewall()
    bedrock = FakeBedrockRuntimeClient()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "hello [REDACTED]"}}

    result = asyncio.run(
        firewall.converse_securely(
            bedrock_runtime_client=bedrock,
            model_id="anthropic.claude-3-5-sonnet",
            messages=[{"role": "user", "content": [{"text": "email Alice"}]}],
            agent_id="agent-a",
            session_id="s1",
        )
    )

    assert result["output"]["message"]["content"][0]["text"] == "hello [REDACTED]"
    assert client.calls[0][0] == "guardrail_validate"
    assert client.calls[0][1]["direction"] == "input"
    assert bedrock.calls[0][0] == "converse"
    assert client.calls[1][0] == "mesh_validate"


def test_converse_securely_blocks_before_bedrock_call():
    firewall, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "BLOCKED", "reason": "prompt injection"}}
    bedrock = FakeBedrockRuntimeClient()

    with pytest.raises(AWSBedrockDenied):
        asyncio.run(
            firewall.converse_securely(
                bedrock_runtime_client=bedrock,
                model_id="model",
                messages=[{"role": "user", "content": [{"text": "bad"}]}],
                agent_id="agent-a",
                session_id="s1",
            )
        )

    assert bedrock.calls == []


def test_invoke_model_securely_extracts_prompt_and_sanitizes_body():
    firewall, client = make_firewall()
    bedrock = FakeBedrockRuntimeClient()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "safe completion"}}

    result = asyncio.run(
        firewall.invoke_model_securely(
            bedrock_runtime_client=bedrock,
            model_id="amazon.titan-text",
            body=json.dumps({"inputText": "tell me about customer Alice"}),
            agent_id="agent-a",
            session_id="s1",
            contentType="application/json",
            accept="application/json",
        )
    )

    assert json.loads(result["body"].decode("utf-8"))["completion"] == "safe completion"
    assert bedrock.calls[0][1]["contentType"] == "application/json"
    assert client.calls[0][1]["policy_context"]["model_id"] == "amazon.titan-text"


def test_wrap_tool_handler_authorizes_tool_and_preserves_structured_output():
    firewall, client = make_firewall()

    def lookup(ctx, args):
        return {"customer_id": args["customer_id"], "status": "active"}

    secured = firewall.wrap_tool_handler(tool_name="crm.customer.read", handler=lookup, tool_platform="crm")
    result = asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"customer_id": "cust_123"}))

    assert result == {"customer_id": "cust_123", "status": "active"}
    assert client.calls[0][0] == "guardrail_validate"
    assert client.calls[0][1]["direction"] == "outbound"
    assert client.calls[0][1]["tool_name"] == "crm.customer.read"


def test_wrap_tool_handler_blocks_before_handler_runs():
    firewall, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "BLOCKED", "reason": "not allowed"}}
    executed = {"value": False}

    def dangerous(ctx, args):
        executed["value"] = True
        return "bad"

    secured = firewall.wrap_tool_handler(tool_name="dangerous", handler=dangerous)

    with pytest.raises(AWSBedrockDenied):
        asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {}))

    assert executed["value"] is False


def test_secure_tool_decorator_wraps_handler():
    firewall, _ = make_firewall()

    @firewall.secure_tool(tool_name="crm.lookup", tool_platform="crm")
    def lookup(ctx, args):
        return {"ok": args["ok"]}

    result = asyncio.run(lookup(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"ok": True}))

    assert result == {"ok": True}


def test_sanitize_retrieval_result_returns_structured_when_unchanged():
    firewall, _ = make_firewall()
    retrieval = {"retrievalResults": [{"content": {"text": "safe"}}]}

    result = asyncio.run(
        firewall.sanitize_retrieval_result(
            retrieval_result=retrieval,
            agent_id="agent-a",
            session_id="s1",
        )
    )

    assert result == retrieval


def test_fail_open_allows_guardrail_error():
    firewall, client = make_firewall(fail_closed=False)
    client.raise_on_guardrail = RuntimeError("network down")

    result = asyncio.run(firewall.screen_prompt(text="hello", agent_id="agent-a", session_id="s1"))

    assert result == {}
