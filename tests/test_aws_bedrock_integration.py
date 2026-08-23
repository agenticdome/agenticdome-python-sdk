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
        self.guardrail_failures_remaining = 0

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if self.guardrail_failures_remaining > 0:
            self.guardrail_failures_remaining -= 1
            raise RuntimeError("temporary network down")
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
        self.converse_response = {"output": {"message": {"role": "assistant", "content": [{"text": "hello alice@example.com"}]}}}
        self.invoke_response = {"body": json.dumps({"completion": "hello alice@example.com"}).encode("utf-8")}
        self.stream_events = [
            {"chunk": {"bytes": json.dumps({"completion": "hello alice@example.com"}).encode("utf-8")}}
        ]

    def converse(self, **kwargs):
        self.calls.append(("converse", kwargs))
        return self.converse_response

    def converse_stream(self, **kwargs):
        self.calls.append(("converse_stream", kwargs))
        return {"stream": list(self.stream_events)}

    def invoke_model(self, **kwargs):
        self.calls.append(("invoke_model", kwargs))
        return self.invoke_response

    def invoke_model_with_response_stream(self, **kwargs):
        self.calls.append(("invoke_model_with_response_stream", kwargs))
        return {"body": list(self.stream_events)}


class FakeBedrockAgentRuntimeClient:
    def __init__(self):
        self.calls = []
        self.response = {"completion": [{"chunk": {"bytes": json.dumps({"completion": "agent says alice@example.com"}).encode("utf-8")}}]}

    def invoke_agent(self, **kwargs):
        self.calls.append(("invoke_agent", kwargs))
        return self.response


def make_firewall(*, fail_closed=True, **overrides):
    client = FakeAgenticDomeClient()
    config_kwargs = dict(
        api_base="https://demo-sidecar.agenticdome.io",
        api_key="key",
        tenant_id="tenant",
        fail_closed=fail_closed,
        report_incidents=False,
        retry_backoff_s=0,
        audit_logging=False,
        otel_enabled=False,
    )
    config_kwargs.update(overrides)
    firewall = AgenticDomeAWSBedrockFirewall(config=FirewallConfig(**config_kwargs), client=client)
    return firewall, client


def test_converse_securely_screens_prompt_calls_bedrock_and_sanitizes_output():
    firewall, client = make_firewall()
    bedrock = FakeBedrockRuntimeClient()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "hello [REDACTED]"}}

    result = asyncio.run(firewall.converse_securely(
        bedrock_runtime_client=bedrock,
        model_id="anthropic.claude-3-5-sonnet",
        messages=[{"role": "user", "content": [{"text": "email Alice"}]}],
        agent_id="agent-a",
        session_id="s1",
    ))

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
        asyncio.run(firewall.converse_securely(
            bedrock_runtime_client=bedrock,
            model_id="model",
            messages=[{"role": "user", "content": [{"text": "bad"}]}],
            agent_id="agent-a",
            session_id="s1",
        ))

    assert bedrock.calls == []


def test_production_mode_requires_stable_session_id():
    firewall, _ = make_firewall(production_mode=True, require_stable_session_id_in_prod=True)

    with pytest.raises(AWSBedrockDenied):
        asyncio.run(firewall.converse_securely(
            bedrock_runtime_client=FakeBedrockRuntimeClient(),
            model_id="model",
            messages=[{"role": "user", "content": [{"text": "hello"}]}],
        ))


def test_invoke_model_securely_extracts_prompt_and_sanitizes_titan_body():
    firewall, client = make_firewall()
    bedrock = FakeBedrockRuntimeClient()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "safe completion"}}

    result = asyncio.run(firewall.invoke_model_securely(
        bedrock_runtime_client=bedrock,
        model_id="amazon.titan-text",
        body=json.dumps({"inputText": "tell me about customer Alice"}),
        agent_id="agent-a",
        session_id="s1",
        contentType="application/json",
        accept="application/json",
    ))

    assert json.loads(result["body"].decode("utf-8"))["completion"] == "safe completion"
    assert bedrock.calls[0][1]["contentType"] == "application/json"
    assert client.calls[0][1]["policy_context"]["model_id"] == "amazon.titan-text"


def test_provider_specific_payload_parsers_cover_claude_llama_mistral():
    firewall, _ = make_firewall()

    claude = {"anthropic_version": "bedrock-2023-05-31", "system": "sys", "messages": [{"role": "user", "content": [{"text": "claude prompt"}]}]}
    llama = {"prompt": "llama prompt"}
    mistral = {"prompt": "mistral prompt"}

    assert "claude prompt" in firewall.extract_text_from_invoke_body(json.dumps(claude))
    assert firewall.extract_text_from_invoke_body(json.dumps(llama)) == "llama prompt"
    assert firewall.extract_text_from_invoke_body(json.dumps(mistral)) == "mistral prompt"


def test_converse_stream_sanitizes_events():
    firewall, client = make_firewall()
    bedrock = FakeBedrockRuntimeClient()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "safe stream"}}

    async def collect():
        out = []
        async for event in firewall.converse_stream_securely(
            bedrock_runtime_client=bedrock,
            model_id="anthropic.claude",
            messages=[{"role": "user", "content": [{"text": "hello"}]}],
            agent_id="agent-a",
            session_id="s1",
        ):
            out.append(event)
        return out

    result = asyncio.run(collect())
    body = json.loads(result[0]["chunk"]["bytes"].decode("utf-8"))
    assert body["completion"] == "safe stream"
    assert bedrock.calls[0][0] == "converse_stream"


def test_invoke_model_with_response_stream_sanitizes_events():
    firewall, client = make_firewall()
    bedrock = FakeBedrockRuntimeClient()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "safe invoke stream"}}

    async def collect():
        out = []
        async for event in firewall.invoke_model_with_response_stream_securely(
            bedrock_runtime_client=bedrock,
            model_id="amazon.titan",
            body=json.dumps({"inputText": "hello"}),
            agent_id="agent-a",
            session_id="s1",
        ):
            out.append(event)
        return out

    result = asyncio.run(collect())
    body = json.loads(result[0]["chunk"]["bytes"].decode("utf-8"))
    assert body["completion"] == "safe invoke stream"
    assert bedrock.calls[0][0] == "invoke_model_with_response_stream"


def test_invoke_agent_securely_screens_and_sanitizes_completion_stream():
    firewall, client = make_firewall()
    agent_client = FakeBedrockAgentRuntimeClient()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "agent safe"}}

    result = asyncio.run(firewall.invoke_agent_securely(
        bedrock_agent_runtime_client=agent_client,
        agent_id="bedrock-agent",
        agent_alias_id="alias",
        session_id="s1",
        input_text="help me",
        source_agent_id="agent-a",
    ))

    body = json.loads(result["completion"][0]["chunk"]["bytes"].decode("utf-8"))
    assert body["completion"] == "agent safe"
    assert agent_client.calls[0][0] == "invoke_agent"


def test_wrap_tool_handler_authorizes_tool_strips_internal_args_and_preserves_structured_output():
    firewall, client = make_firewall()

    def lookup(ctx, args):
        assert "_agenticdome_decision_token" not in args
        return {"customer_id": args["customer_id"], "status": "active"}

    secured = firewall.wrap_tool_handler(tool_name="crm.customer.read", handler=lookup, tool_platform="crm")
    result = asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"customer_id": "cust_123", "_agenticdome_decision_token": "secret"}))

    assert result == {"customer_id": "cust_123", "status": "active"}
    assert client.calls[0][1]["direction"] == "delegated_execution"
    assert "_agenticdome_decision_token" not in client.calls[0][1]["tool_args"]


def test_direct_tool_authorization_strips_internal_args():
    firewall, client = make_firewall()

    asyncio.run(firewall.authorize_tool_call(
        tool_name="crm.customer.read",
        tool_args={"customer_id": "cust_123", "_agenticdome_source_agent_id": "manager"},
        agent_id="agent-a",
        session_id="s1",
        text="tool",
    ))

    assert client.calls[0][1]["tool_args"] == {"customer_id": "cust_123"}


def test_wrap_tool_handler_applies_sanitized_args():
    firewall, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"customer_id": "safe"}}}

    def lookup(ctx, args):
        return {"customer_id": args["customer_id"]}

    secured = firewall.wrap_tool_handler(tool_name="crm.customer.read", handler=lookup, tool_platform="crm")
    result = asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"customer_id": "unsafe"}))

    assert result == {"customer_id": "safe"}


def test_tool_schema_validation_blocks_bad_args():
    firewall, _ = make_firewall()
    secured = firewall.wrap_tool_handler(
        tool_name="crm.customer.read",
        handler=lambda ctx, args: args,
        tool_schema={"required": ["customer_id"], "properties": {"customer_id": {"type": "string"}}},
    )

    with pytest.raises(AWSBedrockDenied):
        asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"customer_id": 123}))


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


def test_action_group_lambda_wrapper_authorizes_event():
    firewall, client = make_firewall()

    def handler(event, context):
        return {"ok": True, "function": event["function"]}

    wrapped = firewall.wrap_action_group_lambda(handler=handler)
    event = {"function": "crm.lookup", "parameters": {"customer_id": "1"}, "sessionId": "s1", "agent": {"id": "agent-a"}}

    result = asyncio.run(wrapped(event, SimpleNamespace(aws_request_id="req", invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:f")))

    assert result == {"ok": True, "function": "crm.lookup"}
    assert client.calls[0][1]["tool_name"] == "crm.lookup"


def test_sanitize_retrieval_result_sanitizes_each_knowledge_base_node():
    firewall, client = make_firewall()
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": "safe node"}}
    retrieval = {"retrievalResults": [{"content": {"text": "alice@example.com"}}, {"content": {"text": "bob@example.com"}}]}

    result = asyncio.run(firewall.sanitize_retrieval_result(retrieval_result=retrieval, agent_id="agent-a", session_id="s1"))

    assert result["retrievalResults"][0]["content"]["text"] == "safe node"
    assert result["retrievalResults"][1]["content"]["text"] == "safe node"
    assert len([call for call in client.calls if call[0] == "mesh_validate"]) == 2


def test_fail_open_allows_guardrail_error():
    firewall, client = make_firewall(fail_closed=False)
    client.raise_on_guardrail = RuntimeError("network down")

    result = asyncio.run(firewall.screen_prompt(text="hello", agent_id="agent-a", session_id="s1"))

    assert result == {}


def test_size_limit_blocks_large_tool_args():
    firewall, _ = make_firewall(max_tool_arg_chars=10)
    secured = firewall.wrap_tool_handler(tool_name="large", handler=lambda ctx, args: args)

    with pytest.raises(AWSBedrockDenied):
        asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"payload": "x" * 100}))


def test_rate_limit_blocks_excess_prompt_calls():
    firewall, _ = make_firewall(rate_limit_per_minute=1)

    asyncio.run(firewall.screen_prompt(text="hello", agent_id="agent-a", session_id="s1"))
    with pytest.raises(AWSBedrockDenied):
        asyncio.run(firewall.screen_prompt(text="hello again", agent_id="agent-a", session_id="s1"))


def test_retry_allows_transient_guardrail_failure():
    firewall, client = make_firewall(retry_attempts=2)
    client.guardrail_failures_remaining = 1

    asyncio.run(firewall.screen_prompt(text="hello", agent_id="agent-a", session_id="s1"))

    assert len([call for call in client.calls if call[0] == "guardrail_validate"]) == 2


def test_handoff_stores_clean_args_and_verify_uses_fallback():
    firewall, client = make_firewall(token_hmac_secret="secret")
    client.guardrail_response = {"result": {"verdict": "ALLOWED", "decision_token": "token-1"}}

    record = asyncio.run(firewall.authorize_manager_handoff(
        source_agent_id="manager",
        target_agent_id="specialist",
        target_tool_name="crm.lookup",
        target_tool_args={"customer_id": "1", "_agenticdome_decision_token": "old"},
        session_id="s1",
    ))
    client.calls.clear()

    asyncio.run(firewall.verify_delegated_execution(
        target_agent_id="specialist",
        tool_name="crm.lookup",
        tool_args={"customer_id": "1"},
        session_id="s1",
    ))

    assert record.decision_token == "token-1"
    assert client.calls[0][1]["direction"] == "delegated_execution"
    assert client.calls[0][1]["decision_token"] == "token-1"
