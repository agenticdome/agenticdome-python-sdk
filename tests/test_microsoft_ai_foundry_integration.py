import asyncio
from types import SimpleNamespace

import pytest

from agenticdome_sdk.microsoft_ai_foundry import (
    AgenticDomeMicrosoftAIFoundryFirewall,
    FirewallConfig,
    InMemoryDecisionTokenStore,
    MicrosoftAIFoundryConfigurationError,
    MicrosoftAIFoundryDenied,
)


class FakeFoundryClient:
    def __init__(self):
        self.prompt_response = {"allowed": True, "reason": "ok"}
        self.tool_response = {"allowed": True, "reason": "ok"}
        self.mesh_response = None
        self.raise_on_prompt = None
        self.prompt_failures_remaining = 0
        self.handoff_response = {"allowed": True, "decision_token": "token-1"}
        self.verify_response = {"valid": True, "allowed": True}
        self.calls = []

    def copilot_validate(self, payload, *, api_version="2025-09-01", timeout=None):
        self.calls.append(("copilot_validate", {"payload": payload, "api_version": api_version, "timeout": timeout}))
        if self.raise_on_prompt:
            raise self.raise_on_prompt
        if self.prompt_failures_remaining:
            self.prompt_failures_remaining -= 1
            raise RuntimeError("temporary network error")
        return self.prompt_response

    def copilot_analyze_tool_execution(self, payload, *, api_version="2025-09-01", timeout=None):
        self.calls.append(("copilot_analyze_tool_execution", {"payload": payload, "api_version": api_version, "timeout": timeout}))
        return self.tool_response

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        if self.mesh_response is not None:
            return self.mesh_response
        return {"verdict": "ALLOWED", "sanitized_text": kwargs["text"]}

    def a2a_authorize_tool(self, **kwargs):
        self.calls.append(("a2a_authorize_tool", kwargs))
        return self.handoff_response

    def a2a_verify_decision_token_rpc(self, token, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", {"token": token, **kwargs}))
        return self.verify_response

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        return None


def make_firewall(*, api_key="mesh-key", fail_closed=True, bearer_token="bearer-token", **overrides):
    client = FakeFoundryClient()
    config = FirewallConfig(
        api_base="https://demo-sidecar.agenticdome.io",
        bearer_token=bearer_token,
        api_key=api_key,
        tenant_id="tenant-1",
        fail_closed=fail_closed,
        report_incidents=False,
        retry_backoff_s=0,
        audit_logging=False,
        otel_enabled=False,
        **overrides,
    )
    fw = AgenticDomeMicrosoftAIFoundryFirewall(config=config, client=client)
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


def test_missing_api_key_raises_configuration_error():
    with pytest.raises(MicrosoftAIFoundryConfigurationError):
        make_firewall(api_key="")


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


def test_missing_bearer_token_raises_configuration_error():
    with pytest.raises(MicrosoftAIFoundryConfigurationError):
        make_firewall(bearer_token="")


def test_production_requires_stable_session_id():
    fw, _ = make_firewall(production_mode=True)

    with pytest.raises(MicrosoftAIFoundryDenied):
        asyncio.run(fw.run_secure(run_callable=lambda input_text, session_id: "ok", input_text="hello", ctx=SimpleNamespace(agent_id="agent-a")))


def test_direct_tool_analysis_strips_internal_args():
    fw, client = make_firewall()

    asyncio.run(fw.analyze_tool_execution(
        payload={
            "sessionId": "s1",
            "tool": {"name": "crm.lookup", "arguments": {"customer_id": "c1", "_agenticdome_decision_token": "secret", "decision_token": "secret"}},
        },
        agent_id="agent-a",
    ))

    forwarded_args = client.calls[0][1]["payload"]["tool"]["arguments"]
    assert forwarded_args == {"customer_id": "c1"}


def test_sanitized_tool_args_are_executed():
    fw, client = make_firewall()
    client.tool_response = {"allowed": True, "sanitized_tool_args": {"query": "select * from t", "limit": 100}}

    def handler(ctx, args):
        return {"limit": args["limit"]}

    secured = fw.wrap_tool_executor(tool_name="sql.query", handler=handler, sanitize_output=False)
    result = asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"query": "select * from t", "limit": 100000}))

    assert result == {"limit": 100}


def test_tool_schema_validation_blocks_bad_args():
    fw, _ = make_firewall()
    secured = fw.wrap_tool_executor(
        tool_name="crm.lookup",
        handler=lambda ctx, args: args,
        tool_schema={"required": ["customer_id"], "properties": {"customer_id": {"type": "string"}}},
    )

    with pytest.raises(MicrosoftAIFoundryDenied):
        asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {"customer_id": 123}))


def test_structured_output_is_preserved_from_sanitized_json():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": '{"email":"[REDACTED]"}'}

    secured = fw.wrap_tool_executor(tool_name="crm.lookup", handler=lambda ctx, args: {"email": "alice@example.com"})
    result = asyncio.run(secured(SimpleNamespace(agent_id="agent-a", session_id="s1"), {}))

    assert result == {"email": "[REDACTED]"}


def test_output_blocking_returns_block_marker():
    fw, client = make_firewall()
    client.mesh_response = {"blocked": True, "reason": "secret"}

    result = asyncio.run(fw.sanitize_text(text="secret", agent_id="agent-a", session_id="s1"))

    assert result == "[OUTPUT BLOCKED BY AgenticDome]"


def test_large_prompt_is_truncated_before_validation():
    fw, client = make_firewall(max_input_chars=5)

    asyncio.run(fw.run_secure(run_callable=lambda input_text, session_id: "ok", input_text="abcdefghij", ctx=SimpleNamespace(agent_id="agent-a", session_id="s1"), sanitize_output=False))

    prompt_text = client.calls[0][1]["payload"]["input"]["text"]
    assert prompt_text.startswith("abcde")
    assert "TRUNCATED BY AgenticDome FOUNDRY INPUT" in prompt_text


def test_rate_limit_blocks_second_prompt():
    fw, _ = make_firewall(rate_limit_per_minute=1)

    asyncio.run(fw.validate_prompt_contract(payload={"sessionId": "s1", "input": {"text": "one"}}, agent_id="agent-a"))
    with pytest.raises(MicrosoftAIFoundryDenied):
        asyncio.run(fw.validate_prompt_contract(payload={"sessionId": "s1", "input": {"text": "two"}}, agent_id="agent-a"))


def test_retry_allows_transient_prompt_failure():
    fw, client = make_firewall(retry_attempts=2)
    client.prompt_failures_remaining = 1

    result = asyncio.run(fw.validate_prompt_contract(payload={"sessionId": "s1"}, agent_id="agent-a"))

    assert result == {"allowed": True, "reason": "ok"}
    assert [name for name, _ in client.calls].count("copilot_validate") == 2


def test_circuit_breaker_fail_closes_after_failures():
    fw, client = make_firewall(retry_attempts=1, circuit_breaker_failures=1, circuit_breaker_reset_s=60)
    client.raise_on_prompt = RuntimeError("down")

    with pytest.raises(MicrosoftAIFoundryDenied):
        asyncio.run(fw.validate_prompt_contract(payload={"sessionId": "s1"}, agent_id="agent-a"))
    client.raise_on_prompt = None
    with pytest.raises(MicrosoftAIFoundryDenied):
        asyncio.run(fw.validate_prompt_contract(payload={"sessionId": "s1"}, agent_id="agent-a"))


def test_middleware_before_tool_call_returns_sanitized_args_and_installs():
    fw, client = make_firewall()
    client.tool_response = {"allowed": True, "sanitized_tool_args": {"limit": 10}}
    foundry_client = SimpleNamespace()

    installed = fw.install_on_client(foundry_client)
    middleware = installed.agenticdome_middleware[0]
    result = asyncio.run(middleware.before_tool_call(SimpleNamespace(agent_id="agent-a", session_id="s1"), "search", {"limit": 100}, tool_schema={"properties": {"limit": {"type": "integer"}}}))

    assert result == {"limit": 10}


def test_streaming_response_sanitizes_chunks():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "[REDACTED]"}

    async def collect():
        return [chunk async for chunk in fw.sanitize_streaming_response(chunks=["secret", "more"], agent_id="agent-a", session_id="s1")]

    assert asyncio.run(collect()) == ["[REDACTED]", "[REDACTED]"]


def test_handoff_authorization_stores_and_consumes_decision_token():
    fw, client = make_firewall(token_hmac_secret="local-secret")
    assert isinstance(fw.token_store, InMemoryDecisionTokenStore)

    asyncio.run(fw.authorize_manager_handoff(
        text="delegate lookup",
        manager_agent_id="manager",
        specialist_agent_id="specialist",
        tool_name="crm.lookup",
        tool_args={"customer_id": "c1"},
        session_id="s1",
    ))
    result = asyncio.run(fw.verify_delegated_execution(
        specialist_agent_id="specialist",
        tool_name="crm.lookup",
        tool_args={"customer_id": "c1"},
        session_id="s1",
    ))

    assert result["valid"] is True
    assert client.calls[-1][0] == "a2a_verify_decision_token_rpc"
    assert client.calls[-1][1]["token"] == "token-1"


def test_missing_delegation_token_blocks_execution():
    fw, _ = make_firewall()

    with pytest.raises(MicrosoftAIFoundryDenied):
        asyncio.run(fw.verify_delegated_execution(specialist_agent_id="specialist", tool_name="crm.lookup", tool_args={}, session_id="s1"))
