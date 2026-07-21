import asyncio

import pytest

from agenticdome_sdk.agno import (
    AgenticDomeAgnoDenied,
    AgenticDomeAgnoFirewall,
    DecisionTokenRecord,
    FirewallConfig,
    InMemoryDecisionTokenStore,
)


class FakePolicyClient:
    def __init__(self):
        self.guardrail_verdict = "ALLOWED"
        self.guardrail_response = None
        self.mesh_response = None
        self.verify_valid = True
        self.raise_guardrail = None
        self.guardrail_failures_remaining = 0
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        if self.guardrail_failures_remaining > 0:
            self.guardrail_failures_remaining -= 1
            raise RuntimeError("temporary network down")
        if self.raise_guardrail:
            raise self.raise_guardrail
        if self.guardrail_response is not None:
            return self.guardrail_response
        return {"verdict": self.guardrail_verdict, "reason": "test policy"}

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        if self.mesh_response is not None:
            return self.mesh_response
        return {"verdict": "ALLOWED", "sanitized_text": kwargs["text"]}

    def a2a_authorize_tool(self, **kwargs):
        self.calls.append(("a2a_authorize_tool", kwargs))
        return {"result": {"verdict": "ALLOWED", "decision_token": "token-ok", "reason": "ok"}}

    def a2a_verify_decision_token_rpc(self, token, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", {"token": token, **kwargs}))
        return {"result": {"valid": self.verify_valid and token == "token-ok", "reason": "verified"}}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        return None


class Agent:
    def __init__(self):
        self.id = "agent-a"
        self.session_id = "session-a"


class Output:
    def __init__(self, content):
        self.content = content


def make_firewall(fail_closed=True, **overrides):
    client = FakePolicyClient()
    config_kwargs = dict(
        api_base="https://demo-sidecar.agenticdome.io",
        api_key="test-key",
        tenant_id="test-tenant",
        fail_closed=fail_closed,
        report_incidents=False,
        retry_backoff_s=0,
        audit_logging=False,
        otel_enabled=False,
    )
    config_kwargs.update(overrides)
    fw = AgenticDomeAgnoFirewall(
        config=FirewallConfig(**config_kwargs),
        client=client,
        token_store=InMemoryDecisionTokenStore("test-tenant"),
    )
    return fw, client


def test_pre_hook_screens_prompt_input():
    fw, client = make_firewall()

    assert fw.pre_hook(Agent(), input="hello", session_id="s1") is True

    assert client.calls[0][0] == "guardrail_validate"
    assert client.calls[0][1]["direction"] == "input"
    assert client.calls[0][1]["platform"] == "agno"


def test_pre_hook_blocks_prompt_when_policy_blocks():
    fw, client = make_firewall()
    client.guardrail_verdict = "BLOCKED"

    with pytest.raises(AgenticDomeAgnoDenied):
        fw.pre_hook(Agent(), input="bad", session_id="s1")


def test_production_mode_requires_stable_session_id():
    fw, _ = make_firewall(production_mode=True, require_stable_session_id_in_prod=True)
    agent = Agent()
    agent.session_id = None

    with pytest.raises(AgenticDomeAgnoDenied):
        fw.pre_hook(agent, input="hello")


def test_pre_hook_authorizes_tool_call_and_strips_private_args():
    fw, client = make_firewall()

    assert fw.pre_hook(
        Agent(),
        input="read crm",
        session_id="s1",
        tool_name="crm.customer.read",
        tool_args={"customer_id": "cust_123", "_AgenticDome_decision_token": "secret"},
        tool_platform="crm",
    ) is True

    assert client.calls[0][0] == "guardrail_validate"
    assert client.calls[0][1]["tool_args"] == {"customer_id": "cust_123"}


def test_direct_authorize_tool_strips_private_args():
    fw, client = make_firewall()

    fw.authorize_tool_call(
        agent=Agent(),
        kwargs={"session_id": "s1"},
        tool_name="crm.customer.read",
        tool_args={"customer_id": "cust_123", "_AgenticDome_source_agent_id": "manager"},
    )

    assert client.calls[0][1]["tool_args"] == {"customer_id": "cust_123"}


def test_pre_hook_applies_sanitized_tool_args_to_kwargs():
    fw, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"customer_id": "safe", "_AgenticDome_decision_token": "drop"}}}
    args = {"customer_id": "unsafe"}

    fw.pre_hook(Agent(), session_id="s1", tool_name="crm.customer.read", tool_args=args)

    assert args == {"customer_id": "safe"}


def test_tool_schema_validation_blocks_bad_args():
    fw, _ = make_firewall()

    with pytest.raises(AgenticDomeAgnoDenied):
        fw.authorize_tool_call(
            agent=Agent(),
            kwargs={"session_id": "s1"},
            tool_name="crm.customer.read",
            tool_args={"customer_id": 123},
            tool_schema={"required": ["customer_id"], "properties": {"customer_id": {"type": "string"}}},
        )


def test_manager_delegation_authorizes_and_stores_token_with_hmac():
    fw, client = make_firewall(token_hmac_secret="secret")
    agent = Agent()
    agent.team = ["specialist"]

    assert fw.pre_hook(
        agent,
        input="delegate refund",
        session_id="s1",
        tool_name="delegate_refund",
        tool_args={
            "target_agent_id": "payments_specialist",
            "target_tool_name": "payments.refund.create",
            "target_tool_args": {"amount": 250, "_AgenticDome_decision_token": "old"},
        },
        tool_platform="payments",
    ) is True

    assert client.calls[0][0] == "a2a_authorize_tool"
    assert client.calls[0][1]["tool_args"] == {"amount": 250}
    pending = fw.token_store.get(session_id="s1", target_agent_id="payments_specialist", tool_name="payments.refund.create", tool_args={"amount": 250})
    assert pending is not None
    assert pending.decision_token == "token-ok"
    assert pending.token_hmac


def test_specialist_execution_verifies_stored_token_once():
    fw, client = make_firewall(token_hmac_secret="secret")
    fw.token_store.put(
        session_id="s1",
        target_agent_id="agent-a",
        tool_name="payments.refund.create",
        tool_args={"amount": 250},
        record=DecisionTokenRecord("token-ok", "manager", 1.0, token_hmac=fw._token_hmac("token-ok")),
        ttl_s=900,
    )

    assert fw.pre_hook(Agent(), session_id="s1", tool_name="payments.refund.create", tool_args={"amount": 250}) is True

    assert client.calls[0][0] == "a2a_verify_decision_token_rpc"
    assert fw.token_store.get(session_id="s1", target_agent_id="agent-a", tool_name="payments.refund.create", tool_args={"amount": 250}) is None


def test_post_hook_sanitizes_output_object():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "email [REDACTED]"}
    output = Output("email alice@example.com")

    result = fw.post_hook(output, Agent(), session_id="s1")

    assert result is output
    assert output.content == "email [REDACTED]"


def test_post_hook_preserves_structured_output_when_unchanged():
    fw, _ = make_firewall()
    payload = {"ok": True}

    result = fw.post_hook(payload, Agent(), session_id="s1")

    assert result == payload


def test_post_hook_parses_sanitized_structured_json():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "ALLOWED", "sanitized_text": '{"email":"[REDACTED]"}'}

    result = fw.post_hook({"email": "a@example.com"}, Agent(), session_id="s1")

    assert result == {"email": "[REDACTED]"}


def test_sanitize_retrieved_text_returns_redacted_text():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "REDACTED", "sanitized_text": "secret [REDACTED]"}

    result = fw.sanitize_retrieved_text(text="secret 123", agent_id="agent-a", session_id="s1")

    assert result == "secret [REDACTED]"


def test_attach_firewall_is_idempotent_and_adds_hooks():
    fw, _ = make_firewall()
    agent = Agent()

    fw.attach_firewall(agent)
    fw.attach_firewall(agent)

    assert len(agent.pre_hooks) == 1
    assert len(agent.post_hooks) == 1
    assert len(agent.tool_hooks) == 1


def test_middleware_and_hook_bundle_helpers():
    fw, _ = make_firewall()
    agent = Agent()
    middleware = fw.create_middleware()

    assert fw.create_hook_bundle()["pre_hooks"] == [fw.pre_hook]
    assert middleware.name == "agenticdome_agno_firewall"
    assert middleware.attach(agent) is agent
    assert len(agent.pre_hooks) == 1


def test_secure_tool_uses_sanitized_args_and_preserves_structured_result():
    fw, client = make_firewall()
    client.guardrail_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"customer_id": "safe"}}}

    @fw.secure_tool(tool_name="crm.lookup", tool_platform="crm")
    def lookup(agent, customer_id):
        return {"customer_id": customer_id}

    result = lookup(Agent(), customer_id="unsafe", session_id="s1")

    assert result == {"customer_id": "safe"}


def test_secure_tool_schema_validation_blocks_bad_args():
    fw, _ = make_firewall()

    @fw.secure_tool(tool_name="crm.lookup", tool_schema={"required": ["customer_id"], "properties": {"customer_id": {"type": "string"}}})
    def lookup(agent, customer_id):
        return {"customer_id": customer_id}

    with pytest.raises(AgenticDomeAgnoDenied):
        lookup(Agent(), customer_id=123, session_id="s1")


def test_streaming_sanitization_blocks_on_chunk():
    fw, client = make_firewall()
    client.mesh_response = {"verdict": "BLOCKED", "reason": "secret"}

    async def chunks():
        yield "secret"
        yield "more"

    async def collect():
        out = []
        async for chunk in fw.sanitize_streaming_response(chunks(), agent_id="agent-a", session_id="s1"):
            out.append(chunk)
        return out

    assert asyncio.run(collect()) == ["[OUTPUT BLOCKED BY AgenticDome]"]


def test_rate_limit_blocks_excess_input_calls():
    fw, _ = make_firewall(rate_limit_per_minute=1)

    fw.pre_hook(Agent(), input="hello", session_id="s1")
    with pytest.raises(AgenticDomeAgnoDenied):
        fw.pre_hook(Agent(), input="again", session_id="s1")


def test_size_limit_blocks_large_tool_args():
    fw, _ = make_firewall(max_tool_arg_chars=10)

    with pytest.raises(AgenticDomeAgnoDenied):
        fw.pre_hook(Agent(), session_id="s1", tool_name="large", tool_args={"payload": "x" * 100})


def test_retry_allows_transient_guardrail_failure():
    fw, client = make_firewall(retry_attempts=2)
    client.guardrail_failures_remaining = 1

    fw.pre_hook(Agent(), input="hello", session_id="s1")

    assert len([call for call in client.calls if call[0] == "guardrail_validate"]) == 2
