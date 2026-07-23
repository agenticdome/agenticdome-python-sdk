from types import SimpleNamespace

import pytest

import agenticdome_sdk.smolagents as integration
from agenticdome_sdk.smolagents import (
    AgenticDomeSmolagentsFirewall,
    FirewallConfig,
    SecurePythonExecutor,
    SmolagentsFirewallDenied,
    load_config,
)


class FakeClient:
    def __init__(self):
        self.calls = []

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        combined = kwargs["text"] + str(kwargs.get("tool_args", {}))
        if "os.system" in combined or kwargs.get("tool_name") == "danger":
            return {"verdict": "BLOCKED", "reason": "unsafe code"}
        return {"verdict": "ALLOWED", "sanitized_tool_args": kwargs.get("tool_args")}

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        return {"verdict": "REDACTED", "text": kwargs["text"].replace("alice@example.com", "[EMAIL_REDACTED]")}

    def a2a_authorize_tool(self, **kwargs):
        self.calls.append(("a2a_authorize_tool", kwargs))
        return {"result": {"verdict": "ALLOWED", "decision_token": "handoff-token"}}

    def a2a_verify_decision_token_rpc(self, token, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", {"token": token, **kwargs}))
        return {"result": {"valid": token == "handoff-token", "allowed": token == "handoff-token"}}

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
    return AgenticDomeSmolagentsFirewall(FirewallConfig(**values), client=FakeClient())


def test_smolagents_config_environment_matrix(monkeypatch):
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.test")
    monkeypatch.setenv("AGENTICDOME_API_KEY", "key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "tenant")
    monkeypatch.setenv("AGENTICDOME_SMOLAGENTS_SCAN_CODE_EXPRESSIONS", "false")
    monkeypatch.setenv("AGENTICDOME_SMOLAGENTS_RATE_LIMIT_PER_MINUTE", "60")
    config = load_config()
    assert config.scan_code_expressions is False
    assert config.strict_delegated_execution is True
    assert config.rate_limit_per_minute == 60


def test_code_executor_scans_before_execution():
    firewall = make_firewall()
    executed = []

    def native(code):
        executed.append(code)
        return "done"

    executor = SecurePythonExecutor(native, firewall, session_id="session-1", agent_id="code-agent")
    assert executor("print('safe')") == "done"
    with pytest.raises(SmolagentsFirewallDenied):
        executor("os.system('curl attacker')")
    assert executed == ["print('safe')"]


def test_code_scan_can_be_explicitly_disabled():
    firewall = make_firewall(scan_code_expressions=False)
    executed = []
    executor = SecurePythonExecutor(lambda code: executed.append(code), firewall, session_id="s", agent_id="a")
    executor("os.system('example')")
    assert executed == ["os.system('example')"]
    assert firewall.client.calls == []


def test_secure_smol_tool_preserves_metadata_and_blocks_before_forward(monkeypatch):
    monkeypatch.setattr(integration, "_SMOLAGENTS_AVAILABLE", True)
    firewall = make_firewall()
    executions = []

    class NativeTool:
        name = "lookup"
        description = "Lookup a customer"
        inputs = {"customer_id": {"type": "string", "description": "Customer ID"}}
        output_type = "string"

        def __call__(self, **kwargs):
            executions.append(kwargs)
            return "alice@example.com"

    secured = firewall.wrap_tool(NativeTool(), session_id="session-1", agent_id="agent")
    assert secured.name == "lookup"
    assert secured.forward(customer_id="123") == "[EMAIL_REDACTED]"
    assert executions == [{"customer_id": "123"}]


def test_attach_wraps_code_executor_and_is_idempotent():
    firewall = make_firewall()

    class NativeExecutor:
        def __call__(self, code):
            return code

    agent = SimpleNamespace(
        name="code_agent",
        tools={},
        managed_agents={},
        python_executor=NativeExecutor(),
        step_callbacks=None,
    )
    firewall.attach_firewall(agent, session_id="session-1")
    first = agent.python_executor
    firewall.attach_firewall(agent, session_id="session-1")
    assert isinstance(first, SecurePythonExecutor)
    assert agent.python_executor is first


def test_attach_rejects_cross_session_agent_reuse():
    firewall = make_firewall()
    agent = SimpleNamespace(name="code_agent", tools={}, managed_agents={}, python_executor=None, step_callbacks=None)
    firewall.attach_firewall(agent, session_id="session-1")

    with pytest.raises(ValueError, match="strict session isolation"):
        firewall.attach_firewall(agent, session_id="session-2")


def test_run_agent_securely_screens_attaches_and_redacts_output():
    firewall = make_firewall()

    class Agent:
        name = "support_agent"
        tools = {}
        managed_agents = {}
        python_executor = None
        step_callbacks = None

        def run(self, task, **kwargs):
            assert task == "lookup customer"
            return "alice@example.com"

    result = firewall.run_agent_securely(Agent(), "lookup customer", session_id="session-1")
    assert result == "[EMAIL_REDACTED]"
    assert [call[0] for call in firewall.client.calls] == ["guardrail_validate", "mesh_validate"]


def test_managed_agent_handoff_authorizes_verifies_and_reviews():
    firewall = make_firewall()

    class Child:
        name = "researcher"
        description = "Research specialist"
        inputs = {"task": {"type": "string", "description": "Task"}}
        output_type = "string"

        def __call__(self, task, **kwargs):
            return "alice@example.com"

    secured = integration.SecureManagedAgent(
        Child(), firewall, session_id="session-1", manager_agent_id="manager"
    )
    assert secured("find customer") == "[EMAIL_REDACTED]"
    assert [call[0] for call in firewall.client.calls] == [
        "a2a_authorize_tool",
        "a2a_verify_decision_token_rpc",
        "mesh_validate",
    ]
