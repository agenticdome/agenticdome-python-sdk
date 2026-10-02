import asyncio

import pytest

from agenticdome_sdk.generic_python import AgenticDomeActionDenied, guarded_tool_executor
from agenticdome_sdk import generic_python


class FakeClient:
    def __init__(self, response=None, error=None):
        self.response = response if response is not None else {"result": {"verdict": "ALLOWED"}}
        self.error = error
        self.calls = []

    def guardrail_validate(self, **payload):
        self.calls.append(payload)
        if self.error:
            raise self.error
        return self.response


def test_sync_executor_authorizes_before_handler_and_passes_trusted_context():
    client = FakeClient()
    observed = []

    @guarded_tool_executor(client=client)
    def execute_tool(tool_name, tool_args, agent_id, session_id, purpose=None, user_id=None, actual_role=None, policy_context=None):
        observed.append(dict(tool_args))
        return tool_args["record"]

    assert execute_tool("crm.read", {"record": "123"}, "agent-1", "session-1", "support", "user-1", "support", {"case_id": "case-1"}) == "123"
    assert observed == [{"record": "123"}]
    assert client.calls[0]["tool_args"] == {"record": "123"}
    assert client.calls[0]["request_purpose"] == "support"
    assert client.calls[0]["user_id"] == "user-1"
    assert client.calls[0]["actual_role"] == "support"
    assert client.calls[0]["policy_context"] == {"case_id": "case-1"}
    assert client.calls[0]["direction"] == "outbound"


def test_blocked_unknown_and_transport_failure_never_execute():
    for client in (FakeClient({"result": {"verdict": "BLOCKED"}}), FakeClient({"status": "ok"}), FakeClient(error=RuntimeError("sidecar unavailable"))):
        invoked = []

        @guarded_tool_executor(client=client)
        def dispatch_tool(tool_name, tool_args, agent_id, session_id):
            invoked.append(True)

        with pytest.raises((AgenticDomeActionDenied, RuntimeError)):
            dispatch_tool("db.delete", {"id": 1}, "agent-1", "session-1")
        assert invoked == []


def test_sanitized_arguments_replace_arguments_before_execution():
    client = FakeClient({"result": {"verdict": "REDACTED", "sanitized_tool_args": {"record": "safe"}}})

    @guarded_tool_executor(client=client)
    def run_tool(tool_name, tool_args, agent_id, session_id):
        return tool_args["record"]

    original = {"record": "unsafe"}
    assert run_tool(tool_name="crm.read", tool_args=original, agent_id="agent-1", session_id="session-1") == "safe"
    assert original == {"record": "unsafe"}


def test_policy_and_executor_use_the_same_normalized_action_snapshot():
    original = {"nested": {"record": "before"}}

    class MutatingClient(FakeClient):
        def guardrail_validate(self, **payload):
            original["nested"]["record"] = "after"
            return super().guardrail_validate(**payload)

    client = MutatingClient()

    @guarded_tool_executor(client=client)
    def execute_tool(tool_name, tool_args, agent_id, session_id):
        return tool_name, tool_args["nested"]["record"], agent_id, session_id

    result = execute_tool(" crm.read ", original, " agent-1 ", " session-1 ")
    assert result == ("crm.read", "before", "agent-1", "session-1")
    assert client.calls[0]["tool_args"]["nested"]["record"] == "before"


def test_redacted_without_sanitized_arguments_fails_closed():
    client = FakeClient({"verdict": "REDACTED"})

    @guarded_tool_executor(client=client)
    def execute_tool(tool_name, tool_args, agent_id, session_id):
        pytest.fail("blocked handler must not run")

    with pytest.raises(AgenticDomeActionDenied):
        execute_tool("mail.send", {}, "agent-1", "session-1")


def test_missing_identity_or_bad_arguments_fail_before_runtime_call():
    client = FakeClient()

    @guarded_tool_executor(client=client)
    def execute_tool(tool_name, tool_args, agent_id, session_id):
        pytest.fail("invalid handler must not run")

    with pytest.raises(AgenticDomeActionDenied):
        execute_tool("mail.send", {}, "", "session-1")
    with pytest.raises(AgenticDomeActionDenied):
        execute_tool("mail.send", "bad", "agent-1", "session-1")
    assert client.calls == []


def test_async_executor_preserves_async_contract_and_sanitized_arguments():
    client = FakeClient({"verdict": "ALLOWED", "sanitized_args": {"record": "safe"}})
    invoked = []

    @guarded_tool_executor(client=client)
    async def invoke_tool(tool_name, tool_args, agent_id, session_id):
        invoked.append(tool_args)
        return tool_args["record"]

    assert asyncio.run(invoke_tool("crm.read", {"record": "unsafe"}, "agent-1", "session-1")) == "safe"
    assert invoked == [{"record": "safe"}]


def test_instance_method_dispatcher_keeps_self_binding():
    client = FakeClient()

    class Tools:
        @guarded_tool_executor(client=client)
        def dispatch_tool(self, tool_name, tool_args, agent_id, session_id):
            return (self, tool_args["record"])

    tools = Tools()
    assert tools.dispatch_tool("crm.read", {"record": "123"}, "agent-1", "session-1") == (tools, "123")
    assert client.calls[0]["tool_name"] == "crm.read"


def test_decorator_rejects_signature_without_explicit_identity():
    with pytest.raises(TypeError):
        guarded_tool_executor(lambda tool_name, tool_args: None)


def test_real_tool_executor_refuses_offline_simulation():
    client = FakeClient()
    client.is_simulation = True

    @guarded_tool_executor(client=client)
    def execute_tool(tool_name, tool_args, agent_id, session_id):
        pytest.fail("offline simulation must not execute a real action")

    with pytest.raises(AgenticDomeActionDenied, match="live assigned runtime"):
        execute_tool("mail.send", {}, "agent-1", "session-1")
    assert client.calls == []


def test_worker_reuses_client_until_connection_rotates(monkeypatch):
    created = []

    def factory():
        runtime = FakeClient()
        created.append(runtime)
        return runtime

    monkeypatch.setattr(generic_python, "AgenticDomeClient", factory)
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example.test")
    monkeypatch.setenv("AGENTICDOME_API_KEY", "first-test-key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "2")

    @guarded_tool_executor
    def execute_tool(tool_name, tool_args, agent_id, session_id):
        return tool_args["id"]

    assert execute_tool("crm.read", {"id": 1}, "agent", "session") == 1
    assert execute_tool("crm.read", {"id": 2}, "agent", "session") == 2
    assert len(created) == 1
    monkeypatch.setenv("AGENTICDOME_API_KEY", "second-test-key")
    assert execute_tool("crm.read", {"id": 3}, "agent", "session") == 3
    assert len(created) == 2
