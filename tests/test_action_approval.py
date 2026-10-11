import copy
import uuid

import pytest

from agenticdome_sdk import AgenticDomeClient, AgenticDomeError, ApprovalRequired


def client():
    return AgenticDomeClient("https://sidecar.example", api_key="fixture", tenant_id="2", execution_broker_mode="enforce", max_retries=0)


def test_pending_action_does_not_execute_and_freezes_exact_arguments(monkeypatch):
    sdk = client(); request_id = str(uuid.uuid4()); calls = []; body = {"messages": [{"content": "private prepared evidence"}]}
    def request(method, path, **kwargs):
        calls.append((method, path, copy.deepcopy(kwargs)))
        return {"verdict": "APPROVAL_REQUIRED", "context": {"approval": {"id": request_id}, "approval_url": "/agentguard/approvals/" + request_id}}
    monkeypatch.setattr(sdk, "_request", request)
    with pytest.raises(ApprovalRequired) as stopped:
        sdk.guardrail_validate(text="Send evidence", agent_id="worker", platform="python", session_id="run", tool_name="model.chat", tool_args=body)
    pending = stopped.value; assert pending.request_id == request_id
    body["messages"][0]["content"] = "changed after pause"
    executed = []
    def resume_request(method, path, **kwargs):
        if method == "GET": return {"approval_grant": "opaque-signed-grant"}
        assert kwargs["json_body"]["tool_args"]["messages"][0]["content"] == "private prepared evidence"
        return {"verdict": "ALLOWED", "broker": {"verified": True, "token_consumed": True, "approval_request_id": request_id}, "execution_receipt": "one-use-receipt"}
    monkeypatch.setattr(sdk, "_request", resume_request)
    exported = pending.export_prepared_action()
    restored = ApprovalRequired.restore_prepared_action(exported)
    exported['prepared_request']['tool_args']['messages'][0]['content'] = 'changed exported copy'
    result = restored.resume(sdk, lambda args: executed.append(args) or "completed")
    assert result == "completed" and len(executed) == 1
    assert executed[0]["messages"][0]["content"] == "private prepared evidence"
    assert "private prepared evidence" not in str(pending)


@pytest.mark.parametrize("response", [{"verdict": "BLOCKED"}, {"verdict": "APPROVAL_REQUIRED"}, {"verdict": "ALLOWED", "broker": {"verified": True, "token_consumed": True}}, {"verdict": "REDACTED"}])
def test_resume_cannot_execute_without_matching_consumed_approval_receipt(monkeypatch, response):
    sdk = client(); rid = str(uuid.uuid4()); pending = ApprovalRequired({"context": {"approval": {"id": rid}}}, {"tenant_id": "2", "tool_args": {"exact": "action"}})
    monkeypatch.setattr(sdk, "_request", lambda method, path, **kwargs: {"approval_grant": "signed"} if method == "GET" else response)
    executed = []
    with pytest.raises(AgenticDomeError): pending.resume(sdk, lambda args: executed.append(args))
    assert executed == []
