import json
import os
import sys
from pathlib import Path

import pytest

from agenticdome_sdk.action_path_proof import ExecutionSpy, load_action_path_proof, run_action_path_test


SDK_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("verdict,calls", [("BLOCKED", 0), ("ALLOWED", 1)])
def test_real_path_report_requires_hook_verdict_and_handler_spy(tmp_path, monkeypatch, verdict, calls):
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example.test")
    monkeypatch.setenv("AGENTICDOME_API_KEY", "test-only-key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "2")
    monkeypatch.setenv("PYTHONPATH", str(SDK_ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    code = f'''
from agenticdome_sdk.client import AgenticDomeClient
from agenticdome_sdk.action_path_proof import ExecutionSpy
client = AgenticDomeClient(api_base="https://sidecar.example.test", api_key="test-only-key", tenant_id="2", mode="live")
client._request = lambda *args, **kwargs: {{"verdict": "{verdict}"}}
scope = {{"__name__": "agenticdome_sdk.google_adk", "client": client}}
exec("def invoke():\\n    return client.guardrail_validate(text='safe fixture', agent_id='fixture', platform='google_adk', tool_name='billing.refund', tool_args={{'id': 'fixture'}})", scope)
spy = ExecutionSpy("billing.refund")
handler = spy.wrap(lambda: None)
decision = scope["invoke"]()
if decision["verdict"] != "BLOCKED":
    handler()
spy.assert_calls({calls})
'''
    exit_code, report = run_action_path_test(
        tmp_path, tool_name="billing.refund", expected_verdict=verdict,
        expected_calls=calls, command=[sys.executable, "-c", code],
    )
    assert report["reasons"] == []
    assert exit_code == 0
    assert report["status"] == "passed"
    assert report["observed_verdict"] == verdict
    assert report["hook_module"] == "agenticdome_sdk.google_adk"
    assert report["observed_handler_calls"] == calls
    assert report["handler_assertion_passed"] is True
    assert "test-only-key" not in json.dumps(report)
    proof_dir = tmp_path / ".agenticdome"
    proof_dir.mkdir()
    proof_file = proof_dir / "action-proof.json"
    proof_file.write_text(json.dumps(report), encoding="utf-8")
    loaded = load_action_path_proof(tmp_path)
    assert loaded is not None
    assert loaded["evidence_origin"] == "customer_test"
    assert "reasons" not in loaded
    proof_file.write_text(json.dumps({**report, "observed_verdict": "REDACTED"}), encoding="utf-8")
    assert load_action_path_proof(tmp_path) is None


def test_direct_sdk_decision_is_not_misrepresented_as_framework_hook(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example.test")
    monkeypatch.setenv("AGENTICDOME_API_KEY", "test-only-key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "2")
    monkeypatch.setenv("PYTHONPATH", str(SDK_ROOT))
    code = '''
from agenticdome_sdk.client import AgenticDomeClient
from agenticdome_sdk.action_path_proof import ExecutionSpy
client = AgenticDomeClient(api_base="https://sidecar.example.test", api_key="test-only-key", tenant_id="2", mode="live")
client._request = lambda *args, **kwargs: {"verdict": "BLOCKED"}
client.guardrail_validate(text="fixture", agent_id="fixture", platform="custom", tool_name="billing.refund", tool_args={"id":"fixture"})
ExecutionSpy("billing.refund").assert_calls(0)
'''
    exit_code, report = run_action_path_test(
        tmp_path, tool_name="billing.refund", expected_verdict="BLOCKED",
        expected_calls=0, command=[sys.executable, "-c", code],
    )
    assert exit_code == 2
    assert report["status"] == "incomplete"
    assert any("framework hook" in reason for reason in report["reasons"])


@pytest.mark.parametrize("verdict,calls", [("BLOCKED", 0), ("ALLOWED", 1)])
def test_explicit_custom_python_executor_is_recognized_as_hook(tmp_path, monkeypatch, verdict, calls):
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example.test")
    monkeypatch.setenv("AGENTICDOME_API_KEY", "test-only-key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "2")
    monkeypatch.setenv("PYTHONPATH", str(SDK_ROOT))
    code = f'''
from agenticdome_sdk.client import AgenticDomeClient
from agenticdome_sdk.generic_python import AgenticDomeActionDenied, guarded_tool_executor
from agenticdome_sdk.action_path_proof import ExecutionSpy
client = AgenticDomeClient(api_base="https://sidecar.example.test", api_key="test-only-key", tenant_id="2", mode="live")
client._request = lambda *args, **kwargs: {{"verdict": "{verdict}"}}
spy = ExecutionSpy("billing.refund")
def raw(tool_name, tool_args, agent_id, session_id):
    return "done"
handler = guarded_tool_executor(spy.wrap(raw), client=client)
try:
    handler("billing.refund", {{"id": "fixture"}}, "agent-1", "session-1")
except AgenticDomeActionDenied:
    pass
spy.assert_calls({calls})
'''
    exit_code, report = run_action_path_test(
        tmp_path, tool_name="billing.refund", expected_verdict=verdict,
        expected_calls=calls, command=[sys.executable, "-c", code],
    )
    assert exit_code == 0
    assert report["status"] == "passed"
    assert report["hook_module"] == "agenticdome_sdk.generic_python"
    assert report["observed_handler_calls"] == calls


def test_no_handler_assertion_cannot_prove_blocked_action(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example.test")
    monkeypatch.setenv("AGENTICDOME_API_KEY", "test-only-key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "2")
    monkeypatch.setenv("PYTHONPATH", str(SDK_ROOT))
    code = '''
from agenticdome_sdk.client import AgenticDomeClient
client = AgenticDomeClient(api_base="https://sidecar.example.test", api_key="test-only-key", tenant_id="2", mode="live")
client._request = lambda *args, **kwargs: {"verdict": "BLOCKED"}
scope = {"__name__": "agenticdome_sdk.google_adk", "client": client}
exec("def invoke():\\n    return client.guardrail_validate(text='fixture', agent_id='fixture', platform='google_adk', tool_name='billing.refund', tool_args={'id':'fixture'})", scope)
scope["invoke"]()
'''
    exit_code, report = run_action_path_test(
        tmp_path, tool_name="billing.refund", expected_verdict="BLOCKED",
        expected_calls=0, command=[sys.executable, "-c", code],
    )
    assert exit_code == 2
    assert any("spy" in reason for reason in report["reasons"])


def test_missing_credentials_is_explicit(tmp_path, monkeypatch):
    for name in ("AGENTICDOME_API_BASE", "AGENTICDOME_API_KEY", "AGENTICDOME_TENANT_ID"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="Live action-path proof requires"):
        run_action_path_test(tmp_path, tool_name="x", expected_verdict="BLOCKED",
                             expected_calls=0, command=[sys.executable, "-c", "pass"])
