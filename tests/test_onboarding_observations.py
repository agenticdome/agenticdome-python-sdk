import pytest

from agenticdome_sdk import onboarding_cli
from agenticdome_sdk.onboarding_observations import POLICY, disclaimer_markdown, observations_summary


def gate(**changes):
    value = dict(action_required=2, unresolved_bypasses=2, high_severity_bypasses=0,
                 review_required=43, confidence="high", assessment_complete=True)
    value.update(changes)
    return value


def test_optional_counts_preserve_two_candidates_and_forty_three_reviews():
    summary = observations_summary(gate())
    assert summary["total_count"] == 45
    assert summary["classification_complete"] is True
    assert summary["candidate_count"] == 2
    assert summary["review_count"] == 43


@pytest.mark.parametrize("bad", [None, True, "0", -1, 3, 10001])
def test_missing_or_inconsistent_severity_cannot_become_optional(bad):
    value = gate()
    if bad is None:
        value.pop("high_severity_bypasses")
    else:
        value["high_severity_bypasses"] = bad
    assert observations_summary(value)["classification_complete"] is False


def test_real_verifier_keeps_missing_severity_blocking(tmp_path, monkeypatch):
    value = gate()
    value.pop("high_severity_bypasses")
    monkeypatch.setattr(onboarding_cli, "_run_existing_tests", lambda root: {"passed": True})
    code, report = onboarding_cli.verify_project(tmp_path, run_tests=True, plan={
        "coverage": {"gaps": []}, "semantic_gate": value,
    })
    assert code == 2 and report["ready"] is False
    assert report["onboarding_observations"]["classification_complete"] is False


def test_cross_part_note_is_optional_and_does_not_claim_flow_proven(tmp_path, monkeypatch):
    value = gate()
    value["cross_workload_review_required"] = True
    monkeypatch.setattr(onboarding_cli, "_run_existing_tests", lambda root: {"passed": True})
    code, report = onboarding_cli.verify_project(tmp_path, run_tests=True, plan={
        "coverage": {"gaps": []}, "semantic_gate": value,
    })
    assert code == 0 and report["ready"] is True
    assert report["onboarding_policy"] == POLICY
    assert report["semantic_gate"]["cross_part_review_required"] is True
    assert report["onboarding_observations"]["total_count"] == 46


def test_unknown_severity_stays_in_blocking_worklist_and_out_of_optional_file(tmp_path, monkeypatch):
    plan = {"coverage": {"gaps": []}, "semantic_gate": gate(assessment_complete=False),
            "semantic_analysis": {"bypass_risks": [
                {"path": "handler.py", "line": 9, "severity": "critical", "boundary": "tool_execution"},
            ]}}
    monkeypatch.setattr(onboarding_cli, "_run_existing_tests", lambda root: {"passed": True})
    code, verification = onboarding_cli.verify_project(tmp_path, run_tests=True, plan=plan)
    assert code == 2 and verification["ready"] is False
    assert verification["onboarding_observations"]["classification_complete"] is False
    worklist = onboarding_cli._reconciliation_markdown(plan, verification, "fixture")
    assert "handler.py" in worklist and "Lines: 9" in worklist
    assert "Blocking findings: 2" in worklist
    assert "unclassified candidates are not optional" in worklist
    optional = (tmp_path / ".agenticdome/DISCLAIMER.md").read_text()
    assert "handler.py" not in optional
    assert "Severity classification is incomplete" in optional


@pytest.mark.parametrize("target_symlink", [True, False])
def test_disclaimer_writer_rejects_target_and_parent_symlinks(tmp_path, target_symlink):
    root = tmp_path / "service"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    if target_symlink:
        (root / ".agenticdome").mkdir()
        target = outside / "untouched.md"
        target.write_text("original")
        (root / ".agenticdome/DISCLAIMER.md").symlink_to(target)
    else:
        (root / ".agenticdome").symlink_to(outside, target_is_directory=True)
    with pytest.raises(SystemExit, match="symlink"):
        onboarding_cli._write_onboarding_disclaimer(root, {}, {"semantic_gate": gate()})
    assert not (outside / "DISCLAIMER.md").exists()
    if target_symlink:
        assert target.read_text() == "original"


def test_disclaimer_replacement_is_idempotent_and_excludes_remote_text(tmp_path):
    semantic = {"bypass_risks": [{"path": "../outside.md", "line": 9, "severity": "medium", "reason": "DO_NOT_COPY_REMOTE_TEXT"}]}
    verification = {"semantic_gate": gate()}
    onboarding_cli._write_onboarding_disclaimer(tmp_path, {"semantic_analysis": semantic}, verification)
    onboarding_cli._write_onboarding_disclaimer(tmp_path, {"semantic_analysis": semantic}, verification)
    output = (tmp_path / ".agenticdome/DISCLAIMER.md").read_text()
    assert output.count("# AgenticDome onboarding observations and disclaimer") == 1
    assert "[invalid relative path]" in output
    assert "DO_NOT_COPY_REMOTE_TEXT" not in output
    assert "no acknowledgement" in output
