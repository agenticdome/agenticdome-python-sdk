import ast
import hashlib
import json
import subprocess

import pytest

from agenticdome_sdk import guided_integration
from agenticdome_sdk import onboarding_cli


SOURCE = '''from smolagents import CodeAgent

def handle(task, session_id):
    agent = CodeAgent(model="example", tools=[])
    return agent.run(task)
'''


def _plan(*, certified=True, bound=True):
    return {
        "schema": "agenticdome.integration-plan.v1",
        "languages": ["python"],
        "frameworks": ["smolagents"],
        "business_purpose": "test",
        "coverage": {"gaps": []},
        "candidate_boundaries": [{"boundary": "tool_execution", "path": "app.py", "line": 5}],
        "framework_hook_plans": [{
            "framework": "smolagents",
            "status": "ready_for_attachment" if certified else "review_required",
            "adapter": {"attachment_methods": ["run_agent_securely"]},
        }],
        "hook_catalog": {"schema": "agenticdome.hook-catalog.v1", "digest": "test-catalog", "verified_at": "2026-09-28", "sidecar_binding": {"verified": bound}},
        "semantic_analysis": {},
        "semantic_gate": {},
    }


def _project(tmp_path):
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    (tmp_path / "other.py").write_text("VALUE = 1\n", encoding="utf-8")
    config = tmp_path / ".agenticdome" / "config.json"
    config.parent.mkdir()
    config.write_text(json.dumps({"frameworks": ["smolagents"], "business_purpose": "test"}), encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "app.py", "other.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "baseline"], cwd=tmp_path, check=True)


def test_preview_apply_status_and_undo_edit_existing_source_with_exact_record(tmp_path, monkeypatch, capsys):
    _project(tmp_path)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())

    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "preview"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["state"] == "preview"
    assert preview["existing_source_edits"] == 1
    assert preview["manual_review_items"] >= 1
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == SOURCE
    assert "-    return agent.run(task)" in (tmp_path / preview["patch"]).read_text(encoding="utf-8")
    stat = subprocess.run(["git", "apply", "--stat", str(tmp_path / preview["patch"])], cwd=tmp_path, text=True, capture_output=True)
    assert stat.returncode == 0
    assert "app.py" in stat.stdout
    dry_run = subprocess.run(["git", "apply", "--check", str(tmp_path / preview["patch"])], cwd=tmp_path, text=True, capture_output=True)
    assert dry_run.returncode == 0, dry_run.stderr
    detailed = guided_integration._load_manifest(tmp_path)
    assert any(item["path"] == "app.py" and item["kind"] == "modified" for item in detailed["changes"])
    assert any(item["path"] == "AGENTICDOME-CHANGES.md" for item in detailed["changes"])

    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "apply", "--approve", preview["approval_code"]]) == 0
    applied = json.loads(capsys.readouterr().out)
    assert applied["state"] == "applied"
    assert applied["branch"].startswith("agenticdome/integrate-")
    changed = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "AgenticDomeSmolagentsFirewall().run_agent_securely(agent, task, session_id=session_id)" in changed
    ast.parse(changed)
    assert (tmp_path / "AGENTICDOME-CHANGES.md").is_file()

    assert onboarding_cli.main(["--path", str(tmp_path), "inspect", "--output", str(tmp_path / "agenticdome-inspection.json")]) == 0
    capsys.readouterr()
    inspection = json.loads((tmp_path / "agenticdome-inspection.json").read_text(encoding="utf-8"))
    assert inspection["guided_integration"]["state"] == "applied"
    assert inspection["guided_integration"]["changes"][0]["after_sha256"]
    assert inspection["guided_integration"]["source_upload"] is False
    inspection_digest = inspection.pop("report_sha256")
    assert inspection_digest == hashlib.sha256(json.dumps(inspection, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "status"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "applied"
    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "undo"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "undone"
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == SOURCE
    assert not (tmp_path / "AGENTICDOME-CHANGES.md").exists()


def test_preview_marks_uncertified_adapter_as_manual_and_refuses_apply(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan(certified=False))
    preview = guided_integration.preview(tmp_path)
    assert preview["source_edits"] == 0
    assert preview["manual_review"]
    stat = subprocess.run(["git", "apply", "--stat", str(tmp_path / preview["patch"])], cwd=tmp_path, text=True, capture_output=True)
    assert stat.returncode == 0, stat.stderr
    with pytest.raises(RuntimeError, match="No supported existing-source edit"):
        guided_integration.apply(tmp_path, approval_code=preview["approval_code"])
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == SOURCE


def test_mcp_preview_applies_only_review_files_and_never_claims_forwarding_is_protected(tmp_path, monkeypatch, capsys):
    _project(tmp_path)
    plan = _plan()
    plan["mcp_protection"] = {
        "detected": True, "servers": [], "tools": [], "request_boundaries": [],
        "response_boundaries": [], "bypass_findings": [],
    }
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)

    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "preview", "--target", "mcp"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["integration_target"] == "mcp"
    assert preview["existing_source_edits"] == 0
    assert "real MCP forwarder manually" in preview["next_action"]
    assert not (tmp_path / "agenticdome_mcp_gateway.py").exists()
    assert "MCP-REVIEW.md" in (tmp_path / preview["patch"]).read_text(encoding="utf-8")

    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "apply", "--approve", preview["approval_code"]]) == 0
    applied = json.loads(capsys.readouterr().out)
    assert applied["state"] == "applied"
    assert applied["integration_target"] == "mcp"
    assert "No existing forwarder was rewired" in applied["next_action"]
    assert (tmp_path / "agenticdome_mcp_gateway.py").is_file()
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == SOURCE

    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "undo"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "undone"
    assert not (tmp_path / "agenticdome_mcp_gateway.py").exists()


def test_mcp_guided_preview_requires_detected_mcp_boundary(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())
    with pytest.raises(RuntimeError, match="No MCP boundary"):
        guided_integration.preview(tmp_path, target="mcp")


def test_apply_refuses_source_changed_after_preview(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())
    preview = guided_integration.preview(tmp_path)
    (tmp_path / "app.py").write_text(SOURCE + "\n# customer edit\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Existing source changed after preview"):
        guided_integration.apply(tmp_path, approval_code=preview["approval_code"])
    assert "# customer edit" in (tmp_path / "app.py").read_text(encoding="utf-8")


def test_undo_refuses_to_overwrite_later_customer_change(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())
    preview = guided_integration.preview(tmp_path)
    guided_integration.apply(tmp_path, approval_code=preview["approval_code"])
    (tmp_path / "app.py").write_text((tmp_path / "app.py").read_text(encoding="utf-8") + "\n# customer edit\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="changed since approval"):
        guided_integration.undo(tmp_path)
    assert "# customer edit" in (tmp_path / "app.py").read_text(encoding="utf-8")


def test_undo_preflights_every_file_before_restoring_anything(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())
    result = guided_integration.preview(tmp_path)
    guided_integration.apply(tmp_path, approval_code=result["approval_code"])
    changed_source = (tmp_path / "app.py").read_text(encoding="utf-8")
    summary = tmp_path / "AGENTICDOME-CHANGES.md"
    summary.write_text(summary.read_text(encoding="utf-8") + "\ncustomer note\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="changed since approval"):
        guided_integration.undo(tmp_path)
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == changed_source


def test_untrusted_candidate_path_and_non_exact_pattern_never_auto_edit(tmp_path, monkeypatch):
    _project(tmp_path)
    plan = _plan()
    plan["candidate_boundaries"] = [
        {"boundary": "tool_execution", "path": "../outside.py", "line": 1},
        {"boundary": "tool_execution", "path": "app.py", "line": 5},
    ]
    (tmp_path / "app.py").write_text(SOURCE.replace("def handle(task, session_id):", "def handle(task):"), encoding="utf-8")
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)
    preview = guided_integration.preview(tmp_path)
    assert preview["source_edits"] == 0
    assert len(preview["manual_review"]) >= 2
    assert "AgenticDomeSmolagentsFirewall" not in (tmp_path / "app.py").read_text(encoding="utf-8")


def test_apply_requires_clean_tracked_workload(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())
    preview = guided_integration.preview(tmp_path)
    (tmp_path / "other.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Tracked workload source changes exist"):
        guided_integration.apply(tmp_path, approval_code=preview["approval_code"])


def test_generated_artifacts_already_tracked_do_not_block_source_approval(tmp_path, monkeypatch):
    _project(tmp_path)
    scaffold = tmp_path / ".agenticdome" / "scaffold"
    scaffold.mkdir()
    (scaffold / "SEMANTIC-REVIEW.md").write_text("older review\n", encoding="utf-8")
    subprocess.run(["git", "add", ".agenticdome/config.json", ".agenticdome/scaffold/SEMANTIC-REVIEW.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "track local configuration"], cwd=tmp_path, check=True)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())

    result = guided_integration.preview(tmp_path)
    applied = guided_integration.apply(tmp_path, approval_code=result["approval_code"])
    assert applied["state"] == "applied"


def test_local_exact_pattern_is_found_when_generic_boundary_heuristic_misses_it(tmp_path, monkeypatch):
    _project(tmp_path)
    plan = _plan()
    plan["candidate_boundaries"] = []
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)

    result = guided_integration.preview(tmp_path)
    assert result["source_edits"] == 1
    assert any(item["path"] == "app.py" for item in result["changes"])
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == SOURCE


def test_apply_refuses_mode_change_after_preview(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())
    result = guided_integration.preview(tmp_path)
    (tmp_path / "app.py").chmod(0o600)

    with pytest.raises(RuntimeError, match="Existing source changed after preview"):
        guided_integration.apply(tmp_path, approval_code=result["approval_code"])


def test_preview_rejects_symlinked_internal_output_directory(tmp_path, monkeypatch):
    _project(tmp_path)
    (tmp_path / ".agenticdome" / "scaffold").symlink_to(tmp_path / "other-output", target_is_directory=True)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())

    with pytest.raises(ValueError, match="outside the selected workload|symlink"):
        guided_integration.preview(tmp_path)


def test_repeat_preview_preserves_prior_applied_revision_and_safe_undo(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: _plan())
    first = guided_integration.preview(tmp_path)
    guided_integration.apply(tmp_path, approval_code=first["approval_code"])

    second = guided_integration.preview(tmp_path)
    assert second["state"] == "preview"
    assert second["prior_applied_revision"] == first["approval_code"]
    assert second["source_edits"] == 0
    current_summary = (tmp_path / ".agenticdome/scaffold/proposed/AGENTICDOME-CHANGES.md").read_text(encoding="utf-8")
    assert "An existing change record uses this name" in current_summary
    assert guided_integration._load_manifest(tmp_path, revision=first["approval_code"])["state"] == "applied"

    undone = guided_integration.undo(tmp_path, revision=first["approval_code"])
    assert undone["state"] == "undone"
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == SOURCE
    assert guided_integration._load_manifest(tmp_path)["state"] == "preview"
