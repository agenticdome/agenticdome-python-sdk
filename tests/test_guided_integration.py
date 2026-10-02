import ast
import hashlib
import json
import subprocess

import pytest

from agenticdome_sdk import guided_integration
from agenticdome_sdk import onboarding_cli
from agenticdome_sdk.existing_integration import detect_existing_integration
from agenticdome_sdk.existing_integration import CATALOG_METHODS, README_METHODS
from agenticdome_sdk.hook_catalog import FRAMEWORK_HOOK_CATALOG, harness_compatibility_manifest


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
        "surface_hook_recommendations": [{
            "framework": "smolagents", "surface": "tool_execution", "method": "attach_firewall",
            "state": "not_observed_in_selected_source", "surface_observed": True,
            "guidance": "Protect the actual executor.",
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
    plan = _plan()
    plan["framework_reconciliation"] = {
        "configured": ["smolagents"], "detected_now": ["smolagents", "mcp"],
        "included_from_current_scan": ["mcp"], "configured_without_current_evidence": [],
        "planned": ["smolagents", "mcp"], "config_changed": False,
    }
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)

    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "preview"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["state"] == "preview"
    assert preview["existing_source_edits"] == 1
    assert preview["recommended_path"]["kind"] == "review_source_edit"
    assert preview["recommended_path"]["may_apply"] is True
    assert preview["manual_review_items"] >= 1
    exported = guided_integration.export_summary(tmp_path)
    assert exported["surface_hook_recommendations"][0]["method"] == "attach_firewall"
    assert exported["surface_hook_recommendations"][0]["surface_observed"] is True
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
    assert applied["recommended_path"]["kind"] == "verify_applied_change"
    assert applied["branch"].startswith("agenticdome/integrate-")
    changed = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "AgenticDomeSmolagentsFirewall().run_agent_securely(agent, task, session_id=session_id)" in changed
    ast.parse(changed)
    assert (tmp_path / "AGENTICDOME-CHANGES.md").is_file()

    assert onboarding_cli.main(["--path", str(tmp_path), "inspect", "--output", str(tmp_path / "agenticdome-inspection.json")]) == 0
    capsys.readouterr()
    inspection = json.loads((tmp_path / "agenticdome-inspection.json").read_text(encoding="utf-8"))
    assert inspection["guided_integration"]["state"] == "applied"
    assert inspection["guided_integration"]["recommended_path"]["kind"] == "verify_applied_change"
    assert inspection["guided_integration"]["framework_reconciliation"]["included_from_current_scan"] == ["mcp"]
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


@pytest.mark.parametrize("framework,method,source,expected", [
    ("crewai", "attach", "from crewai import Crew\ncrew = Crew(agents=[])\n", "import agenticdome_sdk.crewai"),
    ("pydanticai", "install_native_hooks", "from pydantic_ai import Agent\nagent = Agent('x')\n", "CyberSecFirewall().create_hooks()"),
    ("langgraph", "as_langchain_middleware", "from langchain.agents import create_agent\nagent = create_agent('x', tools=[])\n", "AgenticDomeLangGraphFirewall().as_langchain_middleware()"),
    ("google-adk", "build_callback_kwargs", "from google.adk.agents import Agent\nagent = Agent(name='x')\n", "AgenticDomeGoogleADKFirewall().build_callback_kwargs()"),
    ("claude", "install_on_options", "from claude_agent_sdk import ClaudeAgentOptions\noptions = ClaudeAgentOptions()\n", "AgenticDomeClaudeFirewall().install_on_options"),
    ("agno", "attach_firewall", "from agno.agent import Agent\nagent = Agent(name='x')\n", "AgenticDomeAgnoFirewall().attach_firewall(agent)"),
    ("llamaindex", "to_function_tool", "from llama_index.core.tools import FunctionTool\ntool = FunctionTool.from_defaults(fn=lookup, name='lookup')\n", "AgenticDomeLlamaIndexFirewall().wrap_tool_function(lookup"),
    ("openai-agents", "wrap_tool_handler", "from agents import FunctionTool\ntool = FunctionTool(name='lookup', description='x', params_json_schema={}, on_invoke_tool=lookup)\n", "AgenticDomeOpenAIAgentsFirewall().wrap_tool_handler(tool_name='lookup', handler=lookup, handler_args_format='json')"),
    ("custom-python", "guardrail_validate", "def dispatch_tool(tool_name, tool_args, agent_id, session_id):\n    return registry[tool_name](**tool_args)\n", "+@guarded_tool_executor"),
])
def test_preview_proposes_reviewable_source_edit_for_certified_framework(tmp_path, monkeypatch, framework, method, source, expected):
    _project(tmp_path)
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    plan = _plan()
    plan["frameworks"] = [framework]
    plan["detected_frameworks"] = [framework]
    plan["candidate_boundaries"] = []
    plan["framework_hook_plans"] = [{
        "framework": framework, "status": "ready_for_attachment",
        "adapter": {"attachment_methods": [method]},
        "detection_evidence_files": ["app.py"],
    }]
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)

    preview = guided_integration.preview(tmp_path)
    assert preview["source_edits"] == 1
    assert preview["recommended_path"]["kind"] == "review_source_edit"
    assert expected in (tmp_path / preview["patch"]).read_text(encoding="utf-8")
    summary = (tmp_path / "AGENTICDOME-CHANGES.md") if (tmp_path / "AGENTICDOME-CHANGES.md").exists() else (tmp_path / ".agenticdome/scaffold/proposed/AGENTICDOME-CHANGES.md")
    assert "agenticdome verify-action --tool YOUR_TOOL" in summary.read_text(encoding="utf-8")
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == source


def test_agno_certified_edit_apply_and_undo_round_trip(tmp_path, monkeypatch):
    _project(tmp_path)
    original = "from agno.agent import Agent\nagent = Agent(name='support')\n"
    (tmp_path / "app.py").write_text(original, encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "Agno workload"], cwd=tmp_path, check=True)
    plan = _plan()
    plan["frameworks"] = ["agno"]
    plan["candidate_boundaries"] = []
    plan["framework_hook_plans"] = [{
        "framework": "agno", "status": "ready_for_attachment",
        "adapter": {"attachment_methods": ["attach_firewall"]},
        "detection_evidence_files": ["app.py"],
    }]
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)
    proposed = guided_integration.preview(tmp_path)
    assert proposed["source_edits"] == 1
    applied = guided_integration.apply(tmp_path, approval_code=proposed["approval_code"])
    assert applied["state"] == "applied"
    assert "AgenticDomeAgnoFirewall().attach_firewall(agent)" in (tmp_path / "app.py").read_text(encoding="utf-8")
    undone = guided_integration.undo(tmp_path)
    assert undone["state"] == "undone"
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == original


def test_custom_python_exact_executor_apply_is_detected_and_undoable(tmp_path, monkeypatch):
    _project(tmp_path)
    original = "def execute_tool(tool_name, tool_args, agent_id, session_id):\n    return registry[tool_name](**tool_args)\n"
    (tmp_path / "app.py").write_text(original, encoding="utf-8")
    subprocess.run(["git", "add", "app.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "Plain Python tool executor"], cwd=tmp_path, check=True)
    plan = _plan()
    plan["frameworks"] = ["custom-python"]
    plan["candidate_boundaries"] = [{"boundary": "tool_execution", "path": "app.py", "line": 1}]
    plan["framework_hook_plans"] = [{
        "framework": "custom-python", "status": "ready_for_attachment",
        "adapter": {"attachment_methods": ["guardrail_validate"]},
        "detection_evidence_files": ["app.py"],
    }]
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)
    proposed = guided_integration.preview(tmp_path)
    assert proposed["source_edits"] == 1
    applied = guided_integration.apply(tmp_path, approval_code=proposed["approval_code"])
    assert applied["state"] == "applied"
    contents = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "@guarded_tool_executor\ndef execute_tool" in contents
    observed = detect_existing_integration(tmp_path, [tmp_path / "app.py"], scope_complete=True)
    assert observed["surface_call_candidates"]["tool"] == 1
    assert observed["framework_hook_call_candidates"] == 1
    assert guided_integration.undo(tmp_path)["state"] == "undone"
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == original


def test_handwritten_aliased_plain_python_gate_is_detected_as_tool_candidate(tmp_path):
    source = (
        "from agenticdome_sdk.generic_python import guarded_tool_executor as gate\n"
        "@gate\n"
        "def execute_tool(tool_name, tool_args, agent_id, session_id):\n"
        "    return registry[tool_name](**tool_args)\n"
    )
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")

    observed = detect_existing_integration(tmp_path, [path], scope_complete=True)

    assert observed["state"] == "sdk_calls_found"
    assert observed["framework_hook_call_candidates"] == 1
    assert observed["surface_call_candidates"]["tool"] == 1


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


def test_existing_handwritten_sdk_calls_are_reported_without_protection_claim(tmp_path, monkeypatch, capsys):
    _project(tmp_path)
    (tmp_path / "firewall.py").write_text(
        "from agenticdome_sdk.client import AgenticDomeClient\n"
        "class Firewall:\n"
        "    def screen_input(self, value):\n"
        "        return AgenticDomeClient().guardrail_validate(text=value)\n"
        "    def authorize_tool_call(self, value):\n"
        "        return AgenticDomeClient().guardrail_validate(tool_args=value)\n",
        encoding="utf-8",
    )
    (tmp_path / "handler.py").write_text(
        "from firewall import Firewall\n"
        "def handle(value):\n"
        "    return Firewall().authorize_tool_call(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "decoy.py").write_text(
        "# from agenticdome_sdk import AgenticDomeClient\n"
        "MESSAGE = 'AgenticDomeClient().guardrail_validate()'\n",
        encoding="utf-8",
    )
    observed = detect_existing_integration(
        tmp_path, [tmp_path / name for name in ("firewall.py", "handler.py", "decoy.py")], scope_complete=True,
    )
    assert observed["state"] == "wrapper_calls_found"
    assert observed["sdk_call_candidates"] == 2
    assert observed["local_wrapper_call_candidates"] == 1
    assert observed["runtime_proof"] == "not_assessed"
    assert all(row["path"] != "decoy.py" for row in observed["observations"])

    plan = _plan(certified=False)
    plan["existing_integration"] = observed
    plan["semantic_gate"] = {"action_required": 3, "review_required": 2}
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)
    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "preview"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["existing_integration"]["state"] == "wrapper_calls_found"
    assert summary["existing_integration"]["runtime_proof"] == "not_assessed"
    assert summary["semantic_gap_counts"] == {"action_required": 3, "review_required": 2}
    assert "Existing SDK call sites" in summary["next_action"]
    assert summary["existing_source_edits"] == 0


def test_preview_calls_out_unobserved_a2a_and_mcp_paths(tmp_path, monkeypatch):
    _project(tmp_path)
    plan = _plan(certified=False)
    plan["candidate_boundaries"].append({"boundary": "delegation", "path": "app.py", "line": 6})
    plan["mcp_protection"] = {"detected": True, "roles": ["client"]}
    plan["existing_integration"] = {
        "state": "sdk_imports_only", "surface_call_candidates": {"a2a": 0, "mcp": 0},
    }
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)
    result = guided_integration.preview(tmp_path)
    review = {item["path"]: item["reason"] for item in result["manual_review"]}
    assert "receiving-agent verification" in review["a2a-handoff"]
    assert "separate MCP review path" in review["mcp-routing"]
    assert result["source_edits"] == 0
    assert result["recommended_path"]["may_apply"] is False


def test_auto_target_distinguishes_pure_mcp_mixed_application_and_openclaw():
    mcp = {"detected_frameworks": ["mcp"], "mcp_protection": {"detected": True}}
    assert guided_integration._select_target(mcp, "auto")["selected"] == "mcp"
    mixed = {"detected_frameworks": ["custom-python", "mcp"], "mcp_protection": {"detected": True}}
    choice = guided_integration._select_target(mixed, "auto")
    assert choice["selected"] == "application"
    assert choice["secondary_targets"] == ["mcp"]
    with pytest.raises(RuntimeError, match="openclaw protect"):
        guided_integration._select_target({"detected_frameworks": ["openclaw"]}, "auto")


def test_default_preview_uses_mcp_review_path_for_pure_mcp_workload(tmp_path, monkeypatch, capsys):
    _project(tmp_path)
    plan = _plan()
    plan["frameworks"] = ["mcp"]
    plan["detected_frameworks"] = ["mcp"]
    plan["mcp_protection"] = {
        "detected": True, "servers": [], "tools": [], "request_boundaries": [],
        "response_boundaries": [], "bypass_findings": [],
    }
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)
    assert onboarding_cli.main(["--path", str(tmp_path), "integrate", "preview"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["integration_target"] == "mcp"
    assert result["workload_detection"]["requested"] == "auto"
    assert result["existing_source_edits"] == 0


def test_non_python_existing_integration_is_not_misreported_as_absent(tmp_path):
    path = tmp_path / "index.ts"
    path.write_text("import AgenticDomeClient from 'agenticdome-sdk';\n", encoding="utf-8")
    observed = detect_existing_integration(tmp_path, [path], scope_complete=True)
    assert observed["state"] == "not_assessed_non_python"
    assert observed["runtime_proof"] == "not_assessed"


def test_existing_integration_discovers_catalogued_framework_hooks():
    for key, contract in FRAMEWORK_HOOK_CATALOG.items():
        if contract.get("language") != "python":
            continue
        assert contract["attachment_methods"], key
        assert set(contract["attachment_methods"]).issubset(CATALOG_METHODS), key
    for contract in harness_compatibility_manifest().values():
        assert set(contract["firewall_methods"]).issubset(CATALOG_METHODS)
    assert {"attach_to_agent", "graph_transition_node", "converse_stream_securely", "invoke_agent_securely"}.issubset(README_METHODS)


def test_existing_integration_counts_documented_framework_attachment(tmp_path):
    source = tmp_path / "agent.py"
    source.write_text(
        "from agenticdome_sdk.aws_bedrock import AgenticDomeAWSBedrockFirewall\n"
        "def run(firewall):\n"
        "    return firewall.invoke_agent_securely()\n",
        encoding="utf-8",
    )
    observed = detect_existing_integration(tmp_path, [source], scope_complete=True)
    assert observed["sdk_call_candidates"] == 1
    assert observed["framework_hook_call_candidates"] == 1
    assert observed["runtime_proof"] == "not_assessed"


def test_existing_integration_classifies_a2a_mcp_tool_and_output_calls(tmp_path):
    source = tmp_path / "protected.py"
    source.write_text(
        "from agenticdome_sdk import AgenticDomeClient\n"
        "from agenticdome_sdk.mcp_host import AgenticDomeMCPHostFirewall\n"
        "def connect(client, mcp):\n"
        "    client.a2a_authorize_tool()\n"
        "    client.a2a_verify_decision_token_rpc()\n"
        "    mcp.forward_with_firewall()\n"
        "    client.mesh_validate()\n"
        "    # client.a2a_authorize_tool() is only a comment\n"
        "    message = 'client.mcp_tool_call()'\n",
        encoding="utf-8",
    )
    observed = detect_existing_integration(tmp_path, [source], scope_complete=True)
    assert observed["sdk_call_candidates"] == 4
    assert observed["a2a_call_candidates"] == 2
    assert observed["surface_call_candidates"]["a2a"] == 2
    assert observed["surface_call_candidates"]["mcp"] == 1
    assert observed["surface_call_candidates"]["tool"] == 1
    assert observed["surface_call_candidates"]["output"] == 1
    assert observed["runtime_proof"] == "not_assessed"


def test_generic_guardrail_call_is_classified_from_explicit_request_arguments(tmp_path):
    source = tmp_path / "handler.py"
    source.write_text(
        "from agenticdome_sdk import AgenticDomeClient\n"
        "def check(client, arguments):\n"
        "    client.guardrail_validate(direction='input', text='request')\n"
        "    client.guardrail_validate(direction='outbound', tool_name='crm.update', tool_args=arguments)\n"
        "    client.guardrail_validate(direction='output', text='response')\n"
        "    client.guardrail_validate(direction=arguments.get('direction'), text='unknown')\n",
        encoding="utf-8",
    )
    observed = detect_existing_integration(tmp_path, [source], scope_complete=True)
    assert observed["sdk_call_candidates"] == 4
    assert observed["surface_call_candidates"] == {"prompt": 1, "tool": 1, "a2a": 0, "mcp": 0, "output": 1}


def test_relative_package_import_of_handwritten_wrapper_is_detected(tmp_path):
    package = tmp_path / "service"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    wrapper = package / "firewall.py"
    wrapper.write_text(
        "from agenticdome_sdk import AgenticDomeClient\n"
        "def check_action(value):\n"
        "    return AgenticDomeClient().guardrail_validate(tool_args=value)\n",
        encoding="utf-8",
    )
    handler = package / "handler.py"
    handler.write_text(
        "from .firewall import check_action\n"
        "def run(value):\n"
        "    return check_action(value)\n",
        encoding="utf-8",
    )
    observed = detect_existing_integration(tmp_path, [wrapper, handler], scope_complete=True)
    assert observed["sdk_call_candidates"] == 1
    assert observed["local_wrapper_call_candidates"] == 1
    assert observed["observations"][-1]["method"] == "check_action"


def test_preview_does_not_rewrite_a_file_with_handwritten_sdk_hooks(tmp_path, monkeypatch):
    _project(tmp_path)
    current = (tmp_path / "app.py").read_text(encoding="utf-8")
    plan = _plan()
    plan["existing_integration"] = {
        "state": "sdk_calls_found",
        "observations": [{"path": "app.py", "line": 4, "method": "guardrail_validate", "kind": "sdk_call_candidate"}],
    }
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda root: plan)
    result = guided_integration.preview(tmp_path)
    assert result["source_edits"] == 0
    assert any("overlapping automatic rewrite" in item["reason"] for item in result["manual_review"])
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == current
