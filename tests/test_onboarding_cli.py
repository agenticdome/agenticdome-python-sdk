import argparse
import ast
import json
import subprocess
from pathlib import Path

from agenticdome_sdk.onboarding_cli import (
    CONFIG_SCHEMA,
    SCHEMA,
    create_scaffold,
    init_project,
    inspect_repository,
    integration_plan,
    main,
    verify_project,
)


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="sample"\ndependencies=["langgraph"]\n', encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        """from langgraph.graph import StateGraph
user_input = input('Request: ')
result = call_tool('crm.lookup', {'id': '123'})
final_output = str(result)
""",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text("AGENTICDOME_API_KEY=must-never-appear\n", encoding="utf-8")
    return tmp_path


def test_inspection_is_local_redacted_and_finds_framework_and_boundaries(tmp_path):
    root = _project(tmp_path)
    report = inspect_repository(root)

    assert report["schema"] == SCHEMA
    assert report["source_upload"] is False
    assert report["project"]["root_disclosed"] is False
    assert "langgraph" in [item["key"] for item in report["frameworks"]]
    assert report["potential_secret_files_excluded"] == 1
    serialized = json.dumps(report)
    assert str(root) not in serialized
    assert "must-never-appear" not in serialized
    assert report["boundary_counts"]["prompt_ingress"] > 0
    assert report["boundary_counts"]["tool_execution"] > 0
    assert report["boundary_counts"]["output_egress"] > 0


def test_framework_names_in_prose_do_not_become_installed_frameworks(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="workforce"\ndependencies=["langgraph", "fastapi"]\n',
        encoding="utf-8",
    )
    (tmp_path / "content.py").write_text(
        'ARTICLE = "CrewAI AutoGen Bedrock Claude smolagents Agno LlamaIndex"\n'
        'from langgraph.graph import StateGraph\n',
        encoding="utf-8",
    )

    report = inspect_repository(tmp_path)
    frameworks = {item["key"] for item in report["frameworks"]}

    assert frameworks == {"langgraph", "custom-python"}


def test_guarded_dispatcher_is_a_tool_execution_boundary(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (tmp_path / "tools.py").write_text(
        'result = tool_registry.dispatch(agent_id="agent", tool_name="crm.read", arguments={})\n',
        encoding="utf-8",
    )

    report = inspect_repository(tmp_path)

    assert report["boundary_counts"]["tool_execution"] == 1


def test_init_and_scaffold_generate_review_material_without_editing_application(tmp_path):
    root = _project(tmp_path)
    original = (root / "app.py").read_text(encoding="utf-8")
    args = argparse.Namespace(
        framework=None,
        business_purpose="Customer support",
        sensitive_tool=["crm.update"],
        deployment="managed",
        region="au",
    )

    config = init_project(root, args)
    patch_path = create_scaffold(root)

    assert config["schema"] == CONFIG_SCHEMA
    assert config["source_upload"] is False
    assert patch_path.exists()
    assert "AGENTICDOME_API_KEY=replace-in-your-secret-manager" in patch_path.read_text(encoding="utf-8")
    assert (root / "app.py").read_text(encoding="utf-8") == original
    assert not (root / "agenticdome_integration.py").exists()
    ast.parse((root / ".agenticdome" / "scaffold" / "agenticdome_integration.py").read_text(encoding="utf-8"))


def test_plan_and_local_verification_cover_allowed_and_blocked_paths(tmp_path, monkeypatch):
    root = _project(tmp_path)
    monkeypatch.delenv("AGENTICDOME_PRODUCTION_MODE", raising=False)
    plan = integration_plan(root)
    exit_code, result = verify_project(root, live=False)

    assert plan["coverage"]["gaps"] == []
    assert exit_code == 0
    assert result["ready"] is True
    assert result["framework_runtime_instantiated"] is False
    assert [item["case"] for item in result["decision_cases"]] == ["allowed", "blocked"]
    assert all(item["passed"] for item in result["decision_cases"])


def test_command_inspect_json_is_installable(tmp_path, capsys):
    _project(tmp_path)
    assert main(["--path", str(tmp_path), "inspect", "--json"]) == 0
    output = capsys.readouterr().out
    assert SCHEMA in output


def test_command_inspect_output_prints_summary_not_full_report(tmp_path, capsys):
    _project(tmp_path)
    output_path = tmp_path / "inspection.json"

    assert main(["--path", str(tmp_path), "inspect", "--output", str(output_path)]) == 0

    terminal = json.loads(capsys.readouterr().out)
    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert terminal["status"] == "inspection_written"
    assert terminal["source_upload"] is False
    assert "boundaries" not in terminal
    assert saved["schema"] == SCHEMA


def test_init_console_points_to_inspection_file_not_console_copy(tmp_path, capsys):
    _project(tmp_path)

    assert main(["--path", str(tmp_path), "init"]) == 0

    terminal = json.loads(capsys.readouterr().out)
    assert terminal["config_path"] == ".agenticdome/config.json"
    assert terminal["inspection_path"] == ".agenticdome/inspection.json"
    assert "do not paste" in terminal["next_action"].lower()


def test_verification_can_run_detected_tests_without_including_test_output(tmp_path, monkeypatch):
    root = _project(tmp_path)
    (root / "tests").mkdir()
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("agenticdome_sdk.onboarding_cli.subprocess.run", fake_run)
    exit_code, result = verify_project(root, run_tests=True)

    assert exit_code == 0
    assert result["application_tests"]["passed"] is True
    assert result["application_tests"]["results"][0]["output_included"] is False
    assert calls[0][1]["stdout"] is subprocess.DEVNULL
    assert result["source_upload"] is False
    assert len(result["report_sha256"]) == 64


def test_requirements_based_python_workload_detects_pytest(tmp_path, monkeypatch):
    root = _project(tmp_path)
    (root / "pyproject.toml").unlink()
    (root / "requirements.txt").write_text("pytest\n", encoding="utf-8")
    (root / "tests").mkdir()

    monkeypatch.setattr(
        "agenticdome_sdk.onboarding_cli.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 0),
    )

    _, result = verify_project(root, run_tests=True)

    assert result["application_tests"]["detected"] is True
    assert result["application_tests"]["results"][0]["runner"] == "python_pytest"


def test_typescript_project_gets_typescript_scaffold_not_python_only(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"agenticdome-openclaw-security":"latest"}}', encoding="utf-8"
    )
    (tmp_path / "agent.ts").write_text(
        'const user_input = request.body; await call_tool("crm.lookup", {}); const final_output = result;',
        encoding="utf-8",
    )
    args = argparse.Namespace(
        framework=["openclaw"],
        business_purpose="Customer support",
        sensitive_tool=["crm.lookup"],
        deployment="managed",
        region="auto",
    )
    init_project(tmp_path, args)

    create_scaffold(tmp_path)

    scaffold = tmp_path / ".agenticdome" / "scaffold"
    assert (scaffold / "agenticdome_integration.ts").exists()
    assert not (scaffold / "agenticdome_integration.py").exists()
    assert 'from "agenticdome-sdk"' in (scaffold / "agenticdome_integration.ts").read_text(encoding="utf-8")
