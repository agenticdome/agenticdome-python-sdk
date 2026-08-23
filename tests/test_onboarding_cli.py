import argparse
import ast
import json
import subprocess
from pathlib import Path

import pytest

from agenticdome_sdk import onboarding_cli
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

REAL_COPILOT_ANALYSIS = onboarding_cli._copilot_semantic_analysis


def _private_analysis(*, points=None, bypasses=None, reviews=None, confidence="high"):
    return {
        "schema": "agenticdome.semantic-analysis.v2",
        "analysis_revision": onboarding_cli.COPILOT_ANALYSIS_REVISION,
        "ir_schema": "agenticdome.copilot-ir.v1",
        "ir_sha256": "test-bound-by-stub",
        "source_upload": False,
        "analysis_mode": "private_bounded_interprocedural_flow",
        "confidence": confidence,
        "engines": {"python": {"engine": "python-ast", "available": True, "files_parsed": 1}},
        "attachment_points": list(points or []),
        "bypass_risks": list(bypasses or []),
        "review_findings": list(reviews or []),
        "coverage": {},
        "execution_paths": [],
        "symbols_indexed": 1,
        "call_edges": 0,
        "protected_sinks": 0,
        "limitations": [],
    }


@pytest.fixture(autouse=True)
def private_copilot_stub(monkeypatch):
    monkeypatch.setattr(
        onboarding_cli,
        "_copilot_semantic_analysis",
        lambda root, ir, required: _private_analysis() if required else onboarding_cli._pending_semantic_analysis(ir),
    )


def _project(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="sample"\ndependencies=["langgraph"]\n', encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        """from langgraph.graph import StateGraph
user_input = input('Request: ')
screen_input(user_input, agent_id='agent', session_id='session')
authorize_tool(user_input, agent_id='agent', session_id='session', tool_name='crm.lookup', tool_args={})
result = call_tool('crm.lookup', {'id': '123'})
final_output = review_output(str(result), agent_id='agent', session_id='session', platform='langgraph')
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
    assert "crm.lookup" not in serialized
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


def test_boto3_alone_does_not_claim_aws_bedrock(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\nboto3\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )

    report = inspect_repository(tmp_path)
    frameworks = {item["key"] for item in report["frameworks"]}

    assert "custom-python" in frameworks
    assert "bedrock" not in frameworks


def test_bedrock_runtime_client_is_unambiguous_framework_evidence(tmp_path):
    (tmp_path / "runtime.py").write_text(
        'import boto3\nclient = boto3.client("bedrock-runtime")\n',
        encoding="utf-8",
    )

    report = inspect_repository(tmp_path)

    assert "bedrock" in {item["key"] for item in report["frameworks"]}


def test_common_message_variables_are_not_all_reported_as_prompt_ingress(tmp_path):
    (tmp_path / "app.py").write_text(
        "messages = []\nmessages.append({'role': 'system'})\n"
        "user_query = request.query\n"
        "decision = firewall.screen_input(text=user_query)\n"
        "reviewed = firewall.sanitize_output(output=result)\n",
        encoding="utf-8",
    )

    report = inspect_repository(tmp_path)

    assert report["boundary_counts"]["prompt_ingress"] == 2
    assert report["boundary_counts"]["output_egress"] == 1


def test_secret_like_filenames_and_private_key_artifacts_are_never_read(tmp_path):
    (tmp_path / "app.py").write_text("user_query = request.query\n", encoding="utf-8")
    (tmp_path / "api-token.json").write_text('{"value":"must-never-appear"}', encoding="utf-8")
    (tmp_path / "service.pem").write_text("must-never-appear", encoding="utf-8")

    report = inspect_repository(tmp_path)
    serialized = json.dumps(report)

    assert report["potential_secret_files_excluded"] == 2
    assert "must-never-appear" not in serialized


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
    assert (root / ".agenticdome" / "scaffold" / "semantic-analysis.json").exists()
    assert (root / ".agenticdome" / "scaffold" / "SEMANTIC-REVIEW.md").exists()


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


def test_inspection_emits_source_free_ir_for_private_copilot(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.post('/run')\n"
        "def run_agent(request):\n"
        "    result = call_tool('payments.refund', {'amount': 10})\n"
        "    return result\n",
        encoding="utf-8",
    )

    report = inspect_repository(tmp_path)
    semantic = report["semantic_analysis"]
    ir = report["copilot_ir"]

    assert semantic["analysis_mode"] == "pending_private_copilot"
    assert ir["schema"] == "agenticdome.copilot-ir.v1"
    assert ir["source_upload"] is False
    assert ir["privacy"] == {
        "source_text": False,
        "string_literals": False,
        "absolute_paths": False,
        "environment_values": False,
    }
    serialized = json.dumps(ir)
    assert "payments.refund" not in serialized
    assert str(tmp_path) not in serialized
    function = next(item for item in ir["functions"] if item["symbol"] == "run_agent")
    tool_call = next(item for item in function["events"] if item.get("callee") == "call_tool")
    returned = next(item for item in function["events"] if item.get("event") == "return")
    assert tool_call["result_targets"] == ["result"]
    assert returned["value_refs"] == ["ref:result"]


def test_ir_preserves_class_qualified_wrapper_and_fail_closed_raise(tmp_path):
    (tmp_path / "gateway.py").write_text(
        "class ActionGateway:\n"
        "    def execute(self, handler):\n"
        "        try:\n"
        "            self.policy.authorize(tool_name='safe')\n"
        "        except Exception:\n"
        "            raise\n"
        "        return handler()\n",
        encoding="utf-8",
    )

    report = inspect_repository(tmp_path)
    wrapper = next(
        item for item in report["copilot_ir"]["functions"]
        if item["symbol"] == "ActionGateway.execute"
    )

    assert any(item["event"] == "raise" for item in wrapper["events"])
    assert any(item["callee"] == "self.policy.authorize" for item in wrapper["events"])


def test_private_copilot_cache_is_bound_to_tenant_sidecar_ir_and_catalog(tmp_path, monkeypatch):
    ir = {
        "schema": "agenticdome.copilot-ir.v1",
        "source_upload": False,
        "engines": {},
        "functions": [],
    }
    ir_digest = onboarding_cli._ir_sha256(ir)
    catalog = onboarding_cli.catalog_digest()
    binding_digest = "sha256:" + ("b" * 64)
    calls = []
    state = {"tenant": "tenant-1"}

    class Response:
        def __init__(self, tenant):
            self.tenant = tenant

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return json.dumps({
                "schema": "agenticdome.copilot-plan.v1",
                "tenant_id": self.tenant,
                "semantic_analysis": {
                    **_private_analysis(),
                    "ir_sha256": ir_digest,
                },
                "catalog_binding": {
                    "schema": "agenticdome.copilot-hook-catalog-binding.v1",
                    "catalog_schema": onboarding_cli.CATALOG_SCHEMA,
                    "catalog_digest": catalog,
                    "digest": binding_digest,
                    "sidecar_verified": True,
                    "generated_at": 1,
                    "expires_at": 4_102_444_800,
                    "published_packages": {
                        "agenticdome-sdk": {"registry": "npm", "version": "9.9.9"},
                    },
                },
            }).encode("utf-8")

    def urlopen(request, timeout):
        calls.append((request.full_url, request.get_header("Idempotency-key"), timeout))
        return Response(state["tenant"])

    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example")
    monkeypatch.setenv("AGENTICDOME_COPILOT_API_KEY", "scoped-secret")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "tenant-1")
    monkeypatch.setattr(onboarding_cli.urllib.request, "urlopen", urlopen)

    first = REAL_COPILOT_ANALYSIS(tmp_path, ir, required=True)
    second = REAL_COPILOT_ANALYSIS(tmp_path, ir, required=True)
    assert first == second
    assert len(calls) == 1
    assert calls[0][0] == "https://sidecar.example/integration-copilot/v1/analyze"
    assert len(calls[0][1]) == 64
    assert onboarding_cli._active_copilot_catalog_binding(tmp_path)["published_packages"]["agenticdome-sdk"]["version"] == "9.9.9"

    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "tenant-2")
    state["tenant"] = "tenant-2"
    REAL_COPILOT_ANALYSIS(tmp_path, ir, required=True)
    assert len(calls) == 2


def test_private_copilot_rejects_stale_or_invalid_catalog_binding():
    expected = onboarding_cli.catalog_digest()
    current = {
        "schema": "agenticdome.copilot-hook-catalog-binding.v1",
        "catalog_schema": onboarding_cli.CATALOG_SCHEMA,
        "catalog_digest": expected,
        "digest": "sha256:" + ("c" * 64),
        "sidecar_verified": True,
        "expires_at": int(onboarding_cli.time.time()) + 3600,
    }

    assert onboarding_cli._copilot_catalog_binding_matches_sdk(current) is True
    assert onboarding_cli._copilot_catalog_binding_matches_sdk({**current, "catalog_digest": "sha256:" + ("d" * 64)}) is False
    assert onboarding_cli._copilot_catalog_binding_matches_sdk({**current, "digest": "not-a-digest"}) is False
    assert onboarding_cli._copilot_catalog_binding_matches_sdk({**current, "expires_at": int(onboarding_cli.time.time()) - 1}) is False
    assert onboarding_cli._copilot_catalog_binding_matches_sdk({**current, "sidecar_verified": False}) is False


def test_normal_runtime_key_does_not_trigger_optional_copilot_network_call(tmp_path, monkeypatch):
    ir = {"schema": "agenticdome.copilot-ir.v1", "source_upload": False, "engines": {}, "functions": []}
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "tenant-1")
    monkeypatch.setenv("AGENTICDOME_API_KEY", "normal-runtime-secret")
    monkeypatch.delenv("AGENTICDOME_COPILOT_API_KEY", raising=False)
    monkeypatch.setattr(
        onboarding_cli.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("ordinary runtime credentials must not invoke Copilot"),
    )

    semantic = REAL_COPILOT_ANALYSIS(tmp_path, ir, required=False)
    assert semantic["analysis_mode"] == "pending_private_copilot"


def test_semantic_gate_observes_guard_before_final_executor(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "def execute(request):\n"
        "    authorize_tool('refund', agent_id='a', session_id='s', tool_name='payments.refund', tool_args={})\n"
        "    result = call_tool('payments.refund', {'amount': 10})\n"
        "    return review_output(result, agent_id='a', session_id='s', platform='custom')\n",
        encoding="utf-8",
    )

    point = {
        "boundary": "tool_execution", "path": "app.py", "line": 3, "symbol": "execute",
        "semantic_role": "tool_execution", "confidence": "high", "confidence_score": 0.98,
        "protection_observed": True,
    }
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(onboarding_cli, "_copilot_semantic_analysis", lambda root, ir, required: _private_analysis(points=[point]))
        plan = integration_plan(tmp_path)
    tool_point = next(
        item for item in plan["semantic_analysis"]["attachment_points"]
        if item["boundary"] == "tool_execution"
    )

    assert tool_point["protection_observed"] is True
    assert plan["semantic_gate"]["high_severity_bypasses"] == 0


def test_conditional_guard_does_not_falsely_dominate_unconditional_executor(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "def execute(request, should_check):\n"
        "    if should_check:\n"
        "        authorize_tool('refund', agent_id='a', session_id='s', tool_name='payments.refund', tool_args={})\n"
        "    result = call_tool('payments.refund', {'amount': 10})\n"
        "    return review_output(result, agent_id='a', session_id='s', platform='custom')\n",
        encoding="utf-8",
    )

    point = {
        "boundary": "tool_execution", "path": "app.py", "line": 4, "symbol": "execute",
        "semantic_role": "tool_execution", "confidence": "high", "confidence_score": 0.98,
        "protection_observed": False,
    }
    bypass = {
        "boundary": "tool_execution", "path": "app.py", "line": 4, "symbol": "execute",
        "severity": "high", "required_guard": "tool_guard", "confidence_score": 0.98,
    }
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(onboarding_cli, "_copilot_semantic_analysis", lambda root, ir, required: _private_analysis(points=[point], bypasses=[bypass]))
        plan = integration_plan(tmp_path)
    tool_point = next(
        item for item in plan["semantic_analysis"]["attachment_points"]
        if item["boundary"] == "tool_execution"
    )

    assert tool_point["protection_observed"] is False
    assert plan["semantic_gate"]["high_severity_bypasses"] == 1


def test_indirect_output_is_review_required_not_claimed_as_bypass(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "def endpoint(request):\n    return run_agent(request)\n",
        encoding="utf-8",
    )
    review = {
        "boundary": "output_egress", "path": "app.py", "line": 2, "symbol": "endpoint",
        "severity": "medium", "required_guard": "output_guard", "confidence_score": 0.88,
        "disposition": "review_required",
    }
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            onboarding_cli,
            "_copilot_semantic_analysis",
            lambda root, ir, required: _private_analysis(reviews=[review]),
        )
        plan = integration_plan(tmp_path)

    assert plan["semantic_gate"]["unresolved_bypasses"] == 0
    assert plan["semantic_gate"]["review_required"] == 1
    assert plan["semantic_gate"]["production_ready"] is False


def test_command_inspect_json_is_installable(tmp_path, capsys):
    _project(tmp_path)
    assert main(["--path", str(tmp_path), "inspect", "--json"]) == 0
    output = capsys.readouterr().out
    assert SCHEMA in output


def test_command_reports_installed_sdk_version(monkeypatch, capsys):
    monkeypatch.setattr(
        "agenticdome_sdk.onboarding_cli.importlib.metadata.version",
        lambda package: "9.8.7",
    )

    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0

    assert capsys.readouterr().out.strip() == "agenticdome 9.8.7"


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
    assert (scaffold / "FRAMEWORK-HOOKS.md").exists()
    hook_plan = json.loads((scaffold / "framework-hooks.json").read_text(encoding="utf-8"))
    assert hook_plan["hook_catalog"]["schema"] == "agenticdome.hook-catalog.v1"
    assert hook_plan["framework_hook_plans"][0]["adapter"]["native_hooks"] == [
        "before_agent_run", "before_tool_call", "tool_result_persist",
    ]


def test_typescript_without_local_compiler_labels_ir_collection_fallback(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"agenticdome-sdk":"0.5.2"}}', encoding="utf-8"
    )
    (tmp_path / "agent.ts").write_text(
        "authorizeTool('refund', 'agent', 'session', 'custom', 'payments.refund', {});\n"
        "const result = callTool('payments.refund', {});\n"
        "const reviewed = reviewOutput(result, 'agent', 'session', 'custom');\n"
        "return reviewed;\n",
        encoding="utf-8",
    )

    report = inspect_repository(tmp_path)
    semantic = report["semantic_analysis"]

    assert semantic["confidence"] == "unavailable"
    assert semantic["engines"]["typescript"]["engine"] == "typescript-structural-fallback"
    assert report["copilot_ir"]["collector_mode"] == "generic_ast_metadata_only"


def test_certified_python_version_produces_exact_hook_plan(tmp_path, monkeypatch):
    def not_installed(_package):
        raise __import__("importlib.metadata").metadata.PackageNotFoundError

    monkeypatch.setattr("agenticdome_sdk.onboarding_cli.importlib.metadata.version", not_installed)
    (tmp_path / "requirements.txt").write_text("langgraph==1.2.10\nlangchain-core==1.5.4\n", encoding="utf-8")
    (tmp_path / "agent.py").write_text(
        "from langgraph.graph import StateGraph\nuser_query = request.query\n",
        encoding="utf-8",
    )

    plan = integration_plan(tmp_path)
    hook = next(row for row in plan["framework_hook_plans"] if row["framework"] == "langgraph")

    assert hook["status"] == "ready_for_attachment"
    assert hook["exactness"] == "certified_package_and_symbols"
    assert hook["adapter"]["class"] == "AgenticDomeLangGraphFirewall"
    assert "as_langchain_middleware" in hook["adapter"]["attachment_methods"]
    assert {row["status"] for row in hook["packages"]} == {"certified"}


def test_out_of_range_framework_version_is_blocked(tmp_path):
    (tmp_path / "requirements.txt").write_text("crewai==9.0.0\n", encoding="utf-8")
    (tmp_path / "agent.py").write_text("from crewai import Agent\n", encoding="utf-8")

    plan = integration_plan(tmp_path)
    hook = next(row for row in plan["framework_hook_plans"] if row["framework"] == "crewai")

    assert hook["status"] == "blocked"
    assert hook["exactness"] == "blocked_version_mismatch"
    assert hook["packages"][0]["status"] == "outside_certified_range"


def test_mcp_typescript_uses_published_core_contract(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"@modelcontextprotocol/sdk": "latest", "agenticdome-sdk": onboarding_cli.PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-sdk"]["version"]}}),
        encoding="utf-8",
    )
    (tmp_path / "server.ts").write_text('import { Server } from "@modelcontextprotocol/sdk";\n', encoding="utf-8")

    plan = integration_plan(tmp_path)
    hook = next(row for row in plan["framework_hook_plans"] if row["framework"] == "mcp")

    assert hook["contract_key"] == "mcp-ts"
    assert hook["language"] == "typescript"
    assert hook["status"] == "ready_for_attachment"
    assert hook["adapter"]["attachment_methods"] == ["mcpToolCall", "mcpGuardrailValidate", "mcpListTools"]
