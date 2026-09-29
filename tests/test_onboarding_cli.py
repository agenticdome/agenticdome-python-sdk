import argparse
import ast
import hashlib
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
    protect_openclaw,
    verify_openclaw_project,
    verify_project,
)

REAL_COPILOT_ANALYSIS = onboarding_cli._copilot_semantic_analysis


def test_scoped_inspection_excludes_generated_harness_and_exports_bounded_evidence(tmp_path):
    (tmp_path / "app.py").write_text("def run():\n    return call_tool('approved', {})\n", encoding="utf-8")
    generated = tmp_path / ".harness_runtime_ts"
    generated.mkdir()
    (generated / "poison.py").write_text("def leaked():\n    return call_tool('unreviewed', {})\n", encoding="utf-8")
    report = inspect_repository(tmp_path)
    assert report["scope"]["complete"] is True
    assert report["scanned_files"] == 1
    assert all(item["path"] == "app.py" for item in report["copilot_ir"]["functions"])
    exported = onboarding_cli._exportable_inspection(report)
    assert "copilot_ir" not in exported
    assert exported["copilot_ir_summary"]["symbols_collected"] == len(report["copilot_ir"]["functions"])
    digest = exported.pop("report_sha256")
    assert digest == hashlib.sha256(json.dumps(exported, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_chunked_copilot_transport_binds_every_batch_to_one_ir(monkeypatch):
    functions = [
        {"path": "a.py", "symbol": "entry", "line": 1, "events": [{"event": "call", "callee": "a" * 450000, "line": 2}]},
        {"path": "b.py", "symbol": "sink", "line": 1, "events": [{"event": "call", "callee": "b" * 450000, "line": 2}]},
    ]
    ir = {"schema": "agenticdome.copilot-ir.v1", "source_upload": False, "engines": {}, "functions": functions}
    seen = []

    def post(api_base, api_key, tenant_id, path, body, *, method="POST", idempotency_key=""):
        data = json.loads(body)
        seen.append((path, method, data))
        if path.endswith("/sessions"):
            return {"schema": "agenticdome.copilot-session.v2", "session_id": "A" * 32}
        if "/batches/" in path:
            return {"schema": "agenticdome.copilot-batch-receipt.v2", "index": int(path.rsplit("/", 1)[1]), "sha256": data["sha256"]}
        return {"schema": "agenticdome.copilot-plan.v1", "tenant_id": tenant_id}

    monkeypatch.setattr(onboarding_cli, "_post_copilot", post)
    result = onboarding_cli._chunked_copilot_request("https://sidecar.example", "key", "tenant-1", ir, onboarding_cli._ir_sha256(ir), "idempotency")
    assert result["tenant_id"] == "tenant-1"
    assert seen[0][2]["batch_count"] == 2
    assert [item[1] for item in seen] == ["POST", "PUT", "PUT", "POST"]
    assert seen[0][2]["ir_sha256"] == onboarding_cli._ir_sha256(ir)
    assert [item[2]["functions"][0]["symbol"] for item in seen[1:3]] == ["entry", "sink"]


def test_copilot_analyzes_every_deployable_workload_separately(tmp_path, monkeypatch):
    package = tmp_path / "sdk"
    package.mkdir()
    (package / "pyproject.toml").write_text("[build-system]\n", encoding="utf-8")
    ir = {
        "schema": "agenticdome.copilot-ir.v1", "source_upload": False,
        "engines": {"python": {"available": True, "files_parsed": 2}},
        "functions": [
            {"path": "app.py", "symbol": "root", "line": 1, "events": []},
            {"path": "sdk/client.py", "symbol": "client", "line": 1, "events": []},
        ],
        "coverage": {"complete": True, "candidate_source_files": 2},
        "scope": {"complete": True, "selected_root": "project"},
    }
    seen = []

    def post(api_base, api_key, tenant_id, path, body, **kwargs):
        request = json.loads(body)
        seen.append(request["ir"])
        assert len(body) < 4_500_000
        return {
            "schema": "agenticdome.copilot-plan.v1", "tenant_id": tenant_id,
            "catalog_binding": {"schema": "test"},
            "semantic_analysis": {
                "schema": "agenticdome.semantic-analysis.v2",
                "analysis_revision": onboarding_cli.COPILOT_ANALYSIS_REVISION,
                "ir_sha256": onboarding_cli._ir_sha256(request["ir"]),
                "confidence": "high", "symbols_indexed": 1, "call_edges": 0,
                "protected_sinks": 0, "events_analyzed": 0,
                "attachment_points": [], "bypass_risks": [], "review_findings": [],
                "execution_paths": [], "coverage": {}, "limitations": [],
            },
        }

    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example")
    monkeypatch.setenv("AGENTICDOME_COPILOT_API_KEY", "test-key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "tenant-1")
    monkeypatch.setattr(onboarding_cli, "_post_copilot", post)
    monkeypatch.setattr(onboarding_cli, "_copilot_catalog_binding_matches_sdk", lambda binding: True)
    semantic = REAL_COPILOT_ANALYSIS(tmp_path, ir, required=True)
    assert [part["functions"][0]["path"] for part in seen] == ["app.py", "sdk/client.py"]
    assert semantic["ir_sha256"] == onboarding_cli._ir_sha256(ir)
    assert semantic["workload_coverage"]["selected_parts"] == 2
    assert semantic["workload_coverage"]["analyzed_parts"] == 2
    assert semantic["workload_coverage"]["cross_part_flow_proven"] is False
    assert semantic["confidence"] == "partial"


def test_copilot_rejects_oversized_function_before_any_request(tmp_path, monkeypatch):
    ir = {
        "schema": "agenticdome.copilot-ir.v1", "source_upload": False,
        "functions": [{"path": "app.py", "symbol": "large", "events": [{}] * 2049}],
    }
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example")
    monkeypatch.setenv("AGENTICDOME_COPILOT_API_KEY", "test-key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "tenant-1")
    monkeypatch.setattr(onboarding_cli, "_post_copilot", lambda *args, **kwargs: pytest.fail("must not call sidecar"))
    with pytest.raises(SystemExit, match="2048-event analysis boundary"):
        REAL_COPILOT_ANALYSIS(tmp_path, ir, required=True)


def test_init_remains_local_when_private_copilot_is_unavailable(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("def run():\n    pass\n", encoding="utf-8")
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://unavailable.example")
    monkeypatch.setenv("AGENTICDOME_COPILOT_API_KEY", "test-key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "tenant-1")
    monkeypatch.setattr(onboarding_cli, "_post_copilot", lambda *args, **kwargs: pytest.fail("init must stay local"))
    config = init_project(tmp_path, argparse.Namespace(framework=[], business_purpose="test", sensitive_tool=[], deployment="managed", region="auto"))
    assert config["schema"] == CONFIG_SCHEMA
    assert onboarding_cli._read_workload_id(tmp_path) == config["workload_id"]
    assert inspect_repository(tmp_path)["project"]["workload_id"] == config["workload_id"]


def test_existing_project_keeps_config_and_gets_stable_workload_identity(tmp_path):
    (tmp_path / "app.py").write_text("def run():\n    pass\n", encoding="utf-8")
    config_dir = tmp_path / ".agenticdome"
    config_dir.mkdir()
    original = '{"schema":"agenticdome.project-config.v1","frameworks":["custom-python"]}'
    (config_dir / "config.json").write_text(original, encoding="utf-8")
    args = argparse.Namespace(framework=[], business_purpose="", sensitive_tool=[], deployment="managed", region="auto")
    init_project(tmp_path, args)
    first = onboarding_cli._read_workload_id(tmp_path)
    init_project(tmp_path, args)
    assert onboarding_cli._read_workload_id(tmp_path) == first
    assert inspect_repository(tmp_path)["project"]["workload_id"] == first
    assert (config_dir / "config.json").read_text(encoding="utf-8") == original


def test_cross_part_inventory_identifies_a_resolvable_call_without_claiming_proof():
    caller = {"path": "app.py", "symbol": "run", "line": 1,
              "events": [{"event": "call", "callee": "execute", "line": 3}]}
    target = {"path": "sdk/client.py", "symbol": "execute", "line": 8, "events": []}
    ir = {"schema": "agenticdome.copilot-ir.v1", "functions": [caller, target]}
    parts = [("app#0", {"functions": [caller]}), ("sdk#0", {"functions": [target]})]
    result = {"ir_sha256": "part", "attachment_points": [], "bypass_risks": [],
              "review_findings": [], "execution_paths": [], "coverage": {}, "limitations": []}
    semantic = onboarding_cli._merge_copilot_parts(ir, [("app#0", result), ("sdk#0", result)], parts)
    assert semantic["workload_coverage"]["cross_part_edges"]["observed_count"] == 1
    assert semantic["workload_coverage"]["cross_part_flow_proven"] is False
    assert semantic["workload_coverage"]["cross_part_review_required"] is True


def test_copilot_marks_capped_finding_lists_as_not_fully_visible():
    ir = {"schema": "agenticdome.copilot-ir.v1", "source_upload": False, "functions": []}
    result = {
        "ir_sha256": "part-digest", "attachment_points": [{}] * 100,
        "bypass_risks": [], "review_findings": [], "execution_paths": [],
        "limitations": [], "symbols_indexed": 0,
    }
    semantic = onboarding_cli._merge_copilot_parts(ir, [(".#0", result)])
    assert semantic["workload_coverage"]["result_lists_at_cap"] == ["attachment_points"]
    assert any("additional findings may exist" in item for item in semantic["limitations"])


def test_copilot_resumes_successful_parts_after_a_later_failure(tmp_path, monkeypatch):
    package = tmp_path / "sdk"
    package.mkdir()
    (package / "pyproject.toml").write_text("[build-system]\n", encoding="utf-8")
    ir = {
        "schema": "agenticdome.copilot-ir.v1", "source_upload": False,
        "functions": [
            {"path": "app.py", "symbol": "root", "events": []},
            {"path": "sdk/client.py", "symbol": "client", "events": []},
        ],
    }
    monkeypatch.setenv("AGENTICDOME_API_BASE", "https://sidecar.example")
    monkeypatch.setenv("AGENTICDOME_COPILOT_API_KEY", "test-key")
    monkeypatch.setenv("AGENTICDOME_TENANT_ID", "tenant-1")
    monkeypatch.setattr(onboarding_cli, "_copilot_catalog_binding_matches_sdk", lambda binding: True)
    calls = []
    fail_second = True

    def post(api_base, api_key, tenant_id, path, body, **kwargs):
        nonlocal fail_second
        part = json.loads(body)["ir"]
        calls.append(part["functions"][0]["path"])
        if calls[-1] == "sdk/client.py" and fail_second:
            fail_second = False
            raise SystemExit("temporary Core failure")
        return {
            "schema": "agenticdome.copilot-plan.v1", "tenant_id": tenant_id,
            "catalog_binding": {"schema": "test"},
            "semantic_analysis": {
                "ir_sha256": onboarding_cli._ir_sha256(part),
                "analysis_revision": onboarding_cli.COPILOT_ANALYSIS_REVISION,
                "attachment_points": [], "bypass_risks": [], "review_findings": [],
                "execution_paths": [], "coverage": {}, "limitations": [],
            },
        }

    monkeypatch.setattr(onboarding_cli, "_post_copilot", post)
    with pytest.raises(SystemExit, match="temporary Core failure"):
        REAL_COPILOT_ANALYSIS(tmp_path, ir, required=True)
    assert not (tmp_path / ".agenticdome" / "copilot-analysis.json").exists()
    REAL_COPILOT_ANALYSIS(tmp_path, ir, required=True)
    assert calls == ["app.py", "sdk/client.py", "sdk/client.py"]


def test_incomplete_scope_cannot_be_presented_as_a_placement_plan(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("def a():\n    pass\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def b():\n    pass\n", encoding="utf-8")
    monkeypatch.setattr(onboarding_cli, "MAX_FILES", 1)
    report = inspect_repository(tmp_path)
    assert report["scan_limit_reached"] is True
    assert report["scope"]["complete"] is False
    with pytest.raises(SystemExit, match="unexamined code must not be reported as protected"):
        integration_plan(tmp_path)


def test_oversized_source_is_visible_as_a_scope_gap(tmp_path, monkeypatch):
    (tmp_path / "small.py").write_text("def run():\n    pass\n", encoding="utf-8")
    (tmp_path / "large.py").write_text("def hidden():\n    pass\n" * 10, encoding="utf-8")
    monkeypatch.setattr(onboarding_cli, "MAX_TEXT_BYTES", 64)
    report = inspect_repository(tmp_path)
    assert report["scope"]["complete"] is False
    assert report["scope"]["unexamined_source_counts"]["oversized_source_files"] == 1
    assert all(function["path"] != "large.py" for function in report["copilot_ir"]["functions"])
    with pytest.raises(SystemExit, match="Split or isolate the required agent code"):
        integration_plan(tmp_path)


def test_unparsed_source_is_a_scope_gap_not_a_protected_path(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n    pass\n", encoding="utf-8")
    report = inspect_repository(tmp_path, remote_analysis=False)
    assert report["scope"]["complete"] is False
    assert report["copilot_ir"]["coverage"]["limit_reason"] == "parse_or_read_error"
    with pytest.raises(SystemExit, match="could not be parsed"):
        integration_plan(tmp_path)


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
    assert config["execution_broker_mode"] == "policy"
    assert config["source_upload"] is False
    assert patch_path.exists()
    assert "AGENTICDOME_API_KEY=replace-in-your-secret-manager" in patch_path.read_text(encoding="utf-8")
    assert (root / "app.py").read_text(encoding="utf-8") == original
    assert not (root / "agenticdome_integration.py").exists()
    ast.parse((root / ".agenticdome" / "scaffold" / "agenticdome_integration.py").read_text(encoding="utf-8"))
    assert (root / ".agenticdome" / "scaffold" / "semantic-analysis.json").exists()
    assert (root / ".agenticdome" / "scaffold" / "SEMANTIC-REVIEW.md").exists()
    generated = (root / ".agenticdome" / "scaffold" / "agenticdome_integration.py").read_text()
    assert 'execution_broker_mode="policy"' in generated
    assert 'AGENTICDOME_EXECUTION_BROKER_MODE=policy' in patch_path.read_text()


def test_reinitialization_preserves_existing_config_and_explicit_modes(tmp_path):
    root = _project(tmp_path)
    directory = root / ".agenticdome"
    directory.mkdir(exist_ok=True)
    for existing in ({"schema": CONFIG_SCHEMA, "frameworks": ["mcp"]}, {"schema": CONFIG_SCHEMA, "execution_broker_mode": "off"}):
        original = json.dumps(existing, indent=4) + "\n"
        (directory / "config.json").write_text(original)
        assert init_project(root, argparse.Namespace()) == existing
        assert (directory / "config.json").read_text() == original


def test_policy_configuration_reaches_python_typescript_and_mcp_clients(tmp_path):
    root = _project(tmp_path)
    config = {"frameworks": ["mcp"], "execution_broker_mode": "policy"}
    plan = integration_plan(root)
    plan["languages"] = ["python", "typescript/javascript"]
    files = onboarding_cli._scaffold_files(config, plan)
    for filename in ("agenticdome_integration.py", "agenticdome_mcp_gateway.py"):
        ast.parse(files[filename])
        assert 'execution_broker_mode="policy"' in files[filename]
    for filename in ("agenticdome_integration.ts", "agenticdome_mcp_gateway.ts"):
        assert 'executionBrokerMode: "policy"' in files[filename]
    assert "unsupported resolver fails closed" in files["AGENTICDOME-INTEGRATION.md"]
    legacy = onboarding_cli._scaffold_files({"frameworks": ["mcp"]}, plan)
    assert "AGENTICDOME_EXECUTION_BROKER_MODE" not in legacy[".env.agenticdome.example"]
    assert "executionBrokerMode" not in legacy["agenticdome_mcp_gateway.ts"]
    explicit = onboarding_cli._scaffold_files({**config, "execution_broker_mode": "off"}, plan)
    assert 'execution_broker_mode="off"' in explicit["agenticdome_integration.py"]


def test_bad_onboarding_mode_is_rejected_instead_of_silent_downgrade():
    with pytest.raises(SystemExit, match="Invalid execution_broker_mode"):
        onboarding_cli._onboarding_broker_options({"execution_broker_mode": "typo"})


@pytest.mark.parametrize("existing_mode", [None, "off"])
def test_device_connect_sets_policy_only_for_new_workloads(tmp_path, monkeypatch, existing_mode):
    import hashlib
    from agenticdome_sdk import connect

    root = _project(tmp_path)
    state = root / ".agenticdome"
    state.mkdir(exist_ok=True)
    original = None
    if existing_mode:
        original = json.dumps({"schema": CONFIG_SCHEMA, "execution_broker_mode": existing_mode, "frameworks": ["custom-python"]}, indent=4)
        (state / "config.json").write_text(original)
    session = {
        "tenant_id": "2", "session_uuid": "test-session", "access_token": "test-only",
        "expires_at": "2026-09-10T12:00:00Z",
        "runtime": {"api_base": "https://runtime.example", "region": "au", "execution_broker": {"sdk_mode": "policy", "status": "pending_runtime_readiness"}},
        "copilot": {"api_key": "test-copilot-only"},
    }
    metadata_requests = []
    def request(url, data, *args, **kwargs):
        if url.endswith("/device"):
            return {"verification_uri_complete": "https://portal.example/device", "user_code": "TEST", "device_code": "test", "expires_in": 600}
        if url.endswith("/token"):
            return session
        if url.endswith("/metadata"):
            metadata_requests.append(data)
        return {}
    monkeypatch.setattr(connect, "_request", request)
    monkeypatch.setattr(connect.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(connect, "_approve_metadata", lambda *args: None)
    monkeypatch.setattr(connect, "ensure_attestation_key", lambda directory: ("test-private", "test-public"))
    monkeypatch.setattr(onboarding_cli, "_copilot_semantic_analysis", lambda root, ir, required: {
        "ir_sha256": onboarding_cli._ir_sha256(ir), "attachment_points": [], "bypass_risks": [],
        "workload_coverage": {"selected_parts": 2, "analyzed_parts": 2, "cross_part_flow_proven": False},
    })
    monkeypatch.setattr(onboarding_cli, "_active_copilot_catalog_binding", lambda root: {"schema": "test"})
    monkeypatch.setattr(onboarding_cli, "create_scaffold", lambda root: root / ".agenticdome/scaffold/agenticdome.patch")
    result = connect.run_connect(root, argparse.Namespace(portal="https://portal.example", no_browser=True, yes=True, workload_name="test", environment="test", open_pr=False))
    assert json.loads((state / "config.json").read_text())["execution_broker_mode"] == (existing_mode or "policy")
    assert result["execution_broker"]["sdk_mode"] == (existing_mode or "policy")
    assert result["execution_broker"]["status"] == "pending_runtime_readiness"
    assert result["cross_part_review_required"] is True
    assert "cross-part call paths" in result["next_action"]
    assert metadata_requests[0]["ir"]["metadata_kind"] == "bounded_workload_summary"
    assert metadata_requests[0]["ir"]["functions"] == []
    assert metadata_requests[0]["signed_plan"]["aggregation"]["signature_scope"] == "individual_sidecar_parts_only"
    if original:
        assert (state / "config.json").read_text() == original


def test_live_verification_uses_workload_broker_configuration(tmp_path, monkeypatch):
    root = _project(tmp_path)
    state = root / ".agenticdome"
    state.mkdir(exist_ok=True)
    (state / "config.json").write_text(json.dumps({"schema": CONFIG_SCHEMA, "frameworks": ["custom-python"], "execution_broker_mode": "policy"}))
    for key, value in {"AGENTICDOME_API_BASE": "https://sidecar.example", "AGENTICDOME_API_KEY": "test-only", "AGENTICDOME_TENANT_ID": "2"}.items():
        monkeypatch.setenv(key, value)
    captured = {}
    class Client:
        def __init__(self, **kwargs):
            captured.update(kwargs)
        def guardrail_validate(self, **kwargs):
            return {"verdict": "BLOCKED" if kwargs["tool_name"].startswith("salesforce") else "ALLOWED"}
        def close(self):
            pass
    monkeypatch.setattr("agenticdome_sdk.client.AgenticDomeClient", Client)
    verify_project(root, live=True)
    assert captured["execution_broker_mode"] == "policy"
    assert captured["mode"] == "live"


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
    assert "run agenticdome integrate preview" in terminal["next_action"]
    assert "import that refreshed file" in terminal["next_action"]


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
    assert hook["adapter"]["attachment_methods"] == [
        "forward", "preflight", "mcpToolCall", "mcpGuardrailValidate", "mcpListTools",
    ]


def _openclaw_protection():
    return {
        "schema": "agenticdome.openclaw-protection.v1",
        "source_upload": False,
        "plugin_id": "agenticdome-security",
        "plugin_status": "loaded",
        "hook_count": 3,
        "hooks": ["before_agent_run", "before_tool_call", "tool_result_persist"],
        "required_hooks": ["before_agent_run", "before_tool_call", "tool_result_persist"],
        "exact_hook_contract": True,
        "allow_conversation_access": True,
        "versions": {
            "node": "v24.15.0",
            "openclaw": "2026.7.1-2",
            "plugin": "1.0.2",
            "core_sdk": "0.6.3",
        },
        "ready": True,
        "claim_boundary": "test",
    }


def test_openclaw_protect_records_exact_runtime_hooks_without_source_changes(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"openclaw":"2026.7.1-2","agenticdome-openclaw-security":"1.0.2"}}',
        encoding="utf-8",
    )
    (tmp_path / "agent.ts").write_text("openclaw plugins inspect agenticdome-security", encoding="utf-8")
    monkeypatch.setattr(onboarding_cli, "_openclaw_runtime_inspection", lambda _root: _openclaw_protection())

    result = protect_openclaw(tmp_path)
    inspection = json.loads((tmp_path / ".agenticdome" / "inspection.json").read_text(encoding="utf-8"))

    assert result["status"] == "ready_for_verification"
    assert result["customer_source_modified"] is False
    assert inspection["openclaw_protection"]["ready"] is True
    assert inspection["openclaw_protection"]["hooks"] == onboarding_cli.OPENCLAW_REQUIRED_HOOKS
    assert len(inspection["report_sha256"]) == 64


def test_openclaw_verify_requires_exact_hooks_and_live_decisions(tmp_path, monkeypatch):
    monkeypatch.setattr(onboarding_cli, "_openclaw_runtime_inspection", lambda _root: _openclaw_protection())
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda _root: {"mcp_protection": {"detected": False}})
    monkeypatch.setattr(
        onboarding_cli,
        "verify_project",
        lambda _root, live, run_tests, plan: (0, {
            "schema": "agenticdome.verification-result.v1",
            "source_upload": False,
            "decision_cases": [
                {"case": "allowed", "verdict": "ALLOWED", "passed": True},
                {"case": "blocked", "verdict": "BLOCKED", "passed": True},
            ],
            "static_coverage": {"gaps": []},
            "semantic_gate": {"passed": True},
            "application_tests": {"requested": True, "detected": True, "passed": True, "results": []},
            "ready": True,
            "report_sha256": "0" * 64,
        }),
    )

    exit_code, result = verify_openclaw_project(tmp_path)

    assert exit_code == 0
    assert result["ready"] is True
    assert result["openclaw_verification"]["exact_hook_contract"] is True
    assert result["openclaw_verification"]["live_tenant_decisions"] is True
    assert result["openclaw_verification"]["telemetry_confirmation"] == "control_plane_certificate_required"


def test_openclaw_verify_includes_mcp_proof_when_same_workload_uses_mcp(tmp_path, monkeypatch):
    monkeypatch.setattr(onboarding_cli, "_openclaw_runtime_inspection", lambda _root: _openclaw_protection())
    plan = {"mcp_protection": {"detected": True}}
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda _root: plan)
    calls = []

    def mcp_verify(_root, *, live, run_tests, plan):
        calls.append((live, run_tests, plan))
        return 0, {
            "decision_cases": [{"case": "allowed", "passed": True}, {"case": "blocked", "passed": True}],
            "mcp_verification": {"schema": "agenticdome.mcp-verification.v1", "ready": True},
            "ready": True,
            "report_sha256": "0" * 64,
        }

    monkeypatch.setattr(onboarding_cli, "verify_mcp_project", mcp_verify)
    exit_code, result = verify_openclaw_project(tmp_path)

    assert exit_code == 0
    assert calls == [(True, True, plan)]
    assert result["mcp_verification"]["ready"] is True
    assert result["openclaw_verification"]["ready"] is True


def test_openclaw_verify_does_not_pass_when_combined_mcp_proof_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(onboarding_cli, "_openclaw_runtime_inspection", lambda _root: _openclaw_protection())
    monkeypatch.setattr(onboarding_cli, "integration_plan", lambda _root: {"mcp_protection": {"detected": True}})
    monkeypatch.setattr(
        onboarding_cli,
        "verify_mcp_project",
        lambda _root, *, live, run_tests, plan: (2, {
            "decision_cases": [{"case": "allowed", "passed": True}, {"case": "blocked", "passed": True}],
            "mcp_verification": {"schema": "agenticdome.mcp-verification.v1", "ready": False},
            "ready": False,
            "report_sha256": "0" * 64,
        }),
    )

    exit_code, result = verify_openclaw_project(tmp_path)

    assert exit_code == 2
    assert result["ready"] is False
    assert result["mcp_verification"]["ready"] is False
    assert result["openclaw_verification"]["ready"] is True
