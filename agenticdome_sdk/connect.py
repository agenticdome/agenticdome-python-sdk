"""Thin device-flow onboarding client; proprietary analysis stays in the private sidecar."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import time
import tempfile
import urllib.error
import urllib.request
import uuid
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

from .attestation import ensure_attestation_key
from .hook_catalog import CATALOG_SCHEMA, CATALOG_VERIFIED_AT, catalog_digest


SCOPES = ["onboarding:read", "metadata:write", "evidence:write", "workload:write", "repository:prepare"]


def _request(url: str, data: Dict[str, Any], token: str = "", headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    request_headers = {"Accept": "application/json", "Content-Type": "application/json", **(headers or {})}
    if token:
        request_headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=json.dumps(data, separators=(",", ":")).encode("utf-8"), headers=request_headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=90) as response:  # noqa: S310 - operator-selected HTTPS portal/assigned sidecar
            result = json.loads(response.read().decode("utf-8"))
            if not isinstance(result, dict):
                raise RuntimeError("AgenticDome returned a non-object response.")
            return result
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            body = {}
        error = body.get("error") or body.get("message") or body.get("detail") or exc.reason
        failure = RuntimeError(str(error))
        setattr(failure, "status", exc.code)
        raise failure from exc


def _get(url: str, token: str) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "Authorization": "Bearer " + token}, method="GET")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - explicit AgenticDome portal
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("AgenticDome returned a non-object response.")
    return value


def _run_git(root: Path, *arguments: str, env: Optional[Dict[str, str]] = None) -> str:
    result = subprocess.run(["git", *arguments], cwd=root, env=env, text=True, capture_output=True, timeout=180, check=False)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "git command failed").strip()[:500])
    return result.stdout.strip()


def _open_review_pr(root: Path, portal: str, session: Dict[str, Any], connection_uuid: str, patch_path: Path, run_tests: bool = False) -> Dict[str, Any]:
    if not (root / ".git").exists():
        raise RuntimeError("--open-pr requires a Git working tree.")
    if _run_git(root, "status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError("Tracked working-tree changes exist. Commit or stash them before --open-pr.")
    credential = _get(portal + "/api/agentguard/repositories/" + connection_uuid + "/credential", session["access_token"])
    branch = "agenticdome/connect-" + session["session_uuid"].split("-")[0]
    _run_git(root, "switch", "-c", branch)
    try:
        _run_git(root, "apply", "--check", str(patch_path))
        paths = []
        for line in _run_git(root, "apply", "--numstat", str(patch_path)).splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3 and parts[2]:
                paths.append(parts[2])
        _run_git(root, "apply", str(patch_path))
        paths = sorted(set(paths))
        if not paths:
            raise RuntimeError("The generated integration patch did not create reviewable files.")
        if run_tests:
            from .onboarding_cli import verify_project
            exit_code, verification = verify_project(root, live=False, run_tests=True)
            if exit_code != 0:
                raise RuntimeError("Local verification or project tests failed; review .agenticdome/verification.json before retrying.")
        _run_git(root, "add", "--", *paths)
        _run_git(root, "commit", "-m", "Add AgenticDome verified-action integration")
        with tempfile.NamedTemporaryFile("w", prefix="agenticdome-askpass-", delete=False) as handle:
            handle.write("#!/usr/bin/env python3\nimport os,sys\nprint(os.environ['AGENTICDOME_GIT_USERNAME'] if 'Username' in sys.argv[1] else os.environ['AGENTICDOME_GIT_PASSWORD'])\n")
            askpass = handle.name
        os.chmod(askpass, 0o700)
        push_env = dict(os.environ)
        push_env.update({
            "GIT_ASKPASS": askpass, "GIT_ASKPASS_REQUIRE": "force", "GIT_TERMINAL_PROMPT": "0",
            "AGENTICDOME_GIT_USERNAME": "x-access-token" if credential["provider"] == "github" else "oauth2",
            "AGENTICDOME_GIT_PASSWORD": credential["token"],
        })
        try:
            _run_git(root, "push", credential["git_http_url"], "HEAD:refs/heads/" + branch, env=push_env)
        finally:
            os.unlink(askpass)
        return _request(portal + "/api/agentguard/repositories/" + connection_uuid + "/pull-request", {
            "head": branch, "title": "Add AgenticDome verified-action integration",
            "body": "Generated locally from source-free metadata and a tenant-bound private Copilot plan. No source or diff was uploaded to AgenticDome. Review and merge manually.",
        }, session["access_token"])
    except Exception as exc:
        raise RuntimeError(f"Review branch {branch} was retained for inspection after PR preparation failed: {exc}") from exc


def _approve_metadata(ir: Dict[str, Any], assume_yes: bool) -> None:
    functions = ir.get("functions") if isinstance(ir.get("functions"), list) else []
    print(json.dumps({
        "privacy_preview": {
            "schema": ir.get("schema"), "source_upload": False,
            "structural_functions": len(functions), "engines": sorted((ir.get("engines") or {}).keys()),
            "excluded": ["source text", "string literals", "secrets", "environment values", "absolute paths"],
        }
    }, indent=2, sort_keys=True))
    if not assume_yes and input("Send this source-free metadata to your assigned AgenticDome runtime? [y/N] ").strip().lower() not in {"y", "yes"}:
        raise SystemExit("No metadata was uploaded.")


def run_connect(root: Path, args: Any) -> Dict[str, Any]:
    # Import lazily to avoid a module cycle and keep the public client purely orchestration code.
    from .onboarding_cli import _installed_sdk_version, inspect_repository

    portal = str(args.portal).rstrip("/")
    if not portal.startswith("https://") and not getattr(args, "allow_insecure_http", False):
        raise SystemExit("The portal URL must use HTTPS (use --allow-insecure-http only for local development).")
    verifier = secrets.token_urlsafe(64)
    challenge = hashlib.sha256(verifier.encode("ascii")).hexdigest()
    device = _request(portal + "/api/agentguard/connect/device", {"pkce_challenge": challenge, "scopes": SCOPES})
    print(f"Approve this device at {device['verification_uri_complete']} (code {device['user_code']}).")
    if not args.no_browser:
        webbrowser.open(str(device["verification_uri_complete"]))
    deadline = time.monotonic() + int(device.get("expires_in", 600))
    interval = max(3, int(device.get("interval", 5)))
    session: Optional[Dict[str, Any]] = None
    while time.monotonic() < deadline:
        time.sleep(interval)
        try:
            session = _request(portal + "/api/agentguard/connect/token", {"device_code": device["device_code"], "pkce_verifier": verifier})
            break
        except RuntimeError as exc:
            if str(exc) == "authorization_pending":
                continue
            if str(exc) == "slow_down":
                interval = min(interval + 3, 30)
                continue
            raise
    if session is None:
        raise SystemExit("Device approval expired; run agenticdome connect again.")
    if not session.get("runtime") or not session.get("copilot"):
        raise SystemExit("Authentication succeeded, but no eligible runtime is assigned. The saved portal session can be resumed after an administrator enables an assignment policy.")

    report = inspect_repository(root)
    ir = report["copilot_ir"]
    _approve_metadata(ir, bool(args.yes))
    private_pem, public_pem = ensure_attestation_key(root / ".agenticdome")
    del private_pem
    workload_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, session["tenant_id"] + ":" + root.name))
    frameworks = [item["key"] for item in report.get("frameworks", [])]
    _request(portal + "/api/agentguard/connect/workloads", {
        "session_uuid": session["session_uuid"], "workload_uuid": workload_uuid,
        "name": args.workload_name or root.name, "environment": args.environment,
        "attestation_public_key": public_pem, "frameworks": frameworks,
        "capabilities": {"signed_manifests": True, "signed_heartbeats": True, "outcome_receipts": True},
    }, session["access_token"])

    runtime_base = str(session["runtime"]["api_base"]).rstrip("/")
    copilot_key = str(session["copilot"]["api_key"])
    ir_digest = hashlib.sha256(json.dumps(ir, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    plan = _request(runtime_base + "/integration-copilot/v1/analyze", {
        "schema": "agenticdome.copilot-request.v1", "ir": ir,
        "catalog_binding": {"schema": CATALOG_SCHEMA, "catalog_digest": catalog_digest(), "verified_at": CATALOG_VERIFIED_AT},
    }, headers={"X-API-Key": copilot_key, "X-Tenant-Id": session["tenant_id"], "Idempotency-Key": hashlib.sha256((session["tenant_id"] + ir_digest + catalog_digest()).encode()).hexdigest()})
    if plan.get("schema") != "agenticdome.copilot-plan.v1" or plan.get("tenant_id") != session["tenant_id"]:
        raise SystemExit("The assigned private Copilot returned an invalid tenant-bound plan.")
    semantic = plan.get("semantic_analysis") or {}
    if semantic.get("ir_sha256") != ir_digest:
        raise SystemExit("The private Copilot plan was not bound to the submitted metadata.")
    _request(portal + "/api/agentguard/connect/sessions/" + session["session_uuid"] + "/metadata", {"ir": ir, "signed_plan": plan}, session["access_token"])

    state_dir = root / ".agenticdome"
    state_dir.mkdir(parents=True, exist_ok=True)
    cache = {"schema": "agenticdome.copilot-cache.v1", "source_upload": False, "tenant_id": session["tenant_id"], "api_base": runtime_base, "semantic_analysis": semantic, "catalog_binding": plan.get("catalog_binding")}
    (state_dir / "copilot-analysis.json").write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    config_path = state_dir / "config.json"
    if not config_path.exists():
        config_path.write_text(json.dumps({
            "schema": "agenticdome.project-config.v1", "frameworks": frameworks or ["custom-python"],
            "execution_broker_mode": "policy",
            "business_purpose": "REVIEW_REQUIRED_NOT_INVENTED", "sensitive_tools": [],
            "deployment": {"preference": "managed", "region": session["runtime"].get("region") or "auto"},
            "source_upload": False,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    resumable = {"schema": "agenticdome.connect-state.v1", "portal": portal, "tenant_id": session["tenant_id"], "session_uuid": session["session_uuid"], "workload_uuid": workload_uuid, "token_expires_at": session["expires_at"], "access_token": session["access_token"]}
    state_path = state_dir / "connect-session.json"
    state_path.write_text(json.dumps(resumable, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(state_path, 0o600)
    previous = {name: os.environ.get(name) for name in ("AGENTICDOME_API_BASE", "AGENTICDOME_COPILOT_API_KEY", "AGENTICDOME_TENANT_ID")}
    os.environ.update({"AGENTICDOME_API_BASE": runtime_base, "AGENTICDOME_COPILOT_API_KEY": copilot_key, "AGENTICDOME_TENANT_ID": session["tenant_id"]})
    try:
        from .onboarding_cli import create_scaffold
        patch_path = create_scaffold(root)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    pull_request = None
    if args.open_pr:
        if not args.repository_connection:
            raise SystemExit("--open-pr requires --repository-connection with a connection UUID from the customer portal.")
        pull_request = _open_review_pr(root, portal, session, args.repository_connection, patch_path)
    effective_config = json.loads(config_path.read_text(encoding="utf-8"))
    broker_setup = dict(session["runtime"].get("execution_broker") or {
        "status": "readiness_not_reported",
        "next_action": "Ask AgenticDome to confirm policy-aware sidecar readiness before live verification.",
    })
    broker_setup["sdk_mode"] = effective_config.get("execution_broker_mode", "existing_sdk_or_environment_default")
    return {
        "status": "changeset_ready", "source_upload": False, "tenant_id": session["tenant_id"],
        "session_uuid": session["session_uuid"], "workload_uuid": workload_uuid,
        "runtime_region": session["runtime"].get("region"), "frameworks": frameworks,
        "execution_broker": broker_setup,
        "attachment_points": len(semantic.get("attachment_points") or []),
        "bypass_risks": len(semantic.get("bypass_risks") or []),
        "patch": str(patch_path.relative_to(root)),
        "pull_request": pull_request,
        "next_action": "Review the generated pull request and run agenticdome verify." if pull_request else "Review the generated patch, apply it on a branch, then run agenticdome verify.",
        "sdk_version": _installed_sdk_version(),
    }


def run_assist(root: Path) -> Dict[str, Any]:
    """Execute one explicitly approved local-worker task; no discovery IP or source leaves the host."""
    state_path = root / ".agenticdome" / "connect-session.json"
    if not state_path.exists():
        raise SystemExit("No resumable session exists. Run agenticdome connect first.")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    portal = str(state["portal"]).rstrip("/")
    token = str(state["access_token"])
    workload = urllib.parse.quote(str(state["workload_uuid"]), safe="")
    listing = _get(portal + "/api/agentguard/connect/tasks?workload_uuid=" + workload, token)
    tasks = listing.get("tasks") if isinstance(listing.get("tasks"), list) else []
    if not tasks:
        return {"status": "no_approved_tasks", "source_upload": False, "next_action": "Approve a prepared task in the customer portal."}
    task = tasks[0]
    worker_id = hashlib.sha256((str(state["workload_uuid"]) + ":local-cli").encode()).hexdigest()
    claimed = _request(portal + "/api/agentguard/connect/tasks/" + str(task["uuid"]) + "/claim", {"worker_id": worker_id}, token)
    lease = str(claimed["lease_token"])
    action_passport = str(claimed["action_passport"])
    try:
        if task.get("task_type") != "PREPARE_REPOSITORY_CHANGE":
            raise RuntimeError("This approved task type must execute in the portal coordinator, not the local SDK.")
        task_input = task.get("input") if isinstance(task.get("input"), dict) else {}
        connection = str(task_input.get("repository_connection_uuid") or "")
        patch_path = root / ".agenticdome" / "scaffold" / "agenticdome.patch"
        if not connection or not patch_path.exists():
            raise RuntimeError("The approved repository binding or generated review patch is missing. Run agenticdome connect again.")
        pr = _open_review_pr(root, portal, state, connection, patch_path, run_tests=True)
        result = {"pull_request_number": pr.get("number"), "pull_request_url": pr.get("url"), "provider": pr.get("provider"), "branch": "agenticdome/connect-" + str(state["session_uuid"]).split("-")[0], "tests_status": "PASSED"}
        _request(portal + "/api/agentguard/connect/tasks/" + str(task["uuid"]) + "/complete", {"lease_token": lease, "action_passport": action_passport, "result": result}, token)
        return {"status": "completed", "task_uuid": task["uuid"], "pull_request": pr, "source_upload": False, "automatic_merge": False}
    except Exception as exc:
        try:
            _request(portal + "/api/agentguard/connect/tasks/" + str(task["uuid"]) + "/fail", {"lease_token": lease, "action_passport": action_passport, "error": str(exc)[:2000]}, token)
        finally:
            raise
