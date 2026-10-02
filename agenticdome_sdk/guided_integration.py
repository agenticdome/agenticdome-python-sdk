"""Local, review-first integration edits. Source and diffs never leave the workload."""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple


SCHEMA = "agenticdome.guided-integration.v1"
MAX_SOURCE_BYTES = 300_000
MAX_CANDIDATE_FILES = 200
GENERATED_FILES = {
    ".env.agenticdome.example",
    "FRAMEWORK-HOOKS.md",
    "SEMANTIC-REVIEW.md",
}
MCP_GENERATED_FILES = {
    "MCP-SERVER-REGISTRY.json",
    "MCP-PROTECTION.json",
    "MCP-REVIEW.md",
    "agenticdome_mcp_gateway.py",
    "agenticdome_mcp_gateway.ts",
}


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_mode(path: Path) -> Optional[int]:
    return None if os.name == "nt" else path.stat().st_mode & 0o777


def _expected_new_mode() -> Optional[int]:
    return None if os.name == "nt" else 0o644


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _paths(root: Path) -> Tuple[Path, Path, Path]:
    return (
        _target(root, ".agenticdome/scaffold/guided-integration.json"),
        _target(root, ".agenticdome/scaffold/guided-integration.patch"),
        _target(root, ".agenticdome/scaffold/proposed"),
    )


def _history_paths(root: Path, revision: str) -> Tuple[Path, Path]:
    if not isinstance(revision, str) or len(revision) != 12 or any(char not in "0123456789abcdef" for char in revision):
        raise ValueError("The guided integration revision is not valid.")
    return (
        _target(root, ".agenticdome/scaffold/history/" + revision + "/guided-integration.json"),
        _target(root, ".agenticdome/scaffold/history/" + revision + "/guided-integration.patch"),
    )


def _target(root: Path, relative: str) -> Path:
    path = PurePosixPath(relative)
    if not relative or not path.parts or "\\" in relative or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("The proposed file path is not a safe workload-relative path.")
    target = root.joinpath(*path.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError("The proposed file resolves outside the selected workload.")
    for parent in (target, *target.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("A proposed file or parent directory is a symlink.")
    return target


def _atomic_write(path: Path, value: bytes, mode: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".agenticdome-", delete=False) as stream:
            temporary = stream.name
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _write_json(path: Path, value: Dict[str, Any]) -> None:
    _atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"), 0o600)


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, timeout=30, check=False)
    if check and result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "Git could not inspect this workload.").strip()[:500])
    return result


def _git_root(root: Path) -> Optional[Path]:
    result = _git(root, "rev-parse", "--show-toplevel", check=False)
    if result.returncode != 0:
        return None
    git_root = Path(result.stdout.strip()).resolve()
    return git_root if root.resolve().is_relative_to(git_root) else None


def _smolagents_edit(source: str) -> Tuple[Optional[str], List[int]]:
    """Rewrite only direct, single-line returns of a fresh local smolagents agent.

    A function must accept an explicit session_id and construct one CodeAgent or
    ToolCallingAgent locally. Other shapes require human review instead of a
    plausible-looking, potentially bypassable edit.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None, []
    constructors: set[str] = set()
    modules: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "smolagents":
            constructors.update(alias.asname or alias.name for alias in node.names if alias.name in {"CodeAgent", "ToolCallingAgent"})
        elif isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names if alias.name == "smolagents")
    if not constructors and not modules:
        return None, []
    if "AgenticDomeSmolagentsFirewall" in source:
        return None, []

    def is_constructor(value: ast.AST) -> bool:
        if not isinstance(value, ast.Call):
            return False
        call = value.func
        return (isinstance(call, ast.Name) and call.id in constructors) or (
            isinstance(call, ast.Attribute) and call.attr in {"CodeAgent", "ToolCallingAgent"}
            and isinstance(call.value, ast.Name) and call.value.id in modules
        )

    raw = source.encode("utf-8")
    lines = raw.splitlines(keepends=True)

    def offset(line: int, column: int) -> int:
        return sum(len(item) for item in lines[:line - 1]) + column

    replacements: List[Tuple[int, int, bytes]] = []
    changed_lines: List[int] = []
    for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
        parameters = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
        if "session_id" not in {item.arg for item in parameters}:
            continue
        assignments = []
        for index, statement in enumerate(function.body):
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name) and is_constructor(statement.value):
                assignments.append((index, statement.targets[0].id))
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and is_constructor(statement.value):
                assignments.append((index, statement.target.id))
        if len(assignments) != 1:
            continue
        assigned_at, agent_name = assignments[0]
        direct_returns = []
        for index, statement in enumerate(function.body):
            if index <= assigned_at or not isinstance(statement, ast.Return) or not isinstance(statement.value, ast.Call):
                continue
            call = statement.value
            if (isinstance(call.func, ast.Attribute) and call.func.attr == "run"
                    and isinstance(call.func.value, ast.Name) and call.func.value.id == agent_name
                    and len(call.args) == 1 and not call.keywords and call.lineno == call.end_lineno):
                direct_returns.append(call)
        calls_for_agent = [node for node in ast.walk(function)
                           if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                           and node.func.attr == "run" and isinstance(node.func.value, ast.Name)
                           and node.func.value.id == agent_name]
        if len(direct_returns) != 1 or len(calls_for_agent) != 1:
            continue
        if any(isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
               and any(isinstance(name, ast.Name) and name.id in {agent_name, "session_id"}
                       for name in ast.walk(node))
               for node in function.body[assigned_at + 1:] if not isinstance(node, ast.Return)):
            continue
        call = direct_returns[0]
        argument = ast.get_source_segment(source, call.args[0])
        if not argument or "\n" in argument or "\r" in argument:
            continue
        replacement = ("AgenticDomeSmolagentsFirewall().run_agent_securely("
                       + agent_name + ", " + argument + ", session_id=session_id)")
        replacements.append((offset(call.lineno, call.col_offset), offset(call.end_lineno, call.end_col_offset), replacement.encode("utf-8")))
        changed_lines.append(call.lineno)
    if not replacements:
        return None, []

    insertion_line = 0
    body = tree.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, (ast.Str, ast.Constant)) and isinstance(getattr(body[0].value, "value", None), str):
        insertion_line = body[0].end_lineno
        body = body[1:]
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            insertion_line = node.end_lineno
        else:
            break
    if insertion_line == 0:
        for line in lines[:2]:
            if line.startswith(b"#!") or b"coding:" in line or b"coding=" in line:
                insertion_line += 1
            else:
                break
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    import_bytes = b"from agenticdome_sdk.smolagents import AgenticDomeSmolagentsFirewall" + newline
    replacements.append((sum(len(item) for item in lines[:insertion_line]), sum(len(item) for item in lines[:insertion_line]), import_bytes))
    for start, end, value in sorted(replacements, key=lambda item: item[0], reverse=True):
        raw = raw[:start] + value + raw[end:]
    try:
        ast.parse(raw.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return None, []
    return raw.decode("utf-8"), changed_lines


def _candidate_paths(plan: Dict[str, Any]) -> Tuple[List[str], bool]:
    points = list(plan.get("candidate_boundaries") or [])
    paths = sorted({str(item.get("path", "")) for item in points
                    if isinstance(item, dict) and item.get("boundary") in {"prompt_ingress", "tool_execution"}
                    and str(item.get("path", "")).endswith(".py")})
    return paths[:MAX_CANDIDATE_FILES], len(paths) > MAX_CANDIDATE_FILES


def _local_smolagents_paths(root: Path) -> Tuple[List[str], bool]:
    """Find exact local adapter patterns missed by broad boundary heuristics.

    This never sends source to Copilot. It walks one workload, prunes generated
    and dependency trees, and reads at most 5,000 small Python files.
    """
    from .onboarding_cli import IGNORED_DIRECTORIES, SENSITIVE_FILE_PATTERN, SENSITIVE_FILE_SUFFIXES

    found: List[str] = []
    inspected = 0
    capped = False
    for directory, subdirs, filenames in os.walk(root, followlinks=False):
        subdirs[:] = sorted(name for name in subdirs if name not in IGNORED_DIRECTORIES
                            and not (Path(directory) / name).is_symlink())
        for name in sorted(filenames):
            if name.endswith(".py") and not SENSITIVE_FILE_PATTERN.search(name) and Path(name).suffix not in SENSITIVE_FILE_SUFFIXES:
                inspected += 1
                if inspected > 5_000:
                    capped = True
                    break
                path = Path(directory) / name
                try:
                    if path.is_symlink() or path.stat().st_size > MAX_SOURCE_BYTES:
                        continue
                    contents = path.read_bytes()
                except OSError:
                    continue
                if b"CodeAgent" not in contents and b"ToolCallingAgent" not in contents:
                    continue
                if b".run(" not in contents and b".run (" not in contents:
                    continue
                found.append(path.relative_to(root).as_posix())
                if len(found) >= MAX_CANDIDATE_FILES:
                    capped = True
                    break
        if capped:
            break
    return found, capped


def _manual_note(path: str, reason: str) -> Dict[str, str]:
    return {"path": path, "reason": reason}


def _select_target(plan: Dict[str, Any], requested: str) -> Dict[str, Any]:
    if requested not in {"auto", "application", "mcp"}:
        raise ValueError("Choose auto, application or mcp for the guided integration target.")
    detected = set(plan.get("detected_frameworks") or plan.get("frameworks") or [])
    mcp_detected = (plan.get("mcp_protection") or {}).get("detected") is True
    if requested == "auto" and detected == {"openclaw"}:
        raise RuntimeError("This is an OpenClaw workload. Run agenticdome openclaw protect to check the native plugin and hooks; a generic source patch is not the right path.")
    selected = requested if requested != "auto" else ("mcp" if detected == {"mcp"} and mcp_detected else "application")
    secondary = ["mcp"] if selected == "application" and mcp_detected else []
    scope_warning = (
        "Many framework families were found in this selected tree. Confirm it is one deployable workload; otherwise run from the smaller application or package root."
        if len(detected) >= 5 else None
    )
    return {
        "requested": requested,
        "selected": selected,
        "detected_frameworks": sorted(detected),
        "secondary_targets": secondary,
        "scope_warning": scope_warning,
        "reason": (
            "Explicit customer selection." if requested != "auto" else
            "Only an MCP workload was detected; prepare MCP forwarder review files." if selected == "mcp" else
            "Mixed application and MCP signals; assess the application first and review the MCP forwarder separately." if mcp_detected else
            "Application workload detected; evaluate its certified source-edit patterns and existing SDK hooks."
        ),
    }


def preview(root: Path, plan: Optional[Dict[str, Any]] = None, *, target: str = "auto") -> Dict[str, Any]:
    from .onboarding_cli import _load_json, _scaffold_files, create_scaffold, integration_plan

    root = root.resolve()
    manifest_path, patch_path, proposed_root = _paths(root)
    plan = plan or integration_plan(root)
    workload_detection = _select_target(plan, target)
    integration_target = workload_detection["selected"]
    mcp_plan = plan.get("mcp_protection")
    if integration_target == "mcp" and (not isinstance(mcp_plan, dict) or mcp_plan.get("detected") is not True):
        raise RuntimeError("No MCP boundary was found in the current plan. Run agenticdome mcp protect from the MCP workload first.")
    prior_applied_revision = None
    if manifest_path.exists():
        prior = _load_manifest(root)
        if prior.get("state") == "applying":
            raise RuntimeError("A previous integration apply was interrupted. Run integrate undo before creating another preview.")
        if prior.get("state") == "applied":
            prior_applied_revision = prior["approval_code"]
            history_manifest, history_patch = _history_paths(root, prior_applied_revision)
            if history_patch.exists() and not history_manifest.exists() and _sha(history_patch.read_bytes()) == prior["patch_sha256"]:
                _write_json(history_manifest, prior)
            if history_manifest.exists() and not history_patch.exists():
                try:
                    archived_record = json.loads(history_manifest.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    archived_record = None
                if archived_record == prior:
                    _atomic_write(history_patch, patch_path.read_bytes(), 0o600)
            if history_manifest.exists() or history_patch.exists():
                try:
                    archived = _load_manifest(root, revision=prior_applied_revision)
                except (RuntimeError, ValueError) as exc:
                    raise RuntimeError("The previous approved revision has conflicting local history. Review it before creating another preview.") from exc
                if archived != prior:
                    raise RuntimeError("The previous approved revision conflicts with its local history. Review it before creating another preview.")
            else:
                _atomic_write(history_patch, patch_path.read_bytes(), 0o600)
                _write_json(history_manifest, prior)
    create_scaffold(root, plan=plan)
    config = _load_json(root / ".agenticdome" / "config.json")
    generated = _scaffold_files({**config, "frameworks": plan.get("frameworks", config.get("frameworks", []))}, plan)
    existing = plan.get("existing_integration") if isinstance(plan.get("existing_integration"), dict) else {}
    framework_reconciliation = plan.get("framework_reconciliation") if isinstance(plan.get("framework_reconciliation"), dict) else {}
    existing_surfaces = existing.get("surface_call_candidates") if isinstance(existing.get("surface_call_candidates"), dict) else {}
    existing_state = str(existing.get("state", "not_assessed"))
    semantic_gate = plan.get("semantic_gate") if isinstance(plan.get("semantic_gate"), dict) else {}
    changes: List[Dict[str, Any]] = []
    patch_parts: List[str] = []
    manual: List[Dict[str, str]] = []

    review_files = GENERATED_FILES | (MCP_GENERATED_FILES if integration_target == "mcp" else set())
    for relative in sorted(review_files.intersection(generated)):
        try:
            target = _target(root, relative)
        except ValueError as exc:
            manual.append(_manual_note(relative, str(exc)))
            continue
        value = generated[relative].encode("utf-8")
        if target.exists():
            if target.is_file() and _sha(target.read_bytes()) == _sha(value):
                continue
            manual.append(_manual_note(relative, "An existing file uses this name; review it manually. It will not be overwritten."))
            continue
        _atomic_write(_target(proposed_root, relative), value, 0o600)
        patch_parts.extend(difflib.unified_diff([], value.decode("utf-8").splitlines(keepends=True),
                                                fromfile="/dev/null", tofile="b/" + relative))
        changes.append({"path": relative, "kind": "added", "before_sha256": None,
                        "after_sha256": _sha(value), "before_mode": None, "after_mode": _expected_new_mode(),
                        "summary": "Add a generated MCP integration review file; forwarding is not connected."
                        if relative in MCP_GENERATED_FILES else "Add a generated integration review file."})

    from .framework_edits import propose_framework_edits

    auto_recipe_hooks = {
        "custom-python": "guardrail_validate",
        "crewai": "attach", "pydanticai": "install_native_hooks", "langgraph": "as_langchain_middleware",
        "google-adk": "build_callback_kwargs", "claude": "install_on_options", "agno": "attach_firewall", "llamaindex": "to_function_tool", "openai-agents": "wrap_tool_handler", "smolagents": "run_agent_securely",
    }
    ready_frameworks = {
        item["framework"] for item in plan.get("framework_hook_plans", []) if isinstance(item, dict)
        and item.get("framework") in auto_recipe_hooks and item.get("status") == "ready_for_attachment"
        and auto_recipe_hooks[item["framework"]] in (item.get("adapter") or {}).get("attachment_methods", [])
    } if integration_target == "application" else set()
    binding_ready = (plan.get("hook_catalog") or {}).get("sidecar_binding", {}).get("verified") is True
    paths, capped = _candidate_paths(plan)
    if ready_frameworks and binding_ready:
        evidence_paths = {
            str(path) for item in plan.get("framework_hook_plans", []) if isinstance(item, dict)
            and item.get("framework") in ready_frameworks
            for path in item.get("detection_evidence_files", [])
            if isinstance(path, str) and path.endswith(".py")
        }
        local_paths, local_capped = _local_smolagents_paths(root) if "smolagents" in ready_frameworks else ([], False)
        combined_paths = sorted(set(paths).union(local_paths).union(evidence_paths))
        paths = combined_paths[:MAX_CANDIDATE_FILES]
        capped = capped or local_capped or len(combined_paths) > MAX_CANDIDATE_FILES
    if capped:
        manual.append(_manual_note("workload", "The bounded local Python candidate scan reached its 200-candidate or 5,000-file limit; remaining files were not auto-edited."))
    if existing_state in {"sdk_calls_found", "wrapper_calls_found"}:
        manual.append(_manual_note("existing-sdk-hooks", "Customer-written SDK call sites were found. This is a static signal, not proof that every tool path passes through them or that failures stop execution. Review the listed call sites and test the real executor."))
    elif existing_state == "sdk_imports_only":
        manual.append(_manual_note("existing-sdk-hooks", "An AgenticDome SDK import was found, but no supported call site was observed. An import alone does not protect an action."))
    if framework_reconciliation.get("included_from_current_scan"):
        manual.append(_manual_note("framework-drift", "The current scan detected additional frameworks and included their certified hook contracts in this preview. The saved local config was not changed; review the framework list and package versions before attaching hooks."))
    if any(item.get("boundary") == "delegation" for item in plan.get("candidate_boundaries", []) if isinstance(item, dict)) and not existing_surfaces.get("a2a", 0):
        manual.append(_manual_note("a2a-handoff", "Delegation-like source patterns were found but no Python A2A authorization or receiving-agent verification call was observed. Review the actual framework handoff path; a native wrapper may provide the calls internally. Test both handoff authorization and bound-token verification at the receiving executor."))
    mcp_topology = plan.get("mcp_protection") if isinstance(plan.get("mcp_protection"), dict) else {}
    if integration_target == "application" and mcp_topology.get("detected") is True and not existing_surfaces.get("mcp", 0):
        manual.append(_manual_note("mcp-routing", "MCP use was detected but no Python MCP firewall call was observed in this workload. Identify the real client, host or gateway and run the separate MCP review path. A TypeScript or external gateway is not assessed by this Python call-site check."))
    if integration_target == "mcp":
        manual.append(_manual_note("mcp-forwarding", "Generated MCP files are only preparation. Attach the wrapper to each real forwarder, supply trusted identity and purpose, reroute clients, and test allowed/blocked requests. No traffic is protected by copying files alone."))
    elif not ready_frameworks or not binding_ready:
        manual.append(_manual_note("workload", "An existing-source edit requires a verified sidecar catalog and a certified recipe for the detected framework/package version. Review the framework hook plan and attach unsupported paths manually."))
    else:
        existing_paths = {item.get("path") for item in existing.get("observations", []) if isinstance(item, dict)}
        for relative in paths:
            if relative in existing_paths:
                manual.append(_manual_note(relative, "Customer-written AgenticDome calls already exist in this file. Review their placement and fail-closed behavior; no overlapping automatic rewrite was proposed."))
                continue
            try:
                target = _target(root, relative)
            except ValueError as exc:
                manual.append(_manual_note(relative, str(exc)))
                continue
            try:
                if not target.is_file() or target.stat().st_size > MAX_SOURCE_BYTES:
                    manual.append(_manual_note(relative, "Not a readable Python file within the 300 KB local edit limit."))
                    continue
                before = target.read_bytes()
                original_text = before.decode("utf-8")
                after_text = original_text
                recipes = []
                if "smolagents" in ready_frameworks:
                    smol_text, smol_lines = _smolagents_edit(after_text)
                    if smol_text:
                        after_text = smol_text
                        recipes.append(("smolagents", "run_agent_securely", smol_lines))
                framework_text, framework_edits = propose_framework_edits(after_text, ready_frameworks)
                if framework_text:
                    after_text = framework_text
                    recipes.extend((item.framework, item.attachment, [item.line]) for item in framework_edits)
            except (OSError, UnicodeDecodeError):
                manual.append(_manual_note(relative, "Source could not be read as UTF-8; no edit proposed."))
                continue
            if not recipes:
                manual.append(_manual_note(relative, "No unambiguous certified attachment pattern was found in this file. The framework hook plan names the supported method; review the actual construction and execution path manually."))
                continue
            after = after_text.encode("utf-8")
            if after == before:
                continue
            _atomic_write(_target(proposed_root, relative), after, 0o600)
            patch_parts.extend(difflib.unified_diff(before.decode("utf-8").splitlines(keepends=True),
                                                    after_text.splitlines(keepends=True),
                                                    fromfile="a/" + relative, tofile="b/" + relative))
            changes.append({"path": relative, "kind": "modified", "before_sha256": _sha(before),
                            "after_sha256": _sha(after), "before_mode": _file_mode(target),
                            "after_mode": _file_mode(target),
                            "summary": "Propose catalog-qualified " + ", ".join(sorted({item[0] for item in recipes})) + " hooks at reviewed construction or execution sites; exercise the real route before claiming protection.",
                            "lines": sorted({line for _, _, lines in recipes for line in lines}),
                            "adapters": [framework + "." + method for framework, method, _ in recipes]})

    if any(item["kind"] == "modified" for item in changes):
        manual.append(_manual_note("deployment", "Add the certified AgenticDome SDK to the actual application deployment and supply a genuine stable session_id and Runtime / SDK key. Installing the CLI in a separate virtual environment is not enough."))

    summary_path = "AGENTICDOME-CHANGES.md"
    summary_exists = _target(root, summary_path).exists()
    if summary_exists:
        manual.append(_manual_note(summary_path, "An existing change record uses this name; it will not be overwritten. The current proposal summary remains under .agenticdome/scaffold/proposed."))
    summary_lines = [
        "# AgenticDome proposed changes", "",
        "This is a local proposal, not proof that production actions are protected.", "",
        "## Workload and existing integration", "",
        "- Selected path: `" + integration_target + "` (" + workload_detection["reason"] + ")",
        "- Detected frameworks: " + (", ".join(workload_detection["detected_frameworks"]) or "none"),
        "- Frameworks planned now: " + (", ".join(plan.get("frameworks", [])) or "none"),
        "- Newly detected since local config: " + (", ".join(framework_reconciliation.get("included_from_current_scan", [])) or "none"),
        "- Existing SDK wiring: `" + existing_state + "` (static candidates, not runtime proof)",
        "- Observed Python call candidates: framework hooks " + str(existing.get("framework_hook_call_candidates", 0))
        + ", A2A " + str(existing.get("a2a_call_candidates", 0))
        + ", MCP " + str(existing_surfaces.get("mcp", 0))
        + " (categories may overlap; no customer action was exercised)",
        "- Action-required semantic findings: " + str(semantic_gate.get("action_required", "not assessed")),
        "- Review-required semantic findings: " + str(semantic_gate.get("review_required", "not assessed")),
        "",
        "## Framework hooks to attach or verify", "",
    ]
    for recommendation in plan.get("hook_recommendations", []):
        if not isinstance(recommendation, dict):
            continue
        summary_lines.append(
            "- `" + str(recommendation.get("framework")) + "`: `" + str(recommendation.get("method")) +
            "` — " + str(recommendation.get("state")) + ". " + str(recommendation.get("reason"))
        )
    summary_lines.extend(["", "## Conditional hooks by action surface", ""])
    for recommendation in plan.get("surface_hook_recommendations", []):
        if not isinstance(recommendation, dict):
            continue
        summary_lines.append(
            "- `" + str(recommendation.get("framework")) + "` / `" + str(recommendation.get("surface")) +
            "`: `" + str(recommendation.get("method")) + "` — " + str(recommendation.get("state")) +
            ("; candidate boundary found. " if recommendation.get("surface_observed") else "; conditional, surface not confirmed. ") +
            str(recommendation.get("guidance"))
        )
    summary_lines.extend([
        "", "Static observation is not proof of attachment. Review each actual tool, delegation and output route.", "",
        "## Exact file summary", "",
    ])
    if workload_detection["secondary_targets"]:
        summary_lines.insert(summary_lines.index("## Exact file summary"), "- Also assess MCP routing: `agenticdome integrate preview --target mcp` (separate proposal).")
    if workload_detection["scope_warning"]:
        summary_lines.insert(summary_lines.index("## Exact file summary"), "- Scope caution: " + workload_detection["scope_warning"])
    for item in changes:
        summary_lines.append("- `" + item["path"] + "` — " + item["kind"] + ": " + item["summary"])
        summary_lines.append("  - Before SHA-256: `" + (item["before_sha256"] or "file absent") + "`; after SHA-256: `" + item["after_sha256"] + "`")
        summary_lines.append("  - Mode: `" + (oct(item["before_mode"]) if item["before_mode"] is not None else "file absent or platform-managed") + "` → `" + (oct(item["after_mode"]) if item["after_mode"] is not None else "platform-managed") + "`")
        if item.get("lines"):
            summary_lines.append("  - Original call line(s): " + ", ".join(str(line) for line in item["lines"]))
    summary_lines.extend(["", "## Still requires review", ""])
    summary_lines.extend("- `" + item["path"] + "`: " + item["reason"] for item in manual)
    if not manual:
        summary_lines.append("- No additional static candidate was flagged; runtime and workload tests are still required.")
    summary_lines.extend(["", "## Before relying on this integration", "",
                          "Provision a separate Runtime / SDK key to the real application process through your secret manager.",
                          "Review the exact diff and framework hook report; run application tests and `agenticdome mcp verify`." if integration_target == "mcp"
                          else "Review the exact diff and framework hook report; run application tests and `agenticdome verify --run-tests`.",
                          "Exercise an allowed and blocked action through the actual connected tool boundary.",
                          "For an application tool, instrument the actual test handler with `ExecutionSpy`, call `spy.assert_calls(0)` for a blocked fixture, then run `agenticdome verify-action --tool YOUR_TOOL --expect-verdict BLOCKED --expect-executed no -- pytest -q tests/YOUR_SAFE_TEST.py`. Repeat with an allowed fixture and one handler call. See `docs/customer-onboarding.md`; no production action should be used.",
                          "The optional CI and generic wrapper templates remain under `.agenticdome/scaffold`; they are not applied automatically.", ""])
    summary_bytes = "\n".join(summary_lines).encode("utf-8")
    _atomic_write(_target(proposed_root, summary_path), summary_bytes, 0o600)
    if not summary_exists:
        patch_parts.extend(difflib.unified_diff([], summary_bytes.decode("utf-8").splitlines(keepends=True),
                                                fromfile="/dev/null", tofile="b/" + summary_path))
        changes.append({"path": summary_path, "kind": "added", "before_sha256": None,
                        "after_sha256": _sha(summary_bytes), "before_mode": None, "after_mode": _expected_new_mode(),
                        "summary": "Add an exact, reviewable change record to the repository."})

    patch = "".join(patch_parts).encode("utf-8")
    _atomic_write(patch_path, patch, 0o600)
    digest = _sha(patch)
    source_edits = sum(item["kind"] == "modified" for item in changes)
    mcp_review_files = integration_target == "mcp" and any(item["path"] in MCP_GENERATED_FILES for item in changes)
    recommended_path = (
        {"kind": "review_source_edit", "headline": "Review one exact source edit", "may_apply": True,
         "instruction": "Open the patch and change summary. Apply only if the edit fits your real execution path; then test an allowed and blocked action."}
        if source_edits else
        {"kind": "review_mcp_files", "headline": "Attach the MCP forwarder", "may_apply": True,
         "instruction": "Review the generated MCP files before adding them on a branch. You must still connect the wrapper and reroute clients."}
        if mcp_review_files else
        {"kind": "validate_existing_hooks", "headline": "Check your existing AgenticDome calls", "may_apply": False,
         "instruction": "No source edit is offered. Follow the listed call sites through the real executor, close bypasses and test fail-closed behavior."}
        if existing_state in {"sdk_calls_found", "wrapper_calls_found"} else
        {"kind": "manual_integration", "headline": "Connect the suggested hooks manually", "may_apply": False,
         "instruction": "No certified automatic source edit was found. Use the framework hook plan and semantic review to attach protection at the real action boundary."}
    )
    result: Dict[str, Any] = {
        "schema": SCHEMA, "state": "preview", "source_upload": False,
        "integration_target": integration_target,
        "workload_detection": workload_detection,
        "framework_reconciliation": framework_reconciliation,
        "hook_recommendations": plan.get("hook_recommendations", []),
        "surface_hook_recommendations": plan.get("surface_hook_recommendations", []),
        "existing_integration": existing,
        "semantic_gap_counts": {
            "action_required": semantic_gate.get("action_required"),
            "review_required": semantic_gate.get("review_required"),
        },
        "created_at": _now(), "plan_sha256": _sha(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")),
        "patch_sha256": digest, "approval_code": digest[:12],
        "patch": ".agenticdome/scaffold/guided-integration.patch",
        "prior_applied_revision": prior_applied_revision,
        "changes": changes, "manual_review": manual,
        "source_edits": source_edits,
        "recommended_path": recommended_path,
        "next_action": ("Review the exact diff and change summary. If approved, run agenticdome integrate apply. "
                        "This installs review files only; connect the real MCP forwarder manually and run agenticdome mcp verify before claiming protection."
                        if integration_target == "mcp" and any(item["path"] in MCP_GENERATED_FILES for item in changes)
                        else "Review the local patch and exact file summary, then run agenticdome integrate apply. "
                        "Protection is not proven until the real workload and blocked-tool tests pass."
                        if any(item["kind"] == "modified" for item in changes)
                        else "Existing SDK call sites were found, but no certified existing-source edit is available. Review their real call paths and SEMANTIC-REVIEW.md, close the listed gaps, and run workload and live blocked-tool tests. Do not claim complete protection from this preview."
                        if existing_state in {"sdk_calls_found", "wrapper_calls_found"}
                        else "No safe existing-source edit was identified. Review SEMANTIC-REVIEW.md and integrate manually; do not claim this workload is protected."),
    }
    _write_json(manifest_path, result)
    return result


def _load_manifest(root: Path, revision: Optional[str] = None) -> Dict[str, Any]:
    if revision is None:
        manifest_path, patch_path, _ = _paths(root)
    else:
        manifest_path, patch_path = _history_paths(root, revision)
    if not manifest_path.is_file():
        raise RuntimeError("No guided integration record exists for this revision. Run agenticdome integrate preview first or inspect local history.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("The local guided-integration record is unreadable; generate a new preview.") from exc
    if manifest.get("schema") != SCHEMA or manifest.get("source_upload") is not False:
        raise RuntimeError("The local guided-integration record is not recognized.")
    if not patch_path.is_file() or _sha(patch_path.read_bytes()) != manifest.get("patch_sha256"):
        raise RuntimeError("The proposed patch changed after preview. Generate a new preview before applying.")
    return manifest


def _verified_proposals(root: Path, manifest: Dict[str, Any], applied: bool = False) -> List[Tuple[Path, Path, Dict[str, Any]]]:
    _, _, proposed_root = _paths(root)
    verified = []
    for item in manifest.get("changes", []):
        relative = item.get("path")
        if not isinstance(relative, str) or item.get("kind") not in {"added", "modified"}:
            raise RuntimeError("The guided-integration record contains an invalid change.")
        target = _target(root, relative)
        proposed = _target(proposed_root, relative)
        if not proposed.is_file() or _sha(proposed.read_bytes()) != item.get("after_sha256"):
            raise RuntimeError("A proposed file changed after preview; generate a new preview.")
        if applied:
            if not target.is_file() or _sha(target.read_bytes()) != item.get("after_sha256") or _file_mode(target) != item.get("after_mode"):
                raise RuntimeError("An applied file changed since approval; undo is unsafe. Review the Git diff manually.")
        elif item["kind"] == "added":
            if target.exists():
                raise RuntimeError("A proposed new file now exists. Review it and generate a new preview.")
        elif not target.is_file() or _sha(target.read_bytes()) != item.get("before_sha256") or _file_mode(target) != item.get("before_mode"):
            raise RuntimeError("Existing source changed after preview. No files were updated; generate a fresh preview.")
        verified.append((target, proposed, item))
    return verified


def apply(root: Path, approval_code: Optional[str] = None) -> Dict[str, Any]:
    root = root.resolve()
    manifest_path, _, _ = _paths(root)
    manifest = _load_manifest(root)
    if manifest.get("state") != "preview":
        raise RuntimeError("This preview has already been applied or requires recovery.")
    mcp_review_files = manifest.get("integration_target") == "mcp" and any(
        item.get("kind") == "added" and item.get("path") in MCP_GENERATED_FILES
        for item in manifest.get("changes", [])
    )
    if int(manifest.get("source_edits", 0)) < 1 and not mcp_review_files:
        raise RuntimeError("No supported existing-source edit is available. Review the manual findings instead of applying generated files alone.")
    expected = manifest["approval_code"]
    if approval_code is None:
        if not sys.stdin.isatty():
            raise RuntimeError("Approval is required. Review the patch, then rerun with --approve " + expected + ".")
        approval_code = input("Type approval code " + expected + " to apply these local changes: ").strip()
    if approval_code != expected:
        raise RuntimeError("Approval code did not match the reviewed patch. Nothing was changed.")
    verified = _verified_proposals(root, manifest)
    git_root = _git_root(root)
    if git_root is None:
        raise RuntimeError("Automatic apply requires a Git working tree. The preview remains available for manual review.")
    # Preview refreshes .agenticdome artifacts, which customers may choose to
    # track. Those generated changes must not make the reviewed source edit
    # impossible to apply; all other tracked workload changes still block.
    if _git(root, "status", "--porcelain", "--untracked-files=no", "--", ".", ":(exclude).agenticdome").stdout.strip():
        raise RuntimeError("Tracked workload source changes exist. Commit or stash them before applying the guided integration.")
    for _, _, item in verified:
        if item["kind"] == "modified" and _git(root, "ls-files", "--error-unmatch", "--", item["path"], check=False).returncode != 0:
            raise RuntimeError("An existing source file is not Git-tracked. Track it before automatic apply, or review the patch manually.")
    branch = "agenticdome/integrate-" + manifest["patch_sha256"][:8] + "-" + uuid.uuid4().hex[:6]
    if _git(git_root, "show-ref", "--verify", "--quiet", "refs/heads/" + branch, check=False).returncode == 0:
        raise RuntimeError("The review branch already exists. Inspect it or create a new preview after undoing the earlier application.")
    _git(git_root, "switch", "-c", branch)
    backup_root = _target(root, ".agenticdome/scaffold/backups/" + expected)
    written: List[Tuple[Path, Dict[str, Any]]] = []
    manifest["state"] = "applying"
    manifest["branch"] = branch
    _write_json(manifest_path, manifest)
    try:
        for target, proposed, item in verified:
            if item["kind"] == "modified":
                backup = _target(backup_root, item["path"])
                _atomic_write(backup, target.read_bytes(), 0o600)
            current = target.read_bytes() if target.is_file() else None
            if (current is None and item["kind"] != "added") or (current is not None and (
                _sha(current) != item.get("before_sha256") or _file_mode(target) != item.get("before_mode")
            )):
                raise RuntimeError("A file changed during apply; the completed writes will be rolled back.")
            proposed_bytes = proposed.read_bytes()
            if _sha(proposed_bytes) != item["after_sha256"]:
                raise RuntimeError("A proposed file changed during apply; the completed writes will be rolled back.")
            mode = item["after_mode"]
            _atomic_write(target, proposed_bytes, mode)
            written.append((target, item))
    except Exception:
        for target, item in reversed(written):
            if item["kind"] == "added":
                if target.is_file() and _sha(target.read_bytes()) == item["after_sha256"]:
                    target.unlink()
            else:
                backup = _target(backup_root, item["path"])
                if backup.is_file() and target.is_file() and _sha(target.read_bytes()) == item["after_sha256"]:
                    _atomic_write(target, backup.read_bytes(), item["before_mode"])
        manifest["state"] = "apply_failed_rolled_back"
        _write_json(manifest_path, manifest)
        raise
    manifest["state"] = "applied"
    manifest["applied_at"] = _now()
    manifest["recommended_path"] = {
        "kind": "verify_applied_change", "headline": "Test the changed execution path", "may_apply": False,
        "instruction": "The local branch contains the approved change. Run workload tests and send an allowed and blocked action through the actual connected boundary.",
    }
    manifest["next_action"] = (
        "MCP review files were added on a local Git branch. No existing forwarder was rewired and no traffic is protected yet. "
        "Attach the wrapper to the real request/response path, reroute clients, run workload tests and agenticdome mcp verify."
        if manifest.get("integration_target") == "mcp" else
        "Inspect the Git diff, run workload tests and agenticdome verify --run-tests, then review the real blocked-tool path. The edit alone is not protection proof."
    )
    _write_json(manifest_path, manifest)
    return manifest


def undo(root: Path, revision: Optional[str] = None) -> Dict[str, Any]:
    root = root.resolve()
    manifest_path = _paths(root)[0] if revision is None else _history_paths(root, revision)[0]
    manifest = _load_manifest(root, revision=revision)
    if manifest.get("state") not in {"applied", "applying"}:
        raise RuntimeError("There is no applied guided integration to undo.")
    backup_root = _target(root, ".agenticdome/scaffold/backups/" + manifest["approval_code"])
    actions: List[Tuple[Path, Dict[str, Any], Optional[bytes]]] = []
    for item in manifest.get("changes", []):
        target = _target(root, item["path"])
        if item["kind"] == "added":
            if target.exists() and (not target.is_file() or _sha(target.read_bytes()) != item["after_sha256"] or _file_mode(target) != item["after_mode"]):
                raise RuntimeError("An applied file changed since approval; undo is unsafe. Review the Git diff manually.")
            if target.exists():
                actions.append((target, item, None))
        else:
            if not target.is_file():
                raise RuntimeError("An edited source file is missing; restore it from Git manually.")
            current_hash = _sha(target.read_bytes())
            if current_hash not in {item["before_sha256"], item["after_sha256"]} or _file_mode(target) != item["after_mode"]:
                raise RuntimeError("An applied file changed since approval; undo is unsafe. Review the Git diff manually.")
            if current_hash == item["after_sha256"]:
                backup = _target(backup_root, item["path"])
                if not backup.is_file() or _sha(backup.read_bytes()) != item["before_sha256"]:
                    raise RuntimeError("A local backup is missing or changed. Stop and restore from Git manually.")
                actions.append((target, item, backup.read_bytes()))
    for target, item, backup in reversed(actions):
        if item["kind"] == "added":
            target.unlink()
        elif backup is not None:
            _atomic_write(target, backup, item["before_mode"])
    manifest["state"] = "undone"
    manifest["undone_at"] = _now()
    manifest["recommended_path"] = {
        "kind": "preview_again", "headline": "Preview again when ready", "may_apply": False,
        "instruction": "The local edit was restored. Reassess the workload and review a new exact diff before any further change.",
    }
    manifest["next_action"] = "Local edits were restored. The review branch remains available; no Git reset or delete was performed."
    _write_json(manifest_path, manifest)
    return manifest


def record_verification(root: Path, result: Dict[str, Any]) -> None:
    manifest_path, _, _ = _paths(root)
    if not manifest_path.is_file():
        return
    try:
        manifest = _load_manifest(root)
    except RuntimeError:
        return
    if manifest.get("state") != "applied":
        return
    manifest["verification"] = {
        "recorded_at": _now(),
        "ready": result.get("ready") is True,
        "report_sha256": _sha(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")),
    }
    _write_json(manifest_path, manifest)


def export_summary(root: Path) -> Optional[Dict[str, Any]]:
    """Return a bounded source-free change ledger for onboarding evidence."""
    from .onboarding_cli import FRAMEWORK_MARKERS, _PRIMARY_HOOKS, _SURFACE_HOOKS

    manifest_path, _, _ = _paths(root.resolve())
    if not manifest_path.is_file():
        return None
    manifest = _load_manifest(root.resolve())
    recommendation = manifest.get("recommended_path")
    path_kind = recommendation.get("kind") if isinstance(recommendation, dict) else None
    if path_kind not in {
        "review_source_edit", "review_mcp_files", "validate_existing_hooks",
        "manual_integration", "verify_applied_change", "preview_again",
    }:
        path_kind = None
    raw_reconciliation = manifest.get("framework_reconciliation")
    reconciliation = raw_reconciliation if isinstance(raw_reconciliation, dict) else {}
    known_frameworks = set(FRAMEWORK_MARKERS) | {"typescript"}

    def framework_list(key: str) -> List[str]:
        values = reconciliation.get(key)
        if not isinstance(values, list):
            return []
        return list(dict.fromkeys(value for value in values[:30] if isinstance(value, str) and value in known_frameworks))

    hook_recommendations = []
    for item in manifest.get("hook_recommendations", [])[:30] if isinstance(manifest.get("hook_recommendations"), list) else []:
        if not isinstance(item, dict):
            continue
        framework = item.get("framework")
        if framework not in _PRIMARY_HOOKS or item.get("method") != _PRIMARY_HOOKS[framework][0]:
            continue
        hook_recommendations.append({
            "framework": framework,
            "method": item["method"],
            "state": item.get("state") if item.get("state") in {"call_candidate_observed", "not_observed_in_selected_source"} else "not_observed_in_selected_source",
            "runtime_proof": "not_assessed",
        })

    surface_recommendations = []
    for item in manifest.get("surface_hook_recommendations", [])[:60] if isinstance(manifest.get("surface_hook_recommendations"), list) else []:
        if not isinstance(item, dict):
            continue
        framework = item.get("framework")
        allowed = {surface: methods for surface, methods, _ in _SURFACE_HOOKS.get(framework, [])}
        surface = item.get("surface")
        if surface not in allowed or item.get("method") != allowed[surface][0]:
            continue
        surface_recommendations.append({
            "framework": framework, "surface": surface, "method": item["method"],
            "state": item.get("state") if item.get("state") in {"call_candidate_observed", "not_observed_in_selected_source"} else "not_observed_in_selected_source",
            "surface_observed": item.get("surface_observed") is True,
            "runtime_proof": "not_assessed",
        })

    return {
        "schema": SCHEMA,
        "state": manifest.get("state"),
        "integration_target": manifest.get("integration_target", "application"),
        "source_upload": False,
        "patch_sha256": manifest.get("patch_sha256"),
        "branch": manifest.get("branch"),
        "prior_applied_revision": manifest.get("prior_applied_revision"),
        "source_edits": manifest.get("source_edits", 0),
        "manual_review_count": len(manifest.get("manual_review", [])),
        "recommended_path": {"kind": path_kind, "may_apply": path_kind in {"review_source_edit", "review_mcp_files"}},
        "framework_reconciliation": {
            "planned": framework_list("planned"),
            "included_from_current_scan": framework_list("included_from_current_scan"),
            "configured_without_current_evidence": framework_list("configured_without_current_evidence"),
            "config_changed": False,
        },
        "hook_recommendations": hook_recommendations,
        "surface_hook_recommendations": surface_recommendations,
        "changes": [
            {key: item.get(key) for key in ("path", "kind", "before_sha256", "after_sha256", "before_mode", "after_mode", "summary")}
            for item in manifest.get("changes", [])[:250]
        ],
        "change_list_complete": len(manifest.get("changes", [])) <= 250,
    }
