"""Bounded, source-free observations of customer-written AgenticDome hooks.

These are discovery signals, not control-flow proof or runtime verification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, Sequence

from .hook_catalog import FRAMEWORK_HOOK_CATALOG, harness_compatibility_manifest

# Attachment methods are taken from the same versioned contract used by the
# SDK Harness. This keeps framework discovery in step with published adapters.
CATALOG_METHODS = {
    method
    for contract in FRAMEWORK_HOOK_CATALOG.values()
    if contract.get("language") == "python"
    for method in contract.get("attachment_methods", [])
}
CATALOG_METHODS.update(
    method
    for contract in harness_compatibility_manifest().values()
    for method in contract.get("firewall_methods", [])
)
# The README also documents these public adapter methods. They are implemented
# in the SDK but are not all named in the narrow attachment/smoke contract.
README_METHODS = {
    "attach_to_agent", "graph_transition_node", "security_route",
    "run_agent_stream_securely", "converse_stream_securely",
    "invoke_model_securely", "invoke_model_with_response_stream_securely",
    "invoke_agent_securely", "wrap_retriever", "create_node_postprocessor",
    "create_callback_handler",
    "guarded_tool_executor",
}
FRAMEWORK_METHODS = (CATALOG_METHODS | README_METHODS) - {"guardrail_validate", "mesh_validate"}
A2A_METHODS = {
    "a2a_action_call", "a2a_authorize_tool", "a2a_verify_decision_token",
    "a2a_verify_decision_token_rpc", "authorize_manager_handoff",
    "verify_delegated_execution", "verify_specialist_execution",
    "wrap_delegated_tool_handler", "secure_delegated_tool",
    "verify_decision_token_if_present",
}
MCP_METHODS = {
    "forward_with_firewall", "preflight_request", "authorize_mcp_tool_call",
    "authorize_mcp_method", "sanitize_mcp_result", "review_forwarded_response",
    "mcp_tool_call", "mcp_guardrail_validate", "mcp_list_tools",
}
OUTPUT_METHODS = {
    "mesh_validate", "sanitize_output", "output_node", "create_output_guardrail",
    "sanitize_text", "sanitize_mcp_result", "review_forwarded_response",
    "sanitize_streaming_events", "sanitize_retrieval_documents",
}
TOOL_METHODS = {
    "authorize_tool_call", "authorize_transition", "transition_node",
    "wrap_tool_handler", "wrap_tool_node", "wrap_tool_function",
    "wrap_tool_executor", "wrap_action_group_lambda", "secure_tool",
    "secure_sdk_tool", "before_tool_call", "forward_with_firewall",
    "preflight_request", "authorize_mcp_tool_call", "authorize_mcp_method",
    "guarded_tool_executor",
}
PROMPT_METHODS = {
    "screen_input", "screen_prompt", "input_node",
    "create_input_guardrail", "screen_upstream_prompt", "validate_prompt_contract",
}
SURFACE_METHODS = {
    "prompt": PROMPT_METHODS,
    "tool": TOOL_METHODS,
    "a2a": A2A_METHODS,
    "mcp": MCP_METHODS,
    "output": OUTPUT_METHODS,
}
SDK_METHODS = (CATALOG_METHODS | README_METHODS).union(*(SURFACE_METHODS.values()))
MAX_OBSERVATIONS = 100


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _call_surfaces(node: ast.Call) -> set[str]:
    method = _call_name(node.func)
    surfaces = {surface for surface, names in SURFACE_METHODS.items() if method in names}
    if method == "guardrail_validate":
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
        if "tool_name" in keywords or "tool_args" in keywords:
            surfaces.add("tool")
        else:
            direction = keywords.get("direction")
            if isinstance(direction, ast.Constant) and isinstance(direction.value, str):
                if direction.value.lower() in {"input", "inbound"}:
                    surfaces.add("prompt")
                elif direction.value.lower() in {"output", "outbound", "response"}:
                    surfaces.add("output")
    return surfaces


def _module_name(relative: str) -> str:
    path = Path(relative)
    parts = path.with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def detect_existing_integration(root: Path, paths: Sequence[Path], *, scope_complete: bool) -> Dict[str, Any]:
    """Find SDK imports, actual call expressions and calls to local wrappers.

    Comments, docstrings, tests and generated review files are excluded by the
    caller's candidate list. No source text, literals or absolute paths leave
    this function.
    """
    possible_wrappers: list[tuple[Path, str, set[str]]] = []
    assessed_python_files = 0
    sdk_modules: set[str] = set()
    sdk_import_modules: set[str] = set()
    wrapper_methods: dict[str, set[str]] = {}
    observations: list[Dict[str, Any]] = []
    imports = 0
    direct_calls = 0
    framework_calls = 0
    a2a_calls = 0
    surface_counts = {surface: 0 for surface in SURFACE_METHODS}
    wrapper_calls = 0
    parse_gaps = 0

    for path in paths:
        if path.suffix.lower() not in {".py", ".pyi"}:
            continue
        assessed_python_files += 1
        try:
            relative = path.resolve().relative_to(root.resolve()).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, UnicodeError, SyntaxError, ValueError):
            parse_gaps += 1
            continue
        sdk_aliases: set[str] = set()
        guarded_aliases: set[str] = set()
        local_imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "agenticdome_sdk" or alias.name.startswith("agenticdome_sdk."):
                        sdk_aliases.add(alias.asname or alias.name.split(".")[0])
                        sdk_import_modules.add(alias.name)
                        imports += 1
                    else:
                        local_imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module == "agenticdome_sdk" or node.module.startswith("agenticdome_sdk."):
                    sdk_aliases.update(alias.asname or alias.name for alias in node.names)
                    if node.module in {"agenticdome_sdk", "agenticdome_sdk.generic_python"}:
                        guarded_aliases.update(alias.asname or alias.name for alias in node.names
                                               if alias.name == "guarded_tool_executor")
                    sdk_import_modules.add(node.module)
                    if node.module == "agenticdome_sdk":
                        sdk_import_modules.update("agenticdome_sdk." + alias.name for alias in node.names)
                    imports += 1
                else:
                    if node.level:
                        package_parts = _module_name(relative).split(".")[:-1]
                        retained = package_parts[:max(0, len(package_parts) - node.level + 1)]
                        local_imports.add(".".join([*retained, node.module]))
                    else:
                        local_imports.add(node.module)
        if sdk_aliases:
            module = _module_name(relative)
            sdk_modules.add(module)
            wrapper_methods[module] = {
                node.name for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any(isinstance(child, ast.Call) and _call_name(child.func) in SDK_METHODS
                        for child in ast.walk(node))
            }
        calls = [
            (node.lineno, _call_name(node.func), _call_surfaces(node)) for node in ast.walk(tree)
            if isinstance(node, ast.Call) and _call_name(node.func) in SDK_METHODS
        ]
        if sdk_aliases:
            calls.extend(
                (node.lineno, "guarded_tool_executor", {"tool"})
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any(isinstance(decorator, ast.Name) and decorator.id in guarded_aliases
                        or isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name)
                        and decorator.func.id in guarded_aliases and decorator.func.id != "guarded_tool_executor"
                        for decorator in node.decorator_list)
            )
        if sdk_aliases:
            direct_calls += len(calls)
            framework_calls += sum(method in FRAMEWORK_METHODS for _, method, _ in calls)
            a2a_calls += sum("a2a" in surfaces for _, _, surfaces in calls)
            for line, method, surfaces in calls:
                for surface in surfaces:
                    surface_counts[surface] += 1
                if len(observations) < MAX_OBSERVATIONS:
                    observations.append({"path": relative, "line": line, "method": method, "kind": "sdk_call_candidate"})
        elif local_imports:
            possible_wrappers.append((path, relative, local_imports))

    for path, relative, local_imports in possible_wrappers:
        matched_modules = {
            module for imported in local_imports for module in sdk_modules if module
            and (imported == module or imported.startswith(module + ".") or module.startswith(imported + "."))
        }
        if not matched_modules:
            continue
        names = SDK_METHODS.union(*(wrapper_methods.get(module, set()) for module in matched_modules))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, UnicodeError, SyntaxError):
            parse_gaps += 1
            continue
        calls = [
            (node.lineno, _call_name(node.func)) for node in ast.walk(tree)
            if isinstance(node, ast.Call) and _call_name(node.func) in names
        ]
        wrapper_calls += len(calls)
        for line, method in calls:
            if len(observations) < MAX_OBSERVATIONS:
                observations.append({"path": relative, "line": line, "method": method, "kind": "local_wrapper_call_candidate"})

    state = (
        "wrapper_calls_found" if wrapper_calls else
        "sdk_calls_found" if direct_calls else
        "sdk_imports_only" if imports else
        "not_detected" if assessed_python_files else "not_assessed_non_python"
    )
    return {
        "schema": "agenticdome.existing-integration.v1",
        "source_upload": False,
        "state": state,
        "sdk_imports": imports,
        "sdk_import_modules": sorted(sdk_import_modules)[:100],
        "assessed_python_files": assessed_python_files,
        "sdk_call_candidates": direct_calls,
        "framework_hook_call_candidates": framework_calls,
        "a2a_call_candidates": a2a_calls,
        "surface_call_candidates": surface_counts,
        "local_wrapper_call_candidates": wrapper_calls,
        "observations": observations,
        "observations_complete": direct_calls + wrapper_calls <= MAX_OBSERVATIONS,
        "python_parse_gaps": parse_gaps,
        "scope_complete": scope_complete and parse_gaps == 0,
        "runtime_proof": "not_assessed",
        "claim": "Static call-site candidates only. Verify the real execution boundary, fail-closed behavior and assigned-sidecar decisions before claiming protection.",
    }
