"""Exact, local-only framework attachment edits for catalog-qualified SDK contracts.

These recipes add a supported attachment at an unambiguous construction site.
They do not establish that every application route reaches that site; the
customer must review the diff and exercise the real route before promotion.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class FrameworkEdit:
    framework: str
    attachment: str
    line: int
    description: str


_RECIPES = {
    "pydanticai": ("pydantic_ai", ("Agent",), "agenticdome_sdk.pydantic", "CyberSecFirewall", "capabilities", "CyberSecFirewall().create_hooks()"),
    "langgraph": ("langchain.agents", ("create_agent",), "agenticdome_sdk.langgraph", "AgenticDomeLangGraphFirewall", "middleware", "AgenticDomeLangGraphFirewall().as_langchain_middleware()"),
    "google-adk": ("google.adk.agents", ("Agent", "LlmAgent"), "agenticdome_sdk.google_adk", "AgenticDomeGoogleADKFirewall", "callbacks", "AgenticDomeGoogleADKFirewall().build_callback_kwargs()"),
}

_GENERIC_EXECUTOR_NAMES = {"execute_tool", "dispatch_tool", "invoke_tool", "run_tool", "call_tool"}
_GENERIC_REQUIRED_ARGS = {"tool_name", "tool_args", "agent_id", "session_id"}


def _generic_candidates(tree: ast.Module) -> List[ast.AST]:
    eligible = [*tree.body, *(method for node in tree.body if isinstance(node, ast.ClassDef)
                              for method in node.body)]
    return [node for node in eligible
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in _GENERIC_EXECUTOR_NAMES and not node.decorator_list
            and _GENERIC_REQUIRED_ARGS.issubset(
                {arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)})]


def has_explicit_python_tool_dispatcher(source: str) -> bool:
    """Cheap local discovery signal for a bespoke executor alongside any framework."""
    if not any("def " + name in source for name in _GENERIC_EXECUTOR_NAMES):
        return False
    try:
        return bool(_generic_candidates(ast.parse(source)))
    except SyntaxError:
        return False


def _offset(lines: List[bytes], line: int, column: int) -> int:
    return sum(len(value) for value in lines[:line - 1]) + column


def _symbols(tree: ast.Module, module: str, names: Iterable[str]) -> Tuple[set[str], set[str]]:
    direct: set[str] = set()
    modules: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == module:
            direct.update(alias.asname or alias.name for alias in node.names if alias.name in names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == module:
                    modules.add(alias.asname or module)
    return direct, modules


def _matches(func: ast.AST, direct: set[str], modules: set[str], names: Iterable[str]) -> bool:
    name_set = set(names)
    if isinstance(func, ast.Name):
        return func.id in direct
    if not isinstance(func, ast.Attribute) or func.attr not in name_set:
        return False
    value = func.value
    parts: List[str] = []
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if not isinstance(value, ast.Name):
        return False
    parts.append(value.id)
    return ".".join(reversed(parts)) in modules


def _shadowed(tree: ast.Module, names: set[str]) -> bool:
    if not names:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in names:
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in names:
            return True
    return False


def _assigned_calls(tree: ast.Module) -> Iterable[Tuple[ast.Call, str]]:
    for statement in ast.walk(tree):
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1 and isinstance(statement.targets[0], ast.Name) and isinstance(statement.value, ast.Call):
            yield statement.value, statement.targets[0].id
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and isinstance(statement.value, ast.Call):
            yield statement.value, statement.target.id


def _import_offset(tree: ast.Module, lines: List[bytes]) -> int:
    last_line = 0
    body = tree.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        last_line = body[0].end_lineno or 0
        body = body[1:]
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last_line = node.end_lineno or last_line
        else:
            break
    if last_line == 0:
        for line in lines[:2]:
            if line.startswith(b"#!") or b"coding:" in line or b"coding=" in line:
                last_line += 1
            else:
                break
    return sum(len(value) for value in lines[:last_line])


def _import_present(tree: ast.Module, module: str, name: str) -> bool:
    return any(isinstance(node, ast.ImportFrom) and node.module == module
               and any(alias.name == name and (alias.asname is None or alias.asname == name) for alias in node.names)
               for node in tree.body)


def _class_name_conflict(tree: ast.Module, module: str, name: str) -> bool:
    if _import_present(tree, module, name):
        return False
    if _shadowed(tree, {name}):
        return True
    return any(isinstance(node, ast.ImportFrom) and node.module != module
               and any(alias.asname == name or (alias.asname is None and alias.name == name) for alias in node.names)
               for node in tree.body)


def _insert_keyword(source: str, call: ast.Call, key: str, value: str, *, list_value: bool = False) -> Optional[str]:
    if any(keyword.arg is None for keyword in call.keywords):
        return None
    raw = source.encode("utf-8")
    lines = raw.splitlines(keepends=True)
    start = _offset(lines, call.lineno, call.col_offset)
    end = _offset(lines, call.end_lineno or call.lineno, call.end_col_offset or call.col_offset)
    segment = raw[start:end].decode("utf-8")
    if not segment.endswith(")") or "#" in segment:
        return None
    present = next((item for item in call.keywords if item.arg == key), None)
    if present:
        if not list_value or not isinstance(present.value, ast.List):
            return None
        list_start = _offset(lines, present.value.lineno, present.value.col_offset)
        list_end = _offset(lines, present.value.end_lineno or present.value.lineno, present.value.end_col_offset or present.value.col_offset)
        old_list = raw[list_start:list_end].decode("utf-8")
        if not old_list.endswith("]") or "#" in old_list or any(isinstance(item, ast.Starred) for item in present.value.elts):
            return None
        if value in old_list:
            return None
        before_close = old_list[:-1].rstrip()
        separator = ", " if present.value.elts and not before_close.endswith(",") else ""
        replacement = before_close + separator + value + "]"
        changed = raw[:list_start] + replacement.encode("utf-8") + raw[list_end:]
    else:
        before_close = segment[:-1]
        stripped = before_close.rstrip()
        if "\n" in before_close:
            last_newline = before_close.rfind("\n")
            closing_indent = before_close[last_newline + 1:]
            if closing_indent.strip():
                return None
            body = before_close[:last_newline].rstrip()
            separator = "" if body.endswith(("(", ",")) else ","
            item = (key + "=[" + value + "]") if list_value else ("**" + value)
            replacement = body + separator + "\n" + closing_indent + "    " + item + ",\n" + closing_indent + ")"
        else:
            separator = "" if stripped.endswith(("(", ",")) else ", "
            item = (key + "=[" + value + "]") if list_value else ("**" + value)
            replacement = stripped + separator + item + ")"
        changed = raw[:start] + replacement.encode("utf-8") + raw[end:]
    try:
        result = changed.decode("utf-8")
        ast.parse(result)
    except (UnicodeDecodeError, SyntaxError):
        return None
    return result


def _insert_import(source: str, module: str, name: Optional[str]) -> Optional[str]:
    tree = ast.parse(source)
    if name and _import_present(tree, module, name):
        return source
    if name is None and any(isinstance(node, ast.Import) and any(alias.name == module for alias in node.names) for node in tree.body):
        return source
    lines = source.encode("utf-8").splitlines(keepends=True)
    offset = _import_offset(tree, lines)
    newline = b"\r\n" if b"\r\n" in source.encode("utf-8") else b"\n"
    statement = (f"from {module} import {name}" if name else f"import {module}").encode("utf-8") + newline
    raw = source.encode("utf-8")
    if offset and raw[offset - 1:offset] not in {b"\n", b"\r"}:
        statement = newline + statement
    result = (raw[:offset] + statement + raw[offset:]).decode("utf-8")
    try:
        ast.parse(result)
    except SyntaxError:
        return None
    return result


def _apply_recipe(source: str, framework: str) -> Tuple[Optional[str], List[FrameworkEdit]]:
    tree = ast.parse(source)
    if framework == "custom-python":
        adapter_module = "agenticdome_sdk.generic_python"
        adapter_name = "guarded_tool_executor"
        if _class_name_conflict(tree, adapter_module, adapter_name):
            return None, []
        candidates = _generic_candidates(tree)
        if len(candidates) != 1:
            return None, []
        function = candidates[0]
        raw = source.encode("utf-8")
        lines = raw.splitlines(keepends=True)
        offset = _offset(lines, function.lineno, function.col_offset)
        newline = b"\r\n" if b"\r\n" in raw else b"\n"
        indentation = lines[function.lineno - 1][:function.col_offset]
        if indentation.strip():
            return None, []
        updated = (raw[:offset] + b"@guarded_tool_executor" + newline + indentation + raw[offset:]).decode("utf-8")
        try:
            ast.parse(updated)
        except SyntaxError:
            return None, []
        updated = _insert_import(updated, adapter_module, adapter_name)
        return (updated, [FrameworkEdit(framework, adapter_name, function.lineno,
                "Authorize this explicit Python tool dispatcher before its body executes; verify trusted identity and every route.")]) if updated else (None, [])

    if framework == "openai-agents":
        direct, _ = _symbols(tree, "agents", ("FunctionTool",))
        if not direct or _shadowed(tree, direct) or _class_name_conflict(tree, "agenticdome_sdk.openai_agents", "AgenticDomeOpenAIAgentsFirewall"):
            return None, []
        raw = source.encode("utf-8")
        lines = raw.splitlines(keepends=True)
        replacements: List[Tuple[int, int, bytes, int]] = []
        for call, _ in _assigned_calls(tree):
            if not isinstance(call.func, ast.Name) or call.func.id not in direct:
                continue
            if call.args or any(item.arg is None for item in call.keywords):
                continue
            handler = next((item for item in call.keywords if item.arg == "on_invoke_tool"), None)
            name = next((item for item in call.keywords if item.arg == "name"), None)
            if (not handler or not name or not isinstance(handler.value, ast.Name)
                    or not isinstance(name.value, ast.Constant) or not isinstance(name.value.value, str)):
                continue
            call_start = _offset(lines, call.lineno, call.col_offset)
            call_end = _offset(lines, call.end_lineno or call.lineno, call.end_col_offset or call.col_offset)
            if b"#" in raw[call_start:call_end]:
                continue
            name_source = ast.get_source_segment(source, name.value)
            if not name_source:
                continue
            start = _offset(lines, handler.value.lineno, handler.value.col_offset)
            end = _offset(lines, handler.value.end_lineno or handler.value.lineno, handler.value.end_col_offset or handler.value.col_offset)
            replacement = (
                "AgenticDomeOpenAIAgentsFirewall().wrap_tool_handler(tool_name=" +
                name_source + ", handler=" + handler.value.id + ", handler_args_format='json')"
            ).encode("utf-8")
            replacements.append((start, end, replacement, call.lineno))
        if not replacements:
            return None, []
        for start, end, replacement, _ in sorted(replacements, reverse=True):
            raw = raw[:start] + replacement + raw[end:]
        try:
            updated = raw.decode("utf-8")
            ast.parse(updated)
        except (UnicodeDecodeError, SyntaxError):
            return None, []
        updated = _insert_import(updated, "agenticdome_sdk.openai_agents", "AgenticDomeOpenAIAgentsFirewall")
        edits = [FrameworkEdit("openai-agents", "wrap_tool_handler", line, "Authorize this FunctionTool's on_invoke_tool handler before execution.")
                 for _, _, _, line in replacements]
        return (updated, edits) if updated else (None, [])

    if framework == "llamaindex":
        direct, _ = _symbols(tree, "llama_index.core.tools", ("FunctionTool",))
        if not direct or _shadowed(tree, direct) or _class_name_conflict(tree, "agenticdome_sdk.llamaindex", "AgenticDomeLlamaIndexFirewall"):
            return None, []
        calls = [call for call, _ in _assigned_calls(tree)
                 if isinstance(call.func, ast.Attribute) and call.func.attr == "from_defaults"
                 and isinstance(call.func.value, ast.Name) and call.func.value.id in direct]
        if len(calls) != 1 or calls[0].args or any(item.arg is None for item in calls[0].keywords):
            return None, []
        call = calls[0]
        handler_keywords = [item for item in call.keywords if item.arg in {"fn", "async_fn"}]
        if len(handler_keywords) != 1 or not isinstance(handler_keywords[0].value, ast.Name):
            return None, []
        if any(item.arg in {"tool_name", "callback_manager"} for item in call.keywords):
            return None, []
        raw = source.encode("utf-8")
        lines = raw.splitlines(keepends=True)
        call_start = _offset(lines, call.lineno, call.col_offset)
        call_end = _offset(lines, call.end_lineno or call.lineno, call.end_col_offset or call.col_offset)
        if b"#" in raw[call_start:call_end]:
            return None, []
        handler = handler_keywords[0]
        start = _offset(lines, handler.value.lineno, handler.value.col_offset)
        end = _offset(lines, handler.value.end_lineno or handler.value.lineno, handler.value.end_col_offset or handler.value.col_offset)
        name_keyword = next((item for item in call.keywords if item.arg == "name"), None)
        if name_keyword and (not isinstance(name_keyword.value, ast.Constant) or not isinstance(name_keyword.value.value, str)):
            return None, []
        name_source = ast.get_source_segment(source, name_keyword.value) if name_keyword else None
        if name_keyword and not name_source:
            return None, []
        tool_name = ", tool_name=" + name_source if name_source else ""
        replacement = ("AgenticDomeLlamaIndexFirewall().wrap_tool_function(" + handler.value.id + tool_name + ")").encode("utf-8")
        updated = (raw[:start] + replacement + raw[end:]).decode("utf-8")
        if handler.arg == "fn":
            updated = updated[:_offset(lines, handler.lineno, handler.col_offset)] + "async_fn" + updated[_offset(lines, handler.lineno, handler.col_offset) + 2:]
        try:
            ast.parse(updated)
        except SyntaxError:
            return None, []
        updated = _insert_import(updated, "agenticdome_sdk.llamaindex", "AgenticDomeLlamaIndexFirewall")
        return (updated, [FrameworkEdit("llamaindex", "wrap_tool_function", call.lineno, "Authorize this FunctionTool's handler before execution and review its output.")]) if updated else (None, [])

    if framework == "agno":
        if _class_name_conflict(tree, "agenticdome_sdk.agno", "AgenticDomeAgnoFirewall"):
            return None, []
        direct, modules = _symbols(tree, "agno.agent", ("Agent",))
        if _shadowed(tree, direct | {module.split(".")[0] for module in modules}):
            return None, []
        calls = [(call, variable) for call, variable in _assigned_calls(tree)
                 if _matches(call.func, direct, modules, ("Agent",))]
        if len(calls) != 1:
            return None, []
        call, variable = calls[0]
        if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and node.func.attr == "attach_firewall" and node.args
               and isinstance(node.args[0], ast.Name) and node.args[0].id == variable
               for node in ast.walk(tree)):
            return None, []
        raw = source.encode("utf-8")
        lines = raw.splitlines(keepends=True)
        line_no = call.end_lineno or call.lineno
        line = lines[line_no - 1]
        call_end = call.end_col_offset or call.col_offset
        if line[call_end:].strip() or not line.endswith((b"\n", b"\r")):
            return None, []
        opening_line = lines[call.lineno - 1]
        indent = opening_line[:len(opening_line) - len(opening_line.lstrip())]
        if indent.replace(b"\t", b"").replace(b" ", b""):
            return None, []
        newline = b"\r\n" if line.endswith(b"\r\n") else b"\n"
        insertion = indent + f"AgenticDomeAgnoFirewall().attach_firewall({variable})".encode("utf-8") + newline
        offset = sum(len(item) for item in lines[:line_no])
        updated = (raw[:offset] + insertion + raw[offset:]).decode("utf-8")
        updated = _insert_import(updated, "agenticdome_sdk.agno", "AgenticDomeAgnoFirewall")
        if not updated:
            return None, []
        return updated, [FrameworkEdit("agno", "attach_firewall", call.lineno, "Attach Agno pre, tool and post hooks to this constructed agent.")]

    if framework == "crewai":
        direct, modules = _symbols(tree, "crewai", ("Crew",))
        if not direct and not modules:
            return None, []
        if not any(_matches(call.func, direct, modules, ("Crew",)) for call, _ in _assigned_calls(tree)):
            return None, []
        if any(isinstance(node, ast.ImportFrom) and node.module == "agenticdome_sdk"
               and any(alias.name == "crewai" for alias in node.names) for node in tree.body):
            return None, []
        if _shadowed(tree, direct | {module.split(".")[0] for module in modules}):
            return None, []
        updated = _insert_import(source, "agenticdome_sdk.crewai", None)
        if not updated or updated == source:
            return None, []
        return updated, [FrameworkEdit("crewai", "global before/after hooks", 1, "Register CrewAI prompt, tool and output hooks before crew construction.")]

    if framework == "claude":
        direct, modules = _symbols(tree, "claude_agent_sdk", ("ClaudeAgentOptions",))
        if _shadowed(tree, direct | {module.split(".")[0] for module in modules}) or _class_name_conflict(tree, "agenticdome_sdk.claude", "AgenticDomeClaudeFirewall"):
            return None, []
        calls = [(call, variable) for call, variable in _assigned_calls(tree)
                 if _matches(call.func, direct, modules, ("ClaudeAgentOptions",))]
        if len(calls) != 1:
            return None, []
        call, _ = calls[0]
        if any(keyword.arg is None for keyword in call.keywords):
            return None, []
        raw = source.encode("utf-8")
        lines = raw.splitlines(keepends=True)
        start = _offset(lines, call.lineno, call.col_offset)
        end = _offset(lines, call.end_lineno or call.lineno, call.end_col_offset or call.col_offset)
        segment = raw[start:end]
        wrapped = raw[:start] + b"AgenticDomeClaudeFirewall().install_on_options(" + segment + b")" + raw[end:]
        try:
            updated = wrapped.decode("utf-8")
            ast.parse(updated)
        except (UnicodeDecodeError, SyntaxError):
            return None, []
        updated = _insert_import(updated, "agenticdome_sdk.claude", "AgenticDomeClaudeFirewall")
        return (updated, [FrameworkEdit("claude", "install_on_options", call.lineno, "Merge Claude prompt, PreToolUse and PostToolUse hooks into options.")]) if updated else (None, [])

    spec = _RECIPES.get(framework)
    if spec is None:
        return None, []
    native_module, constructors, adapter_module, adapter_class, keyword, expression = spec
    direct, modules = _symbols(tree, native_module, constructors)
    if _shadowed(tree, direct | {module.split(".")[0] for module in modules}) or _class_name_conflict(tree, adapter_module, adapter_class):
        return None, []
    calls = [call for call, _ in _assigned_calls(tree) if _matches(call.func, direct, modules, constructors)]
    if len(calls) != 1:
        return None, []
    call = calls[0]
    if framework == "google-adk":
        callback_names = {"before_agent_callback", "after_agent_callback", "before_model_callback", "after_model_callback", "before_tool_callback", "after_tool_callback"}
        if any(item.arg in callback_names for item in call.keywords):
            return None, []
    updated = _insert_keyword(source, call, keyword, expression, list_value=framework != "google-adk")
    if not updated or updated == source:
        return None, []
    updated = _insert_import(updated, adapter_module, adapter_class)
    if not updated:
        return None, []
    descriptions = {
        "pydanticai": "Add native tool-execution and output hooks to this PydanticAI agent's capabilities.",
        "langgraph": "Add AgenticDome input, tool and output middleware to this LangChain create_agent call.",
        "google-adk": "Add AgenticDome model, tool and agent callbacks to this Google ADK agent.",
    }
    attachment = {"pydanticai": "create_hooks", "langgraph": "as_langchain_middleware", "google-adk": "build_callback_kwargs"}[framework]
    return updated, [FrameworkEdit(framework, attachment, call.lineno, descriptions[framework])]


def propose_framework_edits(source: str, ready_frameworks: Iterable[str]) -> Tuple[Optional[str], List[FrameworkEdit]]:
    """Return an exact source edit only for unambiguous, catalog-ready patterns."""
    current = source
    edits: List[FrameworkEdit] = []
    for framework in ("custom-python", "crewai", "pydanticai", "langgraph", "google-adk", "claude", "agno", "llamaindex", "openai-agents"):
        if framework not in ready_frameworks:
            continue
        try:
            updated, recipe_edits = _apply_recipe(current, framework)
        except (SyntaxError, UnicodeDecodeError):
            continue
        if updated and updated != current:
            current = updated
            edits.extend(recipe_edits)
    return (current if edits else None), edits
