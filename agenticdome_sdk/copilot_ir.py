"""Generic, source-free AST collection for the AgenticDome Integration Copilot.

This public module deliberately performs no placement ranking, guard-dominance
reasoning, bypass scoring or compatibility decisions. Those protectable
capabilities live in the private Copilot Core. The collector emits bounded
structural metadata and never emits source text, literals or absolute paths.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple


IR_SCHEMA = "agenticdome.copilot-ir.v1"
MAX_IR_FILES = 1_000


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        left = _dotted_name(node.value)
        return (left + "." if left else "") + node.attr.lower()
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _tail(value: str) -> str:
    return str(value or "").rsplit(".", 1)[-1].lower()


def _literal_enum(node: ast.AST | None, allowed: set[str]) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value.strip().lower()
        return value if value in allowed else ""
    return ""


def _call_hints(node: ast.Call) -> Dict[str, Any]:
    hints: Dict[str, Any] = {}
    has_tool_binding = False
    for keyword in node.keywords:
        if keyword.arg == "direction":
            direction = _literal_enum(keyword.value, {"input", "inbound", "output", "outbound"})
            if direction:
                hints["direction"] = direction
        elif keyword.arg in {"tool_name", "tool_args"}:
            has_tool_binding = True
        elif keyword.arg == "policy_context" and isinstance(keyword.value, ast.Dict):
            for key, value in zip(keyword.value.keys, keyword.value.values):
                if _literal_enum(key, {"request_purpose"}) != "request_purpose":
                    continue
                purpose = _literal_enum(
                    value,
                    {"prompt_input", "tool_execution", "output_review", "sdk_onboarding_verification"},
                )
                if purpose:
                    hints["request_purpose"] = purpose
    if has_tool_binding:
        hints["has_tool_binding"] = True
    return hints


class _PythonIRVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.stack: List[str] = ["<module>"]
        self.flow_stack: List[str] = []
        self.functions: Dict[str, Dict[str, Any]] = {
            "<module>": {
                "symbol": "<module>",
                "path": path,
                "line": 1,
                "hints": {"entrypoint": True, "parameters": [], "decorators": []},
                "events": [],
            }
        }
        self.features = {"functions": 0, "calls": 0, "returns": 0}

    @property
    def current(self) -> Dict[str, Any]:
        return self.functions[self.stack[-1]]

    def _visit_function(self, node: ast.AST) -> None:
        name = str(getattr(node, "name", "anonymous"))
        parent = self.stack[-1]
        symbol = name if parent == "<module>" else parent + "." + name
        decorators = [_dotted_name(item) for item in getattr(node, "decorator_list", [])]
        parameters = [arg.arg.lower() for arg in getattr(getattr(node, "args", None), "args", [])]
        self.functions[symbol] = {
            "symbol": symbol,
            "path": self.path,
            "line": int(getattr(node, "lineno", 1)),
            "hints": {"parameters": parameters[:100], "decorators": decorators[:50]},
            "events": [],
        }
        self.features["functions"] += 1
        self.stack.append(symbol)
        for statement in getattr(node, "body", []):
            self.visit(statement)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        self.features["calls"] += 1
        self.current["events"].append({
            "event": "call",
            "callee": _dotted_name(node.func),
            "line": int(getattr(node, "lineno", self.current["line"])),
            "flow_scope": list(self.flow_stack),
            "hints": _call_hints(node),
        })
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        self.features["returns"] += 1
        if node.value is not None:
            self.visit(node.value)
        self.current["events"].append({
            "event": "return",
            "callee": "return",
            "line": int(getattr(node, "lineno", self.current["line"])),
            "flow_scope": list(self.flow_stack),
        })

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        role = "user_input" if any(_tail(_dotted_name(target)) in {"user_input", "user_query", "user_message"} for target in node.targets) else ""
        if role:
            self.current["events"].append({
                "event": "assignment",
                "assignment_role": role,
                "callee": "assignment",
                "line": int(getattr(node, "lineno", self.current["line"])),
                "flow_scope": list(self.flow_stack),
            })
        self.generic_visit(node)

    def _visit_branch(self, node: ast.AST, arms: Sequence[Tuple[str, Sequence[ast.stmt]]]) -> None:
        test = getattr(node, "test", None)
        if isinstance(test, ast.AST):
            self.visit(test)
        marker = node.__class__.__name__.lower() + "@" + str(getattr(node, "lineno", 1))
        for arm, statements in arms:
            self.flow_stack.append(marker + ":" + arm)
            for statement in statements:
                self.visit(statement)
            self.flow_stack.pop()

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        self._visit_branch(node, (("body", node.body), ("else", node.orelse)))

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        self.visit(node.iter)
        self._visit_branch(node, (("body", node.body), ("else", node.orelse)))

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:  # noqa: N802
        self.visit_For(node)

    def visit_While(self, node: ast.While) -> None:  # noqa: N802
        self._visit_branch(node, (("body", node.body), ("else", node.orelse)))

    def visit_Try(self, node: ast.Try) -> None:  # noqa: N802
        arms: List[Tuple[str, Sequence[ast.stmt]]] = [("body", node.body)]
        arms.extend(("except" + str(index), handler.body) for index, handler in enumerate(node.handlers))
        arms.extend((("else", node.orelse), ("finally", node.finalbody)))
        self._visit_branch(node, arms)


def _collect_python(root: Path, paths: Sequence[Path]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    functions: List[Dict[str, Any]] = []
    parsed = 0
    parse_errors = 0
    features = {"functions": 0, "calls": 0, "returns": 0}
    for path in paths[:MAX_IR_FILES]:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=path.name)
        except (OSError, SyntaxError, ValueError):
            parse_errors += 1
            continue
        visitor = _PythonIRVisitor(_relative(path, root))
        visitor.visit(tree)
        parsed += 1
        functions.extend(visitor.functions.values())
        for key, value in visitor.features.items():
            features[key] += value
    return functions, {
        "engine": "python-ast",
        "available": True,
        "files_parsed": parsed,
        "parse_errors": parse_errors,
        "features": features,
        "claim": "Generic AST structure collection; private reasoning is performed by the assigned Copilot service",
    }


def _collect_typescript(root: Path, paths: Sequence[Path]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if not paths:
        return [], {"engine": "typescript-compiler-api", "available": False, "files_parsed": 0, "reason": "No TypeScript or JavaScript source was found."}
    node = shutil.which("node")
    helper = Path(__file__).with_name("copilot_ir_collector.cjs")
    if not node or not helper.exists():
        return _typescript_fallback(root, paths, "Node.js or the packaged IR collector is unavailable.")
    try:
        completed = subprocess.run(
            [node, str(helper)],
            input=json.dumps({"root": str(root), "files": [str(path) for path in paths[:MAX_IR_FILES]]}),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=20,
            cwd=root,
        )
        result = json.loads(completed.stdout or "{}") if completed.returncode == 0 else {}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {}
    if not isinstance(result, dict) or not result.get("available"):
        return _typescript_fallback(root, paths, str(result.get("reason", "The TypeScript compiler is unavailable."))[:160] if isinstance(result, dict) else "The TypeScript compiler is unavailable.")
    functions = result.get("functions") if isinstance(result.get("functions"), list) else []
    return [item for item in functions if isinstance(item, dict)], {
        "engine": "typescript-compiler-api",
        "available": True,
        "files_parsed": max(0, int(result.get("files_parsed", 0))),
        "parse_errors": max(0, int(result.get("parse_errors", 0))),
        "typescript_version": str(result.get("typescript_version", ""))[:40],
        "claim": "Generic compiler AST structure collection; private reasoning is performed by the assigned Copilot service",
    }


def _typescript_fallback(root: Path, paths: Sequence[Path], reason: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    functions: List[Dict[str, Any]] = []
    parsed = 0
    call_pattern = re.compile(r"\b([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(")
    for path in paths[:MAX_IR_FILES]:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        events = []
        for line_number, line in enumerate(lines, start=1):
            for match in call_pattern.finditer(line):
                events.append({"event": "call", "callee": re.sub(r"\s+", "", match.group(1)).lower(), "line": line_number, "flow_scope": []})
            if re.search(r"\breturn\b", line):
                events.append({"event": "return", "callee": "return", "line": line_number, "flow_scope": []})
        functions.append({"symbol": "<module>", "path": _relative(path, root), "line": 1, "hints": {"entrypoint": True, "parameters": [], "decorators": []}, "events": events[:500]})
        parsed += 1
    return functions, {
        "engine": "typescript-structural-fallback",
        "available": False,
        "files_parsed": parsed,
        "parse_errors": 0,
        "reason": reason,
        "claim": "Generic structural collection only; install TypeScript for compiler AST evidence",
    }


def collect_repository_ir(root: Path, paths: Sequence[Path]) -> Dict[str, Any]:
    """Collect bounded metadata for private reasoning without emitting source."""
    python_paths = [path for path in paths if path.suffix.lower() in {".py", ".pyi"}]
    typescript_paths = [path for path in paths if path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}]
    python_functions, python_engine = _collect_python(root, python_paths)
    typescript_functions, typescript_engine = _collect_typescript(root, typescript_paths)
    return {
        "schema": IR_SCHEMA,
        "source_upload": False,
        "collector_mode": "generic_ast_metadata_only",
        "engines": {"python": python_engine, "typescript": typescript_engine},
        "functions": (python_functions + typescript_functions)[:20_000],
        "privacy": {
            "source_text": False,
            "string_literals": False,
            "absolute_paths": False,
            "environment_values": False,
        },
    }
