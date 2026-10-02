"""Opt-in, source-free evidence for a customer-run action-path test.

The test must install ExecutionSpy around the actual business handler.  A
sidecar verdict on its own never proves that the handler did or did not run.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple


_ADAPTERS = frozenset({
    "crewai", "pydantic", "langgraph", "microsoft_agent_framework",
    "autogen", "microsoft_ai_foundry", "openai_agents", "claude",
    "smolagents", "agno", "google_adk", "llamaindex", "aws_bedrock",
    "mcp_host", "generic_python", "_framework_firewall",
})


def _hook_frame() -> Tuple[str, str]:
    frame = sys._getframe(2)
    generic = ("", "")
    try:
        while frame:
            module = str(frame.f_globals.get("__name__", ""))
            if module.startswith("agenticdome_sdk.") and module.rsplit(".", 1)[-1] in _ADAPTERS:
                if module != "agenticdome_sdk._framework_firewall":
                    return module, frame.f_code.co_name
                if not generic[0]:
                    generic = (module, frame.f_code.co_name)
            frame = frame.f_back
    finally:
        del frame
    return generic


def _append_event(event: Dict[str, Any]) -> None:
    path = os.environ.get("AGENTICDOME_ACTION_PROOF_FILE", "")
    if not path or not os.path.isabs(path):
        return
    event = {"schema": "agenticdome.action-path-event.v1", **event}
    encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > 2048:
        return
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 262144:
                return
            os.write(fd, encoded)
        finally:
            os.close(fd)
    except OSError:
        # Proof is optional instrumentation; it must not change enforcement.
        return


def record_policy_decision(*, tool_name: Optional[str], platform: Optional[str],
                           direction: str, response: Dict[str, Any], live: bool) -> None:
    """Record no prompt, arguments, identity, token, or raw response."""
    if not os.environ.get("AGENTICDOME_ACTION_PROOF_FILE") or not tool_name:
        return
    module, function = _hook_frame()
    envelope = response.get("result") if isinstance(response.get("result"), dict) else response
    verdict = str(envelope.get("verdict") or envelope.get("decision") or "UNKNOWN").upper()
    decision_id = str(envelope.get("decision_id") or response.get("decision_id") or "")
    _append_event({
        "kind": "policy_decision", "tool_name": str(tool_name)[:160],
        "platform": str(platform or "")[:80], "direction": str(direction)[:24],
        "verdict": verdict if verdict in {"ALLOWED", "BLOCKED", "REDACTED"} else "UNKNOWN",
        "live": bool(live), "hook_module": module, "hook_function": function,
        "decision_id": decision_id if re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", decision_id) else "",
    })


class ExecutionSpy:
    """Wrap the real test handler, then assert its invocation count in the test."""

    def __init__(self, tool_name: str):
        if not tool_name or len(tool_name) > 160:
            raise ValueError("tool_name must contain 1-160 characters")
        self.tool_name = tool_name
        self.calls = 0

    def wrap(self, handler: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(handler):
            @functools.wraps(handler)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                self.calls += 1
                _append_event({"kind": "handler_attempt", "tool_name": self.tool_name})
                return await handler(*args, **kwargs)
            return async_wrapper

        @functools.wraps(handler)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            self.calls += 1
            _append_event({"kind": "handler_attempt", "tool_name": self.tool_name})
            return handler(*args, **kwargs)
        return sync_wrapper

    def assert_calls(self, expected: int) -> None:
        if not isinstance(expected, int) or expected < 0:
            raise ValueError("expected must be a non-negative integer")
        if self.calls != expected:
            raise AssertionError(f"Expected {expected} handler calls; observed {self.calls}")
        _append_event({"kind": "handler_assertion", "tool_name": self.tool_name, "calls": self.calls})


def run_action_path_test(root: Path, *, tool_name: str, expected_verdict: str,
                         expected_calls: int, command: Sequence[str],
                         timeout_seconds: int = 600) -> Tuple[int, Dict[str, Any]]:
    """Run an explicit customer test command, never a shell, and inspect evidence."""
    if not tool_name or len(tool_name) > 160:
        raise ValueError("tool_name must contain 1-160 characters")
    expected_verdict = expected_verdict.upper()
    if expected_verdict not in {"ALLOWED", "BLOCKED", "REDACTED"}:
        raise ValueError("expected_verdict must be ALLOWED, BLOCKED or REDACTED")
    if expected_calls not in {0, 1}:
        raise ValueError("expected_calls must be 0 or 1 for an isolated action test")
    if (expected_verdict == "BLOCKED" and expected_calls != 0) or (expected_verdict != "BLOCKED" and expected_calls != 1):
        raise ValueError("Blocked actions must not execute; allowed/redacted actions need one observed test-handler call")
    if not command or command[0] == "--" or any(not item or "\x00" in item for item in command):
        raise ValueError("Provide one explicit test command after --; a shell is not used")
    required = ("AGENTICDOME_API_BASE", "AGENTICDOME_API_KEY", "AGENTICDOME_TENANT_ID")
    missing = [key for key in required if not os.environ.get(key, "").strip()]
    if missing:
        raise ValueError("Live action-path proof requires " + ", ".join(missing))
    if os.environ.get("AGENTICDOME_MODE", "").strip().lower() in {"local_sim", "simulation", "sim"}:
        raise ValueError("Action-path proof requires a live assigned sidecar, not local simulation")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="agenticdome-action-proof-") as temporary:
        journal = Path(temporary) / "events.jsonl"
        environment = os.environ.copy()
        environment["AGENTICDOME_ACTION_PROOF_FILE"] = str(journal)
        try:
            completed = subprocess.run(list(command), cwd=root, env=environment,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=timeout_seconds, check=False)
            test_exit = completed.returncode
            timeout = False
        except subprocess.TimeoutExpired:
            test_exit = None
            timeout = True
        events = []
        if journal.exists():
            for line in journal.read_text(encoding="utf-8").splitlines()[:200]:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict) and value.get("schema") == "agenticdome.action-path-event.v1":
                    events.append(value)
    decisions = [item for item in events if item.get("kind") == "policy_decision" and item.get("tool_name") == tool_name]
    attempts = [item for item in events if item.get("kind") == "handler_attempt" and item.get("tool_name") == tool_name]
    assertions = [item for item in events if item.get("kind") == "handler_assertion" and item.get("tool_name") == tool_name]
    decision = decisions[0] if len(decisions) == 1 else {}
    assertion = assertions[0] if len(assertions) == 1 else {}
    reasons = []
    if timeout:
        reasons.append("The customer test timed out")
    elif test_exit != 0:
        reasons.append("The customer test did not pass")
    if len(decisions) != 1:
        reasons.append("Expected exactly one SDK tool decision for this action")
    elif not decision.get("live") or decision.get("direction") != "output":
        reasons.append("The decision was not a live outbound tool decision")
    elif not decision.get("hook_module"):
        reasons.append("No certified SDK framework hook was observed; a direct client call is insufficient")
    elif decision.get("verdict") != expected_verdict:
        reasons.append("Observed verdict differs from the expected verdict")
    if len(assertions) != 1 or assertion.get("calls") != expected_calls or len(attempts) != expected_calls:
        reasons.append("The real-handler spy did not establish the expected execution count")
    elif len(decisions) == 1:
        decision_index = events.index(decision)
        assertion_index = events.index(assertion)
        if assertion_index <= decision_index or any(events.index(attempt) <= decision_index or events.index(attempt) >= assertion_index for attempt in attempts):
            reasons.append("Handler evidence was not ordered after the policy decision and before the test assertion")
    report = {
        "schema": "agenticdome.action-path-proof.v1", "status": "passed" if not reasons else "incomplete",
        "tool_name": tool_name, "expected_verdict": expected_verdict,
        "observed_verdict": decision.get("verdict"),
        "decision_id": decision.get("decision_id") or None,
        "hook_module": decision.get("hook_module"), "hook_function": decision.get("hook_function"),
        "expected_handler_calls": expected_calls,
        "observed_handler_calls": len(attempts),
        "handler_assertion_passed": bool(assertion) and assertion.get("calls") == expected_calls,
        "customer_test_exit_code": test_exit, "timed_out": timeout,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "reasons": reasons,
        "next_action": (
            "Run the same safe test command directly to inspect its logs, then check the selected hook and spy placement. No test output was retained."
            if reasons else
            "Review the corresponding retained sidecar decision and repeat with an allowed/blocked counterpart before promoting this route."
        ),
        "qualification": "The SDK hook and live verdict were observed locally. Handler execution is established by a customer-installed spy around the actual test handler; verify that this test exercises the production route. No business action is run by the CLI itself.",
    }
    report["proof_sha256"] = hashlib.sha256(
        json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return (0 if not reasons else 2), report


def load_action_path_proof(root: Path) -> Optional[Dict[str, Any]]:
    """Load a current, intact customer-run report without trusting free text."""
    path = root / ".agenticdome" / "action-proof.json"
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
            return None
        report = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(report, dict) or report.get("schema") != "agenticdome.action-path-proof.v1":
            return None
        expected = str(report.get("proof_sha256") or "")
        source = {key: value for key, value in report.items() if key != "proof_sha256"}
        digest = hashlib.sha256(json.dumps(source, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if digest != expected:
            return None
        observed_at = datetime.fromisoformat(str(report.get("observed_at") or ""))
        age = datetime.now(timezone.utc) - observed_at.astimezone(timezone.utc)
        if age.total_seconds() < -300 or age.total_seconds() > 7 * 86400:
            return None
        if report.get("status") != "passed" or report.get("hook_module") not in {
            "agenticdome_sdk." + adapter for adapter in _ADAPTERS
        }:
            return None
        if report.get("observed_verdict") not in {"ALLOWED", "BLOCKED", "REDACTED"}:
            return None
        if report.get("expected_handler_calls") not in {0, 1} or report.get("observed_handler_calls") != report.get("expected_handler_calls"):
            return None
        return {
            "schema": "agenticdome.action-path-proof.v1", "status": "passed",
            "tool_name": str(report.get("tool_name") or "")[:160],
            "observed_verdict": report["observed_verdict"],
            "decision_id": str(report.get("decision_id") or "")[:100] or None,
            "hook_module": report["hook_module"],
            "hook_function": str(report.get("hook_function") or "")[:100],
            "observed_handler_calls": report["observed_handler_calls"],
            "observed_at": report["observed_at"],
            "proof_sha256": expected,
            "evidence_origin": "customer_test",
        }
    except (OSError, ValueError, TypeError, OverflowError, json.JSONDecodeError):
        return None


__all__ = ["ExecutionSpy", "run_action_path_test", "record_policy_decision", "load_action_path_proof"]
