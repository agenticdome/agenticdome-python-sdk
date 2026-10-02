"""Fail-closed action gate for explicit, application-owned Python executors.

The decorator protects only the function it wraps.  The application must
derive agent_id and session_id from a trusted context and route every real
tool execution through that function.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import os
import threading
from typing import Any, Callable, Dict, Optional

from .client import AgenticDomeClient


class AgenticDomeActionDenied(PermissionError):
    """The runtime did not explicitly authorize this action."""


def _required(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgenticDomeActionDenied(f"A trusted, non-empty {field} is required before tool execution")
    return value.strip()


def _optional_text(value: Any) -> Optional[str]:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _snapshot_args(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise AgenticDomeActionDenied("tool_args must be a dictionary before tool execution")
    try:
        snapshot = json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise AgenticDomeActionDenied("tool_args must be JSON-serializable before tool execution") from exc
    if not isinstance(snapshot, dict):
        raise AgenticDomeActionDenied("tool_args must remain a dictionary before tool execution")
    return snapshot


def _authorize(bound: inspect.BoundArguments, client: Optional[AgenticDomeClient]) -> Dict[str, Any]:
    values = bound.arguments
    tool_name = _required(values.get("tool_name"), "tool_name")
    agent_id = _required(values.get("agent_id"), "agent_id")
    session_id = _required(values.get("session_id"), "session_id")
    tool_args = _snapshot_args(values.get("tool_args"))
    values["tool_name"] = tool_name
    values["agent_id"] = agent_id
    values["session_id"] = session_id
    values["tool_args"] = tool_args
    purpose = _optional_text(values.get("request_purpose")) or _optional_text(values.get("purpose"))
    user_id = _optional_text(values.get("user_id"))
    policy_context = values.get("policy_context")
    if policy_context is not None and not isinstance(policy_context, dict):
        raise AgenticDomeActionDenied("policy_context must be a dictionary when supplied")
    runtime = client if client is not None else AgenticDomeClient()
    if getattr(runtime, "is_simulation", False):
        raise AgenticDomeActionDenied("A real tool executor requires a live assigned runtime, not local simulation")
    response = runtime.guardrail_validate(
        text=f"Custom Python agent requests tool {tool_name}",
        agent_id=agent_id,
        session_id=session_id,
        direction="outbound",
        platform="python",
        tool_name=tool_name,
        tool_args=tool_args,
        request_purpose=purpose,
        user_id=user_id,
        tool_platform=_optional_text(values.get("tool_platform")),
        actual_role=_optional_text(values.get("actual_role")),
        claimed_role=_optional_text(values.get("claimed_role")),
        intent=_optional_text(values.get("intent")),
        workload_id=_optional_text(values.get("workload_id")),
        policy_context=policy_context,
    )
    if not isinstance(response, dict):
        raise AgenticDomeActionDenied("The runtime returned no usable authorization decision")
    decision = response.get("result") if isinstance(response.get("result"), dict) else response
    verdict = str(decision.get("verdict") or decision.get("decision") or "").upper()
    if verdict not in {"ALLOWED", "REDACTED"}:
        raise AgenticDomeActionDenied(str(decision.get("reason") or "Tool action was not authorized"))
    sanitized = next((decision[key] for key in ("sanitized_tool_args", "sanitized_args")
                      if key in decision and isinstance(decision[key], dict)), None)
    if verdict == "REDACTED" and sanitized is None:
        raise AgenticDomeActionDenied("The runtime redacted this action without returning safe tool arguments")
    if sanitized is not None:
        bound.arguments["tool_args"] = _snapshot_args(sanitized)
    return dict(bound.arguments)


def guarded_tool_executor(handler: Optional[Callable[..., Any]] = None, *, client: Optional[AgenticDomeClient] = None) -> Callable[..., Any]:
    """Authorize an explicit tool executor before its original body runs.

    Required handler parameters are tool_name, tool_args, agent_id and
    session_id.  The application remains responsible for trusted identity,
    complete routing, output review and any delegated-token verification.
    """
    if handler is None:
        return lambda function: guarded_tool_executor(function, client=client)
    signature = inspect.signature(handler)
    required = {"tool_name", "tool_args", "agent_id", "session_id"}
    if not required.issubset(signature.parameters):
        raise TypeError("A guarded tool executor needs explicit tool_name, tool_args, agent_id and session_id parameters")
    thread_client = threading.local()

    def authorize(bound: inspect.BoundArguments) -> None:
        runtime = client
        if runtime is None:
            # Keep an HTTP pool per worker thread without sharing requests.Session
            # across threads. Recreate it if the process rotates its connection.
            connection = tuple(os.getenv(key, "") for key in (
                "AGENTICDOME_API_BASE", "AGENTICDOME_API_KEY", "AGENTICDOME_TENANT_ID",
                "AGENTICDOME_MODE", "AGENTICDOME_EXECUTION_BROKER_MODE",
            ))
            if getattr(thread_client, "connection", None) != connection:
                previous = getattr(thread_client, "runtime", None)
                thread_client.runtime = AgenticDomeClient()
                thread_client.connection = connection
                session = getattr(previous, "session", None)
                if session is not None:
                    session.close()
            runtime = thread_client.runtime
        _authorize(bound, runtime)

    if inspect.iscoroutinefunction(handler):
        @functools.wraps(handler)
        async def secured(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            await asyncio.to_thread(authorize, bound)
            return await handler(*bound.args, **bound.kwargs)
        return secured

    @functools.wraps(handler)
    def secured(*args: Any, **kwargs: Any) -> Any:
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        authorize(bound)
        return handler(*bound.args, **bound.kwargs)
    return secured


__all__ = ["AgenticDomeActionDenied", "guarded_tool_executor"]
