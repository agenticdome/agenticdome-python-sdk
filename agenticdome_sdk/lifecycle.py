"""Privacy-bounded Verified Action lifecycle reporting.

The runtime authorization path remains authoritative. This module reports only
minimized lifecycle evidence through a separately scoped portal credential and
never sends tool arguments, prompts, responses, credentials, or source code.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import logging
import os
import queue
import threading
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, TypeVar


logger = logging.getLogger("AgenticDome.lifecycle")
T = TypeVar("T")
_ACTOR_TYPES = {"agent", "function", "human", "process", "service", "tool", "unknown"}
_OPERATION_TYPES = {"application_action", "data_access", "delegation", "function_call", "mcp_operation", "model_request", "network_request", "process_execution", "tool_call", "unknown"}
_TARGET_TYPES = {"database", "filesystem", "llm", "mcp", "process", "service", "tool", "unknown"}


def _bounded(value: Any, length: int = 128) -> str:
    return str(value or "").strip()[:length]


def _token(value: Any, allowed: set[str], fallback: str) -> str:
    candidate = _bounded(value, 32).lower()
    return candidate if candidate in allowed else fallback


def _digest(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class VerifiedActionContext:
    chain_id: str
    action_id: str
    parent_action_id: Optional[str]
    operation_type: str
    initiator_type: str
    executor_type: str
    target_type: str
    tool_name: Optional[str]
    tool_version: Optional[str]
    arguments_sha256: Optional[str]
    destination_sha256: Optional[str]


class VerifiedActionDenied(RuntimeError):
    """Raised when an explicit authorization callback denies execution."""


class VerifiedActionReporter:
    """Non-blocking, bounded reporter for one tenant's Verified Actions.

    Configure ``AGENTICDOME_EVIDENCE_API_BASE`` and a portal token containing
    only ``evidence:write``. Missing evidence credentials disable reporting;
    they never weaken or bypass the primary AgenticDome authorization call.
    """

    def __init__(self, portal: str = "", access_token: str = "", *, tenant_id: str = "", timeout: float = 5.0, queue_size: int = 256) -> None:
        self.portal = portal.rstrip("/")
        self.access_token = access_token.strip()
        self.tenant_id = tenant_id.strip()
        self.timeout = max(1.0, min(float(timeout), 30.0))
        self._queue: "queue.Queue[tuple[str, Dict[str, Any]] | None]" = queue.Queue(maxsize=max(16, min(int(queue_size), 4096)))
        self._worker: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls, *, tenant_id: str = "") -> "VerifiedActionReporter":
        return cls(
            os.getenv("AGENTICDOME_EVIDENCE_API_BASE", ""),
            os.getenv("AGENTICDOME_EVIDENCE_TOKEN", ""),
            tenant_id=tenant_id or os.getenv("AGENTICDOME_TENANT_ID", ""),
            timeout=float(os.getenv("AGENTICDOME_EVIDENCE_TIMEOUT_S", "5") or "5"),
            queue_size=int(os.getenv("AGENTICDOME_EVIDENCE_QUEUE_SIZE", "256") or "256"),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.portal and self.access_token and self.tenant_id)

    def new_context(self, *, operation_type: str, tool_name: Optional[str] = None, tool_version: Optional[str] = None,
                    arguments: Any = None, destination: Optional[str] = None, chain_id: Optional[str] = None,
                    action_id: Optional[str] = None, parent_action_id: Optional[str] = None,
                    initiator_type: str = "agent", executor_type: str = "tool", target_type: str = "tool") -> VerifiedActionContext:
        return VerifiedActionContext(
            chain_id=_bounded(chain_id or "vac-" + uuid.uuid4().hex),
            action_id=_bounded(action_id or "act-" + uuid.uuid4().hex),
            parent_action_id=_bounded(parent_action_id) or None,
            operation_type=_token(operation_type, _OPERATION_TYPES, "unknown"),
            initiator_type=_token(initiator_type, _ACTOR_TYPES, "unknown"),
            executor_type=_token(executor_type, _ACTOR_TYPES, "unknown"),
            target_type=_token(target_type, _TARGET_TYPES, "unknown"),
            tool_name=_bounded(tool_name, 255) or None,
            tool_version=_bounded(tool_version) or None,
            arguments_sha256=_digest(arguments),
            destination_sha256=_digest(destination),
        )

    def phase(self, context: VerifiedActionContext, phase: str, status: str, *, decision_reference: Optional[str] = None,
              policy_identifier: Optional[str] = None, policy_digest: Optional[str] = None,
              evidence_level: str = "sdk_reported") -> bool:
        if phase not in {"requested", "authorised", "admitted", "attempted"}:
            raise ValueError("Use requested, authorised, admitted or attempted for lifecycle phases; outcomes use outcome().")
        payload = {
            "protocol": "vac/1", "event_id": "evt-" + uuid.uuid4().hex,
            "chain_id": context.chain_id, "action_id": context.action_id,
            "parent_action_id": context.parent_action_id, "phase": phase,
            "status": _bounded(status, 32).lower() or phase, "occurred_at": _now(),
            "actor_type": context.executor_type, "initiator_type": context.initiator_type,
            "executor_type": context.executor_type, "operation_type": context.operation_type,
            "target_type": context.target_type, "tool_name": context.tool_name,
            "tool_version": context.tool_version, "arguments_sha256": context.arguments_sha256,
            "destination_sha256": context.destination_sha256, "decision_jti_sha256": _digest(decision_reference),
            "policy_identifier": _bounded(policy_identifier) or None, "policy_digest": _digest(policy_digest),
            "evidence_level": evidence_level,
            "details": {"initiator_type": context.initiator_type, "executor_type": context.executor_type,
                        "operation_type": context.operation_type, "target_type": context.target_type,
                        "privacy_classification": "application_metadata"},
        }
        return self._enqueue("/api/agentguard/verified-actions/events", payload)

    def outcome(self, context: VerifiedActionContext, outcome_class: str, *, side_effect_reference: Optional[str] = None) -> bool:
        allowed = {"not_attempted", "rejected", "accepted", "succeeded", "partially_succeeded", "failed", "rolled_back", "unknown"}
        outcome = _token(outcome_class, allowed, "unknown")
        now = _now()
        payload = {
            "schema": "agenticdome.outcome-receipt.v1", "tenant_id": self.tenant_id,
            "chain_id": context.chain_id, "action_id": context.action_id,
            "jti": "sdk_" + uuid.uuid4().hex, "outcome_class": outcome,
            "assurance_level": "sdk_reported", "authorised_action_sha256": context.arguments_sha256,
            "observed_action_sha256": context.arguments_sha256, "destination_sha256": context.destination_sha256,
            "side_effect_ref_sha256": _digest(side_effect_reference), "attempted_at": now, "completed_at": now,
        }
        return self._enqueue("/api/agentguard/verified-actions/outcomes", payload)

    def flush(self, timeout: float = 5.0) -> bool:
        if not self.enabled:
            return True
        completed = threading.Event()
        marker = {"_flush_event": completed}
        if not self._enqueue("", marker):
            return False
        return completed.wait(max(0.1, timeout))

    def _enqueue(self, path: str, payload: Dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        self._ensure_worker()
        try:
            self._queue.put_nowait((path, payload))
            return True
        except queue.Full:
            logger.warning("Verified Action evidence queue is full; authorization behavior is unchanged.")
            return False

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker and self._worker.is_alive():
                return
            self._worker = threading.Thread(target=self._run, name="agenticdome-evidence", daemon=True)
            self._worker.start()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is None:
                    return
                path, payload = item
                marker = payload.get("_flush_event")
                if isinstance(marker, threading.Event):
                    marker.set()
                    continue
                request = urllib.request.Request(
                    self.portal + path, data=json.dumps(payload, separators=(",", ":")).encode("utf-8"), method="POST",
                    headers={"Authorization": "Bearer " + self.access_token, "Content-Type": "application/json", "Accept": "application/json"},
                )
                with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - configured AgenticDome portal
                    response.read(1)
            except Exception as exc:  # evidence must never alter the protected operation
                logger.warning("Verified Action evidence delivery failed; authorization behavior is unchanged: %s", exc)
            finally:
                self._queue.task_done()


def verified_action(*, reporter: VerifiedActionReporter, operation_type: str, tool_name: Optional[str] = None,
                    tool_version: Optional[str] = None, destination: Optional[str] = None,
                    initiator_type: str = "agent", executor_type: str = "tool", target_type: str = "tool",
                    argument_builder: Optional[Callable[..., Any]] = None) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Report request/attempt/outcome around a function without inventing authorization phases.

    Existing AgenticDome wrappers should report ``authorised`` and ``admitted``
    from their actual decision response. This decorator records only phases it
    can observe truthfully.
    """
    def decorate(function: Callable[..., T]) -> Callable[..., T]:
        if inspect.iscoroutinefunction(function):
            @functools.wraps(function)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                context = reporter.new_context(operation_type=operation_type, tool_name=tool_name or function.__name__,
                                               tool_version=tool_version, arguments=argument_builder(*args, **kwargs) if argument_builder else None,
                                               destination=destination, initiator_type=initiator_type, executor_type=executor_type,
                                               target_type=target_type)
                reporter.phase(context, "requested", "requested")
                reporter.phase(context, "attempted", "attempted")
                try:
                    result = await function(*args, **kwargs)
                except Exception:
                    reporter.outcome(context, "failed")
                    raise
                reporter.outcome(context, "succeeded")
                return result
            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(function)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            context = reporter.new_context(operation_type=operation_type, tool_name=tool_name or function.__name__,
                                           tool_version=tool_version, arguments=argument_builder(*args, **kwargs) if argument_builder else None,
                                           destination=destination, initiator_type=initiator_type, executor_type=executor_type,
                                           target_type=target_type)
            reporter.phase(context, "requested", "requested")
            reporter.phase(context, "attempted", "attempted")
            try:
                result = function(*args, **kwargs)
            except Exception:
                reporter.outcome(context, "failed")
                raise
            reporter.outcome(context, "succeeded")
            return result
        return sync_wrapper
    return decorate


__all__ = ["VerifiedActionContext", "VerifiedActionDenied", "VerifiedActionReporter", "verified_action"]
