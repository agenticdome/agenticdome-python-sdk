from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from threading import Lock
from typing import Any, Dict, Optional, Tuple

try:
    from crewai.hooks import (
        register_after_tool_call_hook,
        register_before_llm_call_hook,
        register_before_tool_call_hook,
    )
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "CrewAI integration requires CrewAI to be installed. "
        "Install with: pip install 'agenticdome-python-sdk[crewai]'"
    ) from exc

from agenticdome_sdk.client import AgentGuardClient

try:
    from agenticdome_sdk.exceptions import AgentGuardHTTPError
except Exception:  # pragma: no cover
    try:
        from agenticdome_sdk.client import AgentGuardHTTPError  # type: ignore
    except Exception:
        class AgentGuardHTTPError(Exception):  # type: ignore
            pass


logger = logging.getLogger("agenticdome.crewai")
logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class FirewallConfig:
    api_base: str
    api_key: str
    tenant_id: str

    platform: str = "crewai"
    timeout_s: int = 20
    fail_closed: bool = True

    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    require_token_on_delegated_execution: bool = True
    default_tool_platform: str = "unknown"
    handoff_token_ttl_s: int = 900

    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:crewai:handoff"

    report_incidents: bool = True
    blocked_incident_severity: str = "medium"


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


CONFIG = FirewallConfig(
    api_base=os.getenv("AGENTICDOME_API_BASE", "https://au.agenticdome.io").rstrip("/"),
    api_key=os.getenv("AGENTICDOME_API_KEY", ""),
    tenant_id=os.getenv("AGENTICDOME_TENANT_ID", ""),
    platform=os.getenv("AGENTICDOME_PLATFORM", "crewai"),
    timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
    fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
    redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
    redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
    block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
    require_token_on_delegated_execution=_env_bool("AGENTICDOME_REQUIRE_TOKEN", True),
    default_tool_platform=os.getenv("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "unknown"),
    handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
    redis_url=os.getenv("AGENTICDOME_REDIS_URL", "").strip(),
    redis_key_prefix=os.getenv(
        "AGENTICDOME_REDIS_KEY_PREFIX",
        "AgenticDome:crewai:handoff",
    ),
    report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
    blocked_incident_severity=os.getenv("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
)


CLIENT: Optional[AgentGuardClient] = None

if CONFIG.api_base and CONFIG.api_key and CONFIG.tenant_id:
    try:
        CLIENT = AgentGuardClient(
            api_base=CONFIG.api_base,
            api_key=CONFIG.api_key,
            tenant_id=CONFIG.tenant_id,
            timeout=CONFIG.timeout_s,
        )
    except TypeError:
        # Compatibility for alternate constructors.
        CLIENT = AgentGuardClient(  # type: ignore
            CONFIG.api_base,
            {
                "api_key": CONFIG.api_key,
                "tenant_id": CONFIG.tenant_id,
                "timeout": CONFIG.timeout_s,
            },
        )
else:
    logger.warning(
        "AgenticDome CrewAI firewall is unconfigured. "
        "Set AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
    )


# ---------------------------------------------------------------------
# Decision token storage
# ---------------------------------------------------------------------

@dataclass(frozen=True)
class DecisionTokenRecord:
    decision_token: str
    source_agent_id: str
    created_at: float


class DecisionTokenStore:
    def put(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        record: DecisionTokenRecord,
        ttl_s: int,
    ) -> None:
        raise NotImplementedError

    def get(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        raise NotImplementedError

    def delete(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        raise NotImplementedError


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _hash_args(args: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_stable_json(args or {}).encode("utf-8")).hexdigest()


def _tool_fingerprint(tool_name: str, tool_args: Dict[str, Any]) -> str:
    payload = {
        "tool_name": tool_name or "",
        "tool_args": tool_args or {},
    }
    return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()


class InMemoryDecisionTokenStore(DecisionTokenStore):
    def __init__(self) -> None:
        self._lock = Lock()
        self._data: Dict[str, Tuple[float, DecisionTokenRecord]] = {}

    def _key(
        self,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        fp = _tool_fingerprint(tool_name, tool_args)
        return f"{CONFIG.tenant_id}:{session_id}:{target_agent_id}:{fp}"

    def _cleanup(self) -> None:
        now = time.time()
        expired = [
            key for key, (expires_at, _) in self._data.items()
            if expires_at <= now
        ]
        for key in expired:
            self._data.pop(key, None)

    def put(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        record: DecisionTokenRecord,
        ttl_s: int,
    ) -> None:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        with self._lock:
            self._cleanup()
            self._data[key] = (time.time() + ttl_s, record)

    def get(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        with self._lock:
            self._cleanup()
            entry = self._data.get(key)
            return entry[1] if entry else None

    def delete(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        with self._lock:
            self._data.pop(key, None)


class RedisDecisionTokenStore(DecisionTokenStore):
    def __init__(self, url: str, prefix: str) -> None:
        import redis

        self.r = redis.Redis.from_url(url, decode_responses=True)
        self.prefix = prefix.rstrip(":")

    def _key(
        self,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        fp = _tool_fingerprint(tool_name, tool_args)
        return f"{self.prefix}:{CONFIG.tenant_id}:{session_id}:{target_agent_id}:{fp}"

    def put(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        record: DecisionTokenRecord,
        ttl_s: int,
    ) -> None:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        payload = {
            "decision_token": record.decision_token,
            "source_agent_id": record.source_agent_id,
            "created_at": record.created_at,
        }
        self.r.setex(key, ttl_s, json.dumps(payload))

    def get(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        raw = self.r.get(key)
        if not raw:
            return None

        try:
            payload = json.loads(raw)
            return DecisionTokenRecord(
                decision_token=str(payload["decision_token"]),
                source_agent_id=str(payload["source_agent_id"]),
                created_at=float(payload.get("created_at", time.time())),
            )
        except Exception:
            try:
                self.r.delete(key)
            except Exception:
                pass
            return None

    def delete(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        self.r.delete(key)


def _build_token_store() -> DecisionTokenStore:
    if CONFIG.redis_url:
        try:
            logger.info("AgenticDome CrewAI firewall using Redis token store.")
            return RedisDecisionTokenStore(CONFIG.redis_url, CONFIG.redis_key_prefix)
        except ImportError:
            logger.warning(
                "Redis dependency missing. Install with: pip install 'agenticdome-python-sdk[redis]'. "
                "Falling back to in-memory token storage."
            )
        except Exception as exc:
            logger.warning(
                "Redis token store unavailable: %s. Falling back to memory storage.",
                exc,
            )

    return InMemoryDecisionTokenStore()


TOKEN_STORE: DecisionTokenStore = _build_token_store()


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _safe_setattr_or_dict(obj: Any, name: str, value: Any) -> None:
    if obj is None:
        return

    try:
        setattr(obj, name, value)
        return
    except Exception:
        pass

    try:
        if hasattr(obj, "__dict__"):
            obj.__dict__[name] = value
    except Exception:
        pass


def _ctx_session_id(ctx: Any) -> str:
    sid = (
        _safe_getattr(ctx, "session_id")
        or _safe_getattr(ctx, "run_id")
        or _safe_getattr(ctx, "task_id")
        or _safe_getattr(ctx, "trace_id")
        or _safe_getattr(ctx, "crew_id")
    )
    return str(sid) if sid else f"crewai-fallback-{uuid.uuid4().hex[:8]}"


def _ctx_agent_id(ctx: Any) -> str:
    agent = _safe_getattr(ctx, "agent")
    agent_id = (
        _safe_getattr(ctx, "agent_id")
        or _safe_getattr(agent, "agent_id")
        or _safe_getattr(agent, "id")
        or _safe_getattr(agent, "role")
        or _safe_getattr(agent, "name")
    )
    return str(agent_id) if agent_id else "crewai-agent"


def _ctx_source_agent_id(ctx: Any, tool_args: Dict[str, Any]) -> Optional[str]:
    value = (
        tool_args.get("_AgenticDome_source_agent_id")
        or tool_args.get("_source_agent_id")
        or _safe_getattr(ctx, "source_agent_id")
    )
    return str(value) if value else None


def _ctx_decision_token(tool_args: Dict[str, Any]) -> Optional[str]:
    value = (
        tool_args.get("_AgenticDome_decision_token")
        or tool_args.get("_decision_token")
    )
    return str(value) if value else None


def _ctx_tool_name_args(ctx: Any) -> Tuple[str, Dict[str, Any]]:
    tool_name = _safe_getattr(ctx, "tool_name") or "unknown_tool"
    tool_input = _safe_getattr(ctx, "tool_input") or {}

    if not isinstance(tool_input, dict):
        tool_input = {"_raw_input": str(tool_input)}

    return str(tool_name), dict(tool_input)


def _ctx_tool_platform(ctx: Any, tool_args: Dict[str, Any]) -> str:
    value = (
        _safe_getattr(ctx, "tool_platform")
        or tool_args.get("tool_platform")
        or tool_args.get("platform")
        or CONFIG.default_tool_platform
    )
    return str(value)


def _without_agenticdome_private_keys(args: Dict[str, Any]) -> Dict[str, Any]:
    private_keys = {
        "_decision_token",
        "_source_agent_id",
        "_AgenticDome_decision_token",
        "_AgenticDome_source_agent_id",
    }

    return {
        key: value
        for key, value in (args or {}).items()
        if key not in private_keys
        and not key.startswith("_AgenticDome_")
        and not key.startswith("_decision_")
    }


def _client_call(method_names: Tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    if CLIENT is None:
        return None

    last_error: Optional[Exception] = None

    for method_name in method_names:
        method = getattr(CLIENT, method_name, None)
        if method is None:
            continue

        try:
            return method(*args, **kwargs)
        except TypeError as exc:
            last_error = exc
            continue

    if last_error:
        raise last_error

    raise AttributeError(
        f"AgenticDome client does not implement any of: {', '.join(method_names)}"
    )


def _result_payload(response: Any) -> Dict[str, Any]:
    if isinstance(response, dict):
        if isinstance(response.get("result"), dict):
            return response["result"]
        return response
    return {}


def _verdict(response: Any) -> str:
    payload = _result_payload(response)
    return str(payload.get("verdict") or payload.get("decision") or "").upper()


def _reason(response: Any) -> str:
    payload = _result_payload(response)
    return str(payload.get("reason") or payload.get("message") or response)


def _extract_decision_token(response: Any) -> Optional[str]:
    payload = _result_payload(response)
    token = payload.get("decision_token") or payload.get("token")
    return str(token) if token else None


def _report_incident(
    *,
    agent_id: str,
    incident_type: str,
    severity: Optional[str] = None,
    details: str = "",
) -> None:
    if CLIENT is None or not CONFIG.report_incidents:
        return

    try:
        _client_call(
            ("report_incident", "reportIncident"),
            agent_id=agent_id,
            incident_type=incident_type,
            severity=severity or CONFIG.blocked_incident_severity,
            details=details,
            tenant_id=CONFIG.tenant_id,
            is_agent=True,
            platform=CONFIG.platform,
        )
    except Exception as exc:
        logger.debug("AgenticDome incident reporting failed: %s", exc)


def _block_or_allow_on_error(stage: str, exc: Exception, agent_id: str = "unknown") -> bool:
    logger.error("AgenticDome CrewAI %s error: %s", stage, exc)

    _report_incident(
        agent_id=agent_id,
        incident_type=f"agenticdome_{stage}_error",
        severity=CONFIG.blocked_incident_severity,
        details=str(exc),
    )

    return CONFIG.fail_closed is False


def _is_handoff_tool(tool_name: str, tool_args: Optional[Dict[str, Any]] = None) -> bool:
    lower = (tool_name or "").lower()

    if any(
        marker in lower
        for marker in ("delegate", "handoff", "handover", "route", "transfer", "assign", "dispatch")
    ):
        return True

    tool_args = tool_args or {}

    delegation_keys = (
        "coworker",
        "assignee",
        "target_agent",
        "target_agent_id",
        "delegate_to",
        "specialist_agent_id",
        "agent_id",
    )

    return any(key in tool_args for key in delegation_keys)


def _target_agent_id(tool_args: Dict[str, Any]) -> str:
    return str(
        tool_args.get("target_agent_id")
        or tool_args.get("target_agent")
        or tool_args.get("coworker")
        or tool_args.get("assignee")
        or tool_args.get("delegate_to")
        or tool_args.get("agent")
        or tool_args.get("agent_id")
        or tool_args.get("specialist_agent_id")
        or "specialist"
    )


def _target_tool_name(tool_name: str, tool_args: Dict[str, Any]) -> str:
    return str(
        tool_args.get("target_tool_name")
        or tool_args.get("tool_name")
        or tool_args.get("skill_name")
        or tool_name
    )


def _target_tool_args(tool_args: Dict[str, Any]) -> Dict[str, Any]:
    raw = (
        tool_args.get("target_tool_args")
        or tool_args.get("skill_args")
        or tool_args.get("arguments")
        or {}
    )
    if isinstance(raw, dict):
        return dict(raw)
    return {"_raw_input": str(raw)}


def _write_back_tool_args(context: Any, tool_args: Dict[str, Any]) -> None:
    _safe_setattr_or_dict(context, "tool_input", tool_args)




def _serialize_result_for_review(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return str(value)

def _extract_prompt(context: Any) -> str:
    prompt = (
        _safe_getattr(context, "prompt")
        or _safe_getattr(context, "messages")
        or _safe_getattr(context, "input")
        or _safe_getattr(context, "text")
        or ""
    )

    try:
        if isinstance(prompt, (list, tuple, dict)):
            return json.dumps(prompt, default=str)
    except Exception:
        pass

    return str(prompt)


# ---------------------------------------------------------------------
# CrewAI Hooks
# ---------------------------------------------------------------------

@register_before_tool_call_hook
def AgenticDome_before_tool_call(context: Any) -> bool:
    """
    CrewAI before-tool hook.

    Security paths:
    1. Specialist execution with token verification.
    2. Manager-to-specialist handoff authorization.
    3. Direct tool authorization.
    """
    agent_id = "unknown"

    try:
        if CLIENT is None:
            logger.warning("AgenticDome CrewAI firewall unconfigured. Allowing tool call.")
            return True

        session_id = _ctx_session_id(context)
        agent_id = _ctx_agent_id(context)
        tool_name, tool_args = _ctx_tool_name_args(context)
        tool_platform = _ctx_tool_platform(context, tool_args)

        decision_token = _ctx_decision_token(tool_args)
        source_agent_id = _ctx_source_agent_id(context, tool_args)
        clean_tool_args = _without_agenticdome_private_keys(tool_args)

        # Distributed/same-process fallback:
        # If a manager stored a token but CrewAI did not pass it directly,
        # retrieve it by session, target agent, tool, and clean args.
        if not decision_token:
            pending = TOKEN_STORE.get(
                session_id=session_id,
                target_agent_id=agent_id,
                tool_name=tool_name,
                tool_args=clean_tool_args,
            )

            if pending:
                decision_token = pending.decision_token
                source_agent_id = pending.source_agent_id

        # Case A: Specialist delegated execution verification
        if decision_token or source_agent_id:
            if CONFIG.require_token_on_delegated_execution and not decision_token:
                raise PermissionError(
                    "Missing AgenticDome decision token for delegated CrewAI execution."
                )

            if not source_agent_id:
                raise PermissionError(
                    "Missing AgenticDome source agent id for delegated CrewAI execution."
                )

            response = _client_call(
                (
                    "a2a_verify_decision_token_rpc",
                    "a2aVerifyDecisionTokenRpc",
                    "a2a_verify_decision_token",
                ),
                decision_token,
                tool_name=tool_name,
                tool_args=clean_tool_args,
                agent_id=agent_id,
                source_agent_id=source_agent_id,
                platform=CONFIG.platform,
                require_allowed=True,
            )

            payload = _result_payload(response)

            if bool(payload.get("valid")) is not True:
                raise PermissionError(
                    f"AgenticDome blocked delegated CrewAI execution: {_reason(response)}"
                )

            TOKEN_STORE.delete(
                session_id=session_id,
                target_agent_id=agent_id,
                tool_name=tool_name,
                tool_args=clean_tool_args,
            )

            return True

        # Case B: Manager handoff routing
        if _is_handoff_tool(tool_name, tool_args):
            target_agent_id = _target_agent_id(tool_args)
            target_tool_name = _target_tool_name(tool_name, tool_args)
            target_args = _target_tool_args(tool_args)
            clean_target_args = _without_agenticdome_private_keys(target_args)

            response = _client_call(
                ("a2a_authorize_tool", "a2aAuthorizeTool"),
                text=f"CrewAI manager {agent_id} delegating {target_tool_name} to {target_agent_id}",
                agent_id=target_agent_id,
                platform=CONFIG.platform,
                source_platform=CONFIG.platform,
                tool_platform=tool_platform,
                tool_name=target_tool_name,
                tool_args=clean_target_args,
                session_id=session_id,
                direction="outbound",
                source_agent_id=agent_id,
                policy_context={
                    "source_agent_id": agent_id,
                    "request_purpose": "crewai_delegated_task",
                    "platform": CONFIG.platform,
                    "delegation_chain": [agent_id, target_agent_id],
                    "tool_args_hash": _hash_args(clean_target_args),
                },
            )

            if _verdict(response) != "ALLOWED":
                raise PermissionError(
                    f"AgenticDome blocked CrewAI delegation: {_reason(response)}"
                )

            decision_token = _extract_decision_token(response)

            if decision_token:
                TOKEN_STORE.put(
                    session_id=session_id,
                    target_agent_id=target_agent_id,
                    tool_name=target_tool_name,
                    tool_args=clean_target_args,
                    record=DecisionTokenRecord(
                        decision_token=decision_token,
                        source_agent_id=agent_id,
                        created_at=time.time(),
                    ),
                    ttl_s=CONFIG.handoff_token_ttl_s,
                )

                # Inject into router-level args.
                tool_args["_AgenticDome_decision_token"] = decision_token
                tool_args["_AgenticDome_source_agent_id"] = agent_id

                # Inject into nested specialist args.
                target_args["_AgenticDome_decision_token"] = decision_token
                target_args["_AgenticDome_source_agent_id"] = agent_id

                if "target_tool_args" in tool_args or "skill_args" not in tool_args:
                    tool_args["target_tool_args"] = target_args
                else:
                    tool_args["skill_args"] = target_args

                _write_back_tool_args(context, tool_args)

            return True

        # Case C: Direct tool authorization
        response = _client_call(
            ("guardrail_validate", "guardrailValidate"),
            text=f"CrewAI agent {agent_id} executing tool {tool_name}",
            agent_id=agent_id,
            direction="outbound",
            session_id=session_id,
            platform=CONFIG.platform,
            source_platform=CONFIG.platform,
            tool_platform=tool_platform,
            tool_name=tool_name,
            tool_args=clean_tool_args,
            policy_context={
                "source_agent_id": agent_id,
                "request_purpose": "crewai_tool_execution",
                "platform": CONFIG.platform,
                "tool_args_hash": _hash_args(clean_tool_args),
            },
        )

        if _verdict(response) == "BLOCKED":
            raise PermissionError(
                f"AgenticDome blocked CrewAI tool execution: {_reason(response)}"
            )

        return True

    except Exception as exc:
        _report_incident(
            agent_id=agent_id,
            incident_type="crewai_tool_call_blocked_or_failed",
            severity=CONFIG.blocked_incident_severity,
            details=str(exc),
        )
        return _block_or_allow_on_error("before_tool_call", exc, agent_id)


@register_after_tool_call_hook
def AgenticDome_after_tool_call(context: Any) -> Any:
    """
    CrewAI after-tool hook for output DLP and sanitization.
    """
    agent_id = "unknown"

    try:
        tool_result = _safe_getattr(context, "tool_result")
        if tool_result is None:
            return tool_result

        if CLIENT is None:
            return tool_result

        session_id = _ctx_session_id(context)
        agent_id = _ctx_agent_id(context)

        review_text = _serialize_result_for_review(tool_result)

        response = _client_call(
            ("mesh_validate", "meshValidate"),
            agent_id=agent_id,
            session_id=session_id,
            direction="output",
            text=review_text,
            platform=CONFIG.platform,
            redact_pii=CONFIG.redact_pii,
            redact_secrets=CONFIG.redact_secrets,
            block_on_sensitive_output=CONFIG.block_on_sensitive_output,
            policy_context={
                "source_agent_id": agent_id,
                "request_purpose": "crewai_output_review",
                "platform": CONFIG.platform,
                "redact_pii": CONFIG.redact_pii,
                "redact_secrets": CONFIG.redact_secrets,
                "block_on_sensitive_output": CONFIG.block_on_sensitive_output,
            },
        )

        payload = _result_payload(response)
        verdict = _verdict(response)

        if verdict == "BLOCKED":
            _report_incident(
                agent_id=agent_id,
                incident_type="crewai_output_blocked",
                severity=CONFIG.blocked_incident_severity,
                details=_reason(response),
            )

            sanitized = "[OUTPUT BLOCKED BY AGENTICDOME SECURITY POLICY]"
            _safe_setattr_or_dict(context, "tool_result", sanitized)
            return sanitized

        sanitized = (
            payload.get("sanitized_text")
            or payload.get("text")
            or payload.get("output")
        )

        if sanitized is not None:
            sanitized_text = str(sanitized)
            if isinstance(tool_result, (dict, list, tuple)) and sanitized_text == review_text:
                return tool_result
            _safe_setattr_or_dict(context, "tool_result", sanitized_text)
            return sanitized_text

        return tool_result

    except Exception as exc:
        logger.error("AgenticDome CrewAI after_tool_call error: %s", exc)

        _report_incident(
            agent_id=agent_id,
            incident_type="crewai_output_sanitization_failed",
            severity="medium",
            details=str(exc),
        )

        if CONFIG.fail_closed:
            sanitized = "[OUTPUT BLOCKED BY AGENTICDOME SECURITY POLICY]"
            _safe_setattr_or_dict(context, "tool_result", sanitized)
            return sanitized

        return _safe_getattr(context, "tool_result")


@register_before_llm_call_hook
def AgenticDome_before_llm_call(context: Any) -> bool:
    """
    CrewAI before-LLM hook for prompt ingress screening.
    """
    agent_id = "unknown"

    try:
        if CLIENT is None:
            return True

        session_id = _ctx_session_id(context)
        agent_id = _ctx_agent_id(context)
        prompt = _extract_prompt(context)

        if not prompt.strip():
            return True

        response = _client_call(
            ("guardrail_validate", "guardrailValidate"),
            text=prompt,
            agent_id=agent_id,
            direction="input",
            session_id=session_id,
            platform=CONFIG.platform,
            source_platform=CONFIG.platform,
            policy_context={
                "source_agent_id": agent_id,
                "request_purpose": "crewai_prompt_input",
                "platform": CONFIG.platform,
            },
        )

        if _verdict(response) == "BLOCKED":
            raise PermissionError(
                f"AgenticDome blocked CrewAI prompt: {_reason(response)}"
            )

        return True

    except Exception as exc:
        _report_incident(
            agent_id=agent_id,
            incident_type="crewai_prompt_blocked_or_failed",
            severity=CONFIG.blocked_incident_severity,
            details=str(exc),
        )
        return _block_or_allow_on_error("before_llm_call", exc, agent_id)


__all__ = [
    "CONFIG",
    "CLIENT",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "AgenticDome_before_tool_call",
    "AgenticDome_after_tool_call",
    "AgenticDome_before_llm_call",
]