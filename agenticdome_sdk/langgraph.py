from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from typing import Any, AsyncIterator, Callable, Deque, Dict, Iterable, List, Optional, Tuple, cast, Annotated

import anyio
from typing_extensions import TypedDict

from agenticdome_sdk.client import AgenticDomeClient
from agenticdome_sdk._mode import credentials_or_local_sim

try:
    from agenticdome_sdk.exceptions import AgenticDomeHTTPError
except Exception:  # pragma: no cover
    try:
        from agenticdome_sdk.client import AgenticDomeHTTPError  # type: ignore
    except Exception:
        class AgenticDomeHTTPError(Exception):  # type: ignore
            pass


try:
    from langchain_core.messages import SystemMessage
except Exception:  # pragma: no cover
    SystemMessage = None


logger = logging.getLogger("agenticdome.langgraph")
logger.setLevel(logging.INFO)


# ----------------------------------------------------------------------------
# Environment helpers
# ----------------------------------------------------------------------------

def _env(name: str, default: str = "") -> str:
    return os.getenv(name, os.getenv(name.replace("AGENTICDOME", "AgenticDome"), default))


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name, "")
    if value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    value = _env(name, "")
    if value == "":
        return default
    try:
        return int(value)
    except Exception:
        return default


def _env_float(name: str, default: float) -> float:
    value = _env(name, "")
    if value == "":
        return default
    try:
        return float(value)
    except Exception:
        return default


# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class FirewallConfig:
    api_base: str
    api_key: str
    tenant_id: str

    platform: str = "langgraph"
    orchestrator_agent_id: str = "langgraph_orchestrator"
    final_agent_id: str = "langgraph_final_node"

    timeout_s: int = 20
    fail_closed: bool = True
    production_mode: bool = False
    require_explicit_session_id: bool = True
    require_stable_session_id_in_prod: bool = True

    default_tool_platform: str = "unknown"

    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:langgraph:handoff"
    token_hmac_secret: str = ""
    require_server_issued_decision_tokens: bool = False
    strict_delegated_execution: bool = True

    max_input_chars: int = 50_000
    max_output_chars: int = 100_000
    max_tool_arg_chars: int = 20_000
    streaming_buffer_chars: int = 4_000
    rate_limit_per_minute: int = 0
    retry_attempts: int = 2
    retry_backoff_s: float = 0.25
    circuit_breaker_failures: int = 5
    circuit_breaker_reset_s: int = 60
    audit_logging: bool = True
    otel_enabled: bool = True
    emergency_block_tools: str = ""
    emergency_block_agents: str = ""
    cloud_provider: str = ""
    cloud_project_id: str = ""
    identity_provider: str = ""

    report_incidents: bool = True
    blocked_incident_severity: str = "medium"


DEFAULT_CONFIG = FirewallConfig(
    api_base=_env("AGENTICDOME_API_BASE", "").rstrip("/"),
    api_key=_env("AGENTICDOME_API_KEY", ""),
    tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
    platform=_env("AGENTICDOME_PLATFORM", "langgraph"),
    orchestrator_agent_id=_env("AGENTICDOME_LANGGRAPH_AGENT_ID", "langgraph_orchestrator"),
    final_agent_id=_env("AGENTICDOME_LANGGRAPH_FINAL_ID", "langgraph_final_node"),
    timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
    fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
    production_mode=_env_bool("AGENTICDOME_PRODUCTION_MODE", False),
    require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", True),
    require_stable_session_id_in_prod=_env_bool("AGENTICDOME_REQUIRE_STABLE_SESSION_ID_IN_PROD", True),
    default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "unknown"),
    redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
    redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
    block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
    handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
    redis_url=_env("AGENTICDOME_REDIS_URL", "").strip(),
    redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:langgraph:handoff"),
    token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET", ""),
    require_server_issued_decision_tokens=_env_bool("AGENTICDOME_LANGGRAPH_REQUIRE_SERVER_TOKENS", False),
    strict_delegated_execution=_env_bool("AGENTICDOME_LANGGRAPH_STRICT_DELEGATED_EXECUTION", True),
    max_input_chars=_env_int("AGENTICDOME_LANGGRAPH_MAX_INPUT_CHARS", 50_000),
    max_output_chars=_env_int("AGENTICDOME_LANGGRAPH_MAX_OUTPUT_CHARS", 100_000),
    max_tool_arg_chars=_env_int("AGENTICDOME_LANGGRAPH_MAX_TOOL_ARG_CHARS", 20_000),
    streaming_buffer_chars=_env_int("AGENTICDOME_LANGGRAPH_STREAMING_BUFFER_CHARS", 4_000),
    rate_limit_per_minute=_env_int("AGENTICDOME_LANGGRAPH_RATE_LIMIT_PER_MINUTE", 0),
    retry_attempts=_env_int("AGENTICDOME_LANGGRAPH_RETRY_ATTEMPTS", 2),
    retry_backoff_s=_env_float("AGENTICDOME_LANGGRAPH_RETRY_BACKOFF_S", 0.25),
    circuit_breaker_failures=_env_int("AGENTICDOME_LANGGRAPH_CIRCUIT_BREAKER_FAILURES", 5),
    circuit_breaker_reset_s=_env_int("AGENTICDOME_LANGGRAPH_CIRCUIT_BREAKER_RESET_S", 60),
    audit_logging=_env_bool("AGENTICDOME_LANGGRAPH_AUDIT_LOGGING", True),
    otel_enabled=_env_bool("AGENTICDOME_LANGGRAPH_OTEL_ENABLED", True),
    emergency_block_tools=_env("AGENTICDOME_LANGGRAPH_EMERGENCY_BLOCK_TOOLS", ""),
    emergency_block_agents=_env("AGENTICDOME_LANGGRAPH_EMERGENCY_BLOCK_AGENTS", ""),
    cloud_provider=_env("AGENTICDOME_CLOUD_PROVIDER", ""),
    cloud_project_id=_env("AGENTICDOME_CLOUD_PROJECT_ID", ""),
    identity_provider=_env("AGENTICDOME_IDENTITY_PROVIDER", ""),
    report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
    blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
)


# ----------------------------------------------------------------------------
# LangGraph state
# ----------------------------------------------------------------------------

class AgentState(TypedDict, total=False):
    messages: Annotated[list, "Conversation / graph messages"]
    session_id: str
    risk_score: int

    agent_id: str
    current_agent_id: str
    next_agent_id: str
    target_agent_id: str
    user_id: str
    subject_id: str
    account_id: str
    organization_id: str
    tenant_context: str

    policy_context: Dict[str, Any]
    AgenticDome: Dict[str, Any]


# ----------------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------------

class AgenticDomeError(RuntimeError):
    """Base LangGraph integration exception."""


class AgenticDomeDenied(AgenticDomeError):
    """Raised when AgenticDome denies an action."""


class AgenticDomeConfigurationError(AgenticDomeError):
    """Raised when required LangGraph runtime data is missing."""


# ----------------------------------------------------------------------------
# Decision token store
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class DecisionTokenRecord:
    decision_token: str
    source_agent_id: str
    created_at: float
    token_hmac: str = ""


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

    def consume(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        record = self.get(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        if record:
            self.delete(
                session_id=session_id,
                target_agent_id=target_agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
            )
        return record


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        return json.dumps(str(value))


def _hash_args(args: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(args or {}).encode("utf-8")).hexdigest()


def _tool_fingerprint(tool_name: str, tool_args: Dict[str, Any]) -> str:
    payload = {
        "tool_name": tool_name or "",
        "tool_args": tool_args or {},
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


class InMemoryDecisionTokenStore(DecisionTokenStore):
    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id
        self._lock = Lock()
        self._data: Dict[str, Tuple[float, DecisionTokenRecord]] = {}

    def _key(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        fp = _tool_fingerprint(tool_name, tool_args)
        return f"{self._tenant_id}:{session_id}:{target_agent_id}:{fp}"

    def _cleanup(self) -> None:
        now = time.time()
        expired = [key for key, (expires_at, _) in self._data.items() if expires_at <= now]
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
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
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
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
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
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        with self._lock:
            self._data.pop(key, None)

    def consume(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        with self._lock:
            self._cleanup()
            entry = self._data.pop(key, None)
            return entry[1] if entry else None


class RedisDecisionTokenStore(DecisionTokenStore):
    def __init__(self, redis_url: str, key_prefix: str, tenant_id: str) -> None:
        import redis

        self._tenant_id = tenant_id
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = key_prefix.rstrip(":")

    def _key(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        fp = _tool_fingerprint(tool_name, tool_args)
        return f"{self._prefix}:{self._tenant_id}:{session_id}:{target_agent_id}:{fp}"

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
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        payload = {
            "decision_token": record.decision_token,
            "source_agent_id": record.source_agent_id,
            "created_at": record.created_at,
            "token_hmac": record.token_hmac,
        }
        self._client.setex(key, ttl_s, _canonical_json(payload))

    def get(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        raw = self._client.get(key)
        if not raw:
            return None

        try:
            payload = json.loads(raw)
            return DecisionTokenRecord(
                decision_token=str(payload["decision_token"]),
                source_agent_id=str(payload["source_agent_id"]),
                created_at=float(payload["created_at"]),
                token_hmac=str(payload.get("token_hmac") or ""),
            )
        except Exception:
            try:
                self._client.delete(key)
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
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        self._client.delete(key)

    def consume(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        try:
            raw = self._client.getdel(key)
        except Exception:
            raw = None
            try:
                pipe = self._client.pipeline()
                pipe.get(key)
                pipe.delete(key)
                raw = pipe.execute()[0]
            except Exception:
                raw = None
        if not raw:
            return None
        try:
            payload = json.loads(raw)
            return DecisionTokenRecord(
                decision_token=str(payload["decision_token"]),
                source_agent_id=str(payload["source_agent_id"]),
                created_at=float(payload["created_at"]),
                token_hmac=str(payload.get("token_hmac") or ""),
            )
        except Exception:
            return None


def _build_token_store(config: FirewallConfig) -> DecisionTokenStore:
    if config.redis_url:
        try:
            logger.info("AgenticDome LangGraph firewall using Redis token store.")
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id)
        except Exception as exc:
            logger.warning("Redis token store unavailable; falling back to memory. reason=%s", exc)

    return InMemoryDecisionTokenStore(config.tenant_id)


# ----------------------------------------------------------------------------
# Message and tool-call helpers
# ----------------------------------------------------------------------------

def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name)
    except Exception:
        return default


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        return repr(value)


def _state_ns(state: AgentState) -> Dict[str, Any]:
    raw = state.get("AgenticDome")
    ns = dict(raw) if isinstance(raw, dict) else {}
    state["AgenticDome"] = ns
    return ns


def _get_messages(state: AgentState) -> List[Any]:
    msgs = state.get("messages")
    return list(msgs) if isinstance(msgs, list) else []


def _set_messages(state: AgentState, messages: List[Any]) -> AgentState:
    state["messages"] = messages
    return state


def _get_last_message(state: AgentState) -> Any:
    msgs = _get_messages(state)
    return msgs[-1] if msgs else None


def _message_role(msg: Any) -> str:
    if msg is None:
        return ""

    role = _safe_getattr(msg, "type") or _safe_getattr(msg, "role")
    if role:
        return _safe_str(role).lower()

    if isinstance(msg, (tuple, list)) and msg:
        return _safe_str(msg[0]).lower()

    if isinstance(msg, dict):
        return _safe_str(msg.get("type") or msg.get("role")).lower()

    return ""


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if item.get("type") == "text" and "text" in item:
                    parts.append(_safe_str(item.get("text")))
                elif "content" in item:
                    parts.append(_safe_str(item.get("content")))
                else:
                    parts.append(_safe_str(item))
            else:
                parts.append(_safe_str(item))
        return "\n".join(part for part in parts if part)

    return _safe_str(content)


def _message_text(msg: Any) -> str:
    if msg is None:
        return ""

    if hasattr(msg, "content"):
        return _content_to_text(_safe_getattr(msg, "content"))

    if isinstance(msg, (tuple, list)) and len(msg) >= 2:
        return _content_to_text(msg[1])

    if isinstance(msg, dict):
        return _content_to_text(msg.get("content") or msg.get("text") or "")

    return _safe_str(msg)


def _make_system_message(text: str) -> Any:
    if SystemMessage is not None:
        try:
            return SystemMessage(content=text)
        except Exception:
            pass
    return ("system", text)


def _replace_message_content(msg: Any, new_text: str) -> Any:
    if msg is None:
        return _make_system_message(new_text)

    for method_name in ("model_copy", "copy"):
        method = getattr(msg, method_name, None)
        if callable(method):
            try:
                return method(update={"content": new_text})
            except Exception:
                try:
                    return method(deep=True, update={"content": new_text})
                except Exception:
                    pass

    try:
        setattr(msg, "content", new_text)
        return msg
    except Exception:
        role = _message_role(msg) or "assistant"
        return (role, new_text)


def _normalize_tool_args(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    return {"_raw_tool_args": _safe_str(raw)}


def _strip_private_args(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in (args or {}).items()
        if not key.startswith("_agenticdome_")
        and key not in {
            "_decision_token",
            "_source_agent_id",
            "decision_token",
            "source_agent_id",
            "agenticdome_decision_token",
            "agenticdome_source_agent_id",
        }
    }


def _extract_tool_calls(msg: Any) -> List[Dict[str, Any]]:
    if msg is None:
        return []

    direct = _safe_getattr(msg, "tool_calls")
    if isinstance(direct, list):
        return cast(List[Dict[str, Any]], direct)

    ak = _safe_getattr(msg, "additional_kwargs")
    if isinstance(ak, dict) and isinstance(ak.get("tool_calls"), list):
        return cast(List[Dict[str, Any]], ak["tool_calls"])

    if isinstance(msg, dict):
        if isinstance(msg.get("tool_calls"), list):
            return cast(List[Dict[str, Any]], msg["tool_calls"])

        ak2 = msg.get("additional_kwargs")
        if isinstance(ak2, dict) and isinstance(ak2.get("tool_calls"), list):
            return cast(List[Dict[str, Any]], ak2["tool_calls"])

    return []


def _normalize_tool_call(call: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    if "name" in call:
        name = _safe_str(call.get("name") or "unknown_tool")
        args = call.get("args")

        if args is None and "arguments" in call:
            args = call.get("arguments")

        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                args = {"_raw_arguments": args}

        return name, _normalize_tool_args(args)

    fn = call.get("function") or {}
    name = _safe_str(fn.get("name") or "unknown_tool")
    arguments = fn.get("arguments") or {}

    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except Exception:
            arguments = {"_raw_arguments": arguments}

    return name, _normalize_tool_args(arguments)


def _extract_result(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    result = payload.get("result")
    return result if isinstance(result, dict) else payload


def _verdict(payload: Any) -> str:
    env = _extract_result(payload)
    return _safe_str(env.get("verdict") or env.get("decision")).upper()


def _reason(payload: Any) -> str:
    env = _extract_result(payload)
    return _safe_str(env.get("reason") or env.get("message") or payload)


def _detect_delegation_tool_call(
    tool_name: str,
    tool_args: Dict[str, Any],
) -> Tuple[bool, Optional[str], str, Dict[str, Any]]:
    target_agent_id = (
        tool_args.get("target_agent_id")
        or tool_args.get("target_agent")
        or tool_args.get("assignee")
        or tool_args.get("coworker")
        or tool_args.get("delegate_to")
        or tool_args.get("specialist_agent_id")
    )

    target_agent_id = _safe_str(target_agent_id) if target_agent_id else None

    lower_name = (tool_name or "").lower()
    name_indicates_delegation = any(
        marker in lower_name
        for marker in ("route", "coordinate", "delegate", "handoff", "handover", "assign", "dispatch", "transfer")
    )

    delegated_tool_name = _safe_str(
        tool_args.get("delegated_tool_name")
        or tool_args.get("requested_tool_name")
        or tool_args.get("next_tool_name")
        or tool_args.get("target_tool_name")
        or tool_args.get("skill_name")
        or tool_name
        or "langgraph.handoff"
    )

    delegated_tool_args = _normalize_tool_args(
        tool_args.get("delegated_tool_args")
        or tool_args.get("requested_tool_args")
        or tool_args.get("next_tool_args")
        or tool_args.get("target_tool_args")
        or tool_args.get("skill_args")
        or {}
    )

    is_delegation = bool(target_agent_id and name_indicates_delegation)
    return is_delegation, target_agent_id, delegated_tool_name, delegated_tool_args


def _csv_set(value: str) -> set:
    return {item.strip().lower() for item in (value or "").split(",") if item.strip()}


def _bounded_text(value: Any, limit: int, label: str) -> str:
    text = _safe_str(value)
    if limit > 0 and len(text) > limit:
        raise AgenticDomeDenied(f"LangGraph {label} exceeds max size.")
    return text


def _serialized_size(value: Any) -> int:
    return len(_canonical_json(value))


def _parse_structured_like(original: Any, sanitized_text: str) -> Any:
    if isinstance(original, str):
        return sanitized_text
    if isinstance(original, (dict, list, tuple)):
        try:
            parsed = json.loads(sanitized_text)
        except Exception:
            return sanitized_text
        if isinstance(original, tuple) and isinstance(parsed, list):
            return tuple(parsed)
        return parsed
    return sanitized_text


def _extract_sanitized_tool_args(payload: Any) -> Optional[Dict[str, Any]]:
    env = _extract_result(payload)
    value = env.get("sanitized_tool_args") or env.get("sanitized_args") or env.get("sanitized_arguments")
    if value is None and env.get("args_sanitized"):
        value = env.get("tool_args")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return None
    return dict(value) if isinstance(value, dict) else None


def _set_tool_call_args(call: Dict[str, Any], new_args: Dict[str, Any]) -> None:
    if not isinstance(call, dict):
        return
    if "name" in call or "args" in call or "arguments" in call:
        if "arguments" in call and "args" not in call:
            call["arguments"] = _canonical_json(new_args) if isinstance(call.get("arguments"), str) else dict(new_args)
        else:
            call["args"] = dict(new_args)
        return
    fn = call.get("function")
    if isinstance(fn, dict):
        fn["arguments"] = _canonical_json(new_args)


def _token_hmac(secret: str, *, token: str, source_agent_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
    if not secret:
        return ""
    payload = _canonical_json({
        "token": token,
        "source_agent_id": source_agent_id,
        "target_agent_id": target_agent_id,
        "tool_name": tool_name,
        "tool_args_hash": _hash_args(tool_args),
    })
    digest = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


# ----------------------------------------------------------------------------
# Main firewall
# ----------------------------------------------------------------------------

class AgenticDomeLangGraphFirewall:
    """
    AgenticDome firewall for LangGraph.

    Provides:
    - Input screening
    - Tool authorization
    - A2A delegation authorization
    - Delegated decision-token verification
    - Output sanitization / DLP
    - LangGraph node wrappers
    """

    def __init__(self, *, config: FirewallConfig = DEFAULT_CONFIG):
        if not credentials_or_local_sim(config.api_base, config.api_key, config.tenant_id):
            raise ValueError(
                "AgenticDome LangGraph firewall misconfigured. "
                "Set AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
            )

        self.config = config
        self.client = AgenticDomeClient(
            api_base=config.api_base,
            api_key=config.api_key,
            tenant_id=config.tenant_id,
            timeout=config.timeout_s,
        )
        self.token_store = _build_token_store(config)
        self._rate_lock = Lock()
        self._rate_events: Dict[str, Deque[float]] = defaultdict(deque)
        self._circuit_lock = Lock()
        self._circuit_failures = 0
        self._circuit_open_until = 0.0

    def _audit(self, event: str, **fields: Any) -> None:
        if not self.config.audit_logging:
            return
        safe_fields = {
            key: value
            for key, value in fields.items()
            if key not in {"text", "prompt", "output", "tool_args", "decision_token"}
        }
        logger.info("AgenticDome LangGraph audit %s %s", event, _canonical_json(safe_fields))

    def _otel_event(self, event: str, **attrs: Any) -> None:
        if not self.config.otel_enabled:
            return
        try:
            logger.debug("AgenticDome LangGraph otel_event=%s attrs=%s", event, _canonical_json(attrs))
        except Exception:
            pass

    def _check_rate_limit(self, key: str) -> None:
        limit = self.config.rate_limit_per_minute
        if limit <= 0:
            return
        now = time.time()
        cutoff = now - 60
        with self._rate_lock:
            events = self._rate_events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                raise AgenticDomeDenied(f"LangGraph rate limit exceeded for {key}.")
            events.append(now)

    def _enforce_tool_arg_size(self, tool_name: str, tool_args: Dict[str, Any]) -> None:
        limit = self.config.max_tool_arg_chars
        if limit > 0 and _serialized_size(tool_args) > limit:
            raise AgenticDomeDenied(f"LangGraph tool arguments exceed max size for {tool_name}.")

    def _emergency_policy_check(self, *, agent_id: str, tool_name: str = "") -> None:
        blocked_agents = _csv_set(self.config.emergency_block_agents)
        blocked_tools = _csv_set(self.config.emergency_block_tools)
        if agent_id.lower() in blocked_agents:
            raise AgenticDomeDenied(f"LangGraph agent {agent_id} is blocked by local emergency policy.")
        if tool_name and tool_name.lower() in blocked_tools:
            raise AgenticDomeDenied(f"LangGraph tool {tool_name} is blocked by local emergency policy.")

    def _record_client_success(self) -> None:
        with self._circuit_lock:
            self._circuit_failures = 0
            self._circuit_open_until = 0.0

    def _record_client_failure(self) -> None:
        if self.config.circuit_breaker_failures <= 0:
            return
        with self._circuit_lock:
            self._circuit_failures += 1
            if self._circuit_failures >= self.config.circuit_breaker_failures:
                self._circuit_open_until = time.time() + max(1, self.config.circuit_breaker_reset_s)

    def _verify_record_hmac(
        self,
        record: DecisionTokenRecord,
        *,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        if not self.config.token_hmac_secret:
            return
        expected = _token_hmac(
            self.config.token_hmac_secret,
            token=record.decision_token,
            source_agent_id=record.source_agent_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        if not record.token_hmac or not hmac.compare_digest(record.token_hmac, expected):
            raise AgenticDomeDenied("AgenticDome blocked delegated execution: invalid decision token binding.")

    async def _to_thread(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))

    async def _invoke_callable(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        if inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(getattr(fn, "__call__", None)):
            return await fn(*args, **kwargs)
        return await self._to_thread(fn, *args, **kwargs)

    async def _client_call(self, method_names: Tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
        with self._circuit_lock:
            if self._circuit_open_until > time.time():
                raise AgenticDomeError("AgenticDome LangGraph circuit breaker is open.")

        last_type_error: Optional[TypeError] = None
        last_exc: Optional[Exception] = None
        attempts = max(1, self.config.retry_attempts + 1)

        for attempt in range(attempts):
            for method_name in method_names:
                method = getattr(self.client, method_name, None)
                if method is None:
                    continue

                try:
                    result = await self._to_thread(method, *args, **kwargs)
                    self._record_client_success()
                    return result
                except TypeError as exc:
                    last_type_error = exc
                    continue
                except Exception as exc:
                    last_exc = exc
                    break

            if last_exc is None:
                break
            if attempt < attempts - 1 and self.config.retry_backoff_s > 0:
                await anyio.sleep(self.config.retry_backoff_s * (2 ** attempt))

        if last_exc is not None:
            self._record_client_failure()
            raise last_exc
        if last_type_error:
            raise last_type_error

        raise AttributeError(
            f"AgenticDome client does not implement any of: {', '.join(method_names)}"
        )

    def _fail_or_allow(self, message: str, exc: Optional[Exception] = None) -> bool:
        if self.config.fail_closed:
            if exc:
                logger.error("AgenticDome LangGraph FAIL-CLOSED: %s", message, exc_info=exc)
            else:
                logger.error("AgenticDome LangGraph FAIL-CLOSED: %s", message)
            return False

        logger.warning("AgenticDome LangGraph FAIL-OPEN: %s", message)
        return True

    def _resolve_session_id(self, state: AgentState) -> str:
        explicit = state.get("session_id")
        if explicit:
            return str(explicit)

        if self.config.require_explicit_session_id or (
            self.config.production_mode and self.config.require_stable_session_id_in_prod
        ):
            raise AgenticDomeConfigurationError(
                "Missing session_id in LangGraph state. "
                "Set state['session_id'] to a stable correlation ID or disable strict session enforcement."
            )

        sid = f"langgraph-ephemeral-{uuid.uuid4().hex}"
        state["session_id"] = sid
        return sid

    def _resolve_agent_id(self, state: AgentState, explicit: Optional[str], default: str) -> str:
        return (
            explicit
            or _safe_str(
                state.get("current_agent_id")
                or state.get("agent_id")
                or state.get("target_agent_id")
                or default
            )
        )

    def _tool_platform(self, tool_args: Dict[str, Any], override: Optional[str] = None) -> str:
        return _safe_str(
            override
            or tool_args.get("tool_platform")
            or tool_args.get("platform")
            or self.config.default_tool_platform
        )

    def _merged_policy_context(
        self,
        state: AgentState,
        *,
        agent_id: str,
        default_request_purpose: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}

        if isinstance(state.get("policy_context"), dict):
            ctx.update(cast(Dict[str, Any], state["policy_context"]))

        ns = _state_ns(state)
        if isinstance(ns.get("policy_context"), dict):
            ctx.update(cast(Dict[str, Any], ns["policy_context"]))
        lineage = ns.get("lineage_context")
        if isinstance(lineage, dict):
            for key in (
                "user_id",
                "actor_chain",
                "root_jti",
                "parent_jti",
                "scopes",
                "policy_id",
                "policy_version",
                "policy_hash",
            ):
                if lineage.get(key) is not None and key not in ctx:
                    ctx[key] = lineage[key]

        ctx.setdefault("source_agent_id", agent_id)
        ctx.setdefault("request_purpose", default_request_purpose)
        ctx.setdefault("platform", self.config.platform)
        ctx.setdefault("tenant_id", self.config.tenant_id)

        identity_fields = {
            "user_id": state.get("user_id"),
            "subject_id": state.get("subject_id"),
            "account_id": state.get("account_id"),
            "organization_id": state.get("organization_id"),
            "tenant_context": state.get("tenant_context"),
            "cloud_provider": self.config.cloud_provider,
            "cloud_project_id": self.config.cloud_project_id,
            "identity_provider": self.config.identity_provider,
        }
        for key, value in identity_fields.items():
            if value and key not in ctx:
                ctx[key] = value

        if extra:
            ctx.update(extra)

        return ctx

    def _capture_verified_lineage(self, state: AgentState, verification: Dict[str, Any]) -> None:
        claims = verification.get("claims") if isinstance(verification.get("claims"), dict) else {}
        if not claims:
            return
        subject = claims.get("subject") if isinstance(claims.get("subject"), dict) else {}
        policy = claims.get("policy") if isinstance(claims.get("policy"), dict) else {}
        _state_ns(state)["lineage_context"] = {
            "user_id": claims.get("user_id") or subject.get("id"),
            "actor_chain": claims.get("actor_chain") or [],
            "root_jti": claims.get("root_jti") or claims.get("jti"),
            "parent_jti": claims.get("jti"),
            "scopes": claims.get("scopes") or [],
            "policy_id": policy.get("id"),
            "policy_version": policy.get("version"),
            "policy_hash": policy.get("hash"),
        }

    def _extract_explicit_handoff(self, state: AgentState) -> Optional[Dict[str, Any]]:
        ns = _state_ns(state)
        raw = ns.get("handoff") or cast(Dict[str, Any], state).get("handoff")
        return dict(raw) if isinstance(raw, dict) else None

    def _clear_delegation_state(self, state: AgentState) -> None:
        ns = _state_ns(state)
        for key in (
            "decision_token",
            "source_agent_id",
            "target_agent_id",
            "authorized_tool_name",
            "authorized_tool_args",
            "handoff_authorized_at",
        ):
            ns.pop(key, None)

    async def _report_incident_best_effort(
        self,
        *,
        agent_id: str,
        incident_type: str,
        severity: Optional[str] = None,
        details: Optional[str] = None,
    ) -> None:
        if not self.config.report_incidents:
            return

        try:
            await self._client_call(
                ("report_incident", "reportIncident"),
                agent_id=agent_id,
                incident_type=incident_type,
                severity=severity or self.config.blocked_incident_severity,
                details=details,
                tenant_id=self.config.tenant_id,
                is_agent=True,
                platform=self.config.platform,
            )
        except Exception as exc:
            logger.warning("AgenticDome incident reporting failed; continuing. reason=%s", exc)

    async def _block_state(
        self,
        state: AgentState,
        *,
        reason: str,
        agent_id: str,
        incident_type: str,
        severity: Optional[str] = None,
    ) -> AgentState:
        messages = _get_messages(state)
        messages.append(_make_system_message(f"🛑 Security Block: {reason}"))
        _set_messages(state, messages)

        state["risk_score"] = max(int(state.get("risk_score") or 0), 90)

        ns = _state_ns(state)
        ns["blocked"] = True
        ns["reason"] = reason
        ns["blocked_by"] = "AgenticDome"
        ns["blocked_at"] = time.time()
        ns["route"] = "security_block"
        state["next_agent_id"] = "security_block"
        self._audit("blocked", agent_id=agent_id, reason=reason, incident_type=incident_type, severity=severity)
        self._otel_event("agenticdome.langgraph.blocked", agent_id=agent_id, incident_type=incident_type)

        await self._report_incident_best_effort(
            agent_id=agent_id,
            incident_type=incident_type,
            severity=severity,
            details=reason,
        )
        return state

    async def _verify_token_rpc(
        self,
        *,
        token: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        agent_id: str,
        source_agent_id: str,
    ) -> Tuple[bool, Dict[str, Any]]:
        response = await self._client_call(
            ("a2a_verify_decision_token_rpc", "a2aVerifyDecisionTokenRpc", "a2a_verify_decision_token"),
            token,
            tool_name=tool_name,
            tool_args=tool_args,
            agent_id=agent_id,
            source_agent_id=source_agent_id,
            platform=self.config.platform,
            require_allowed=True,
        )
        result = _extract_result(response)
        return bool(result.get("valid") or result.get("allowed")), result

    async def _verify_delegated_execution_if_needed(
        self,
        state: AgentState,
        *,
        session_id: str,
        agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        ns = _state_ns(state)

        clean_args = _strip_private_args(tool_args)

        state_token = _safe_str(ns.get("decision_token"))
        state_source_agent_id = _safe_str(ns.get("source_agent_id"))
        state_target_agent_id = _safe_str(ns.get("target_agent_id"))

        if state_token and state_source_agent_id and (not state_target_agent_id or state_target_agent_id == agent_id):
            valid, verification = await self._verify_token_rpc(
                token=state_token,
                tool_name=tool_name,
                tool_args=clean_args,
                agent_id=agent_id,
                source_agent_id=state_source_agent_id,
            )
            if not valid:
                raise AgenticDomeDenied(f"AgenticDome blocked delegated execution: {_reason(verification)}")

            self._capture_verified_lineage(state, verification)
            self._clear_delegation_state(state)
            return

        arg_token = _safe_str(
            tool_args.get("_agenticdome_decision_token")
            or tool_args.get("_decision_token")
            or tool_args.get("decision_token")
            or tool_args.get("agenticdome_decision_token")
        )
        arg_source = _safe_str(
            tool_args.get("_agenticdome_source_agent_id")
            or tool_args.get("_source_agent_id")
            or tool_args.get("source_agent_id")
            or tool_args.get("agenticdome_source_agent_id")
        )

        if arg_token and arg_source:
            valid, verification = await self._verify_token_rpc(
                token=arg_token,
                tool_name=tool_name,
                tool_args=clean_args,
                agent_id=agent_id,
                source_agent_id=arg_source,
            )
            if not valid:
                raise AgenticDomeDenied(f"AgenticDome blocked delegated execution: {_reason(verification)}")
            self._capture_verified_lineage(state, verification)
            return

        pending = self.token_store.consume(
            session_id=session_id,
            target_agent_id=agent_id,
            tool_name=tool_name,
            tool_args=clean_args,
        )

        if pending:
            self._verify_record_hmac(
                pending,
                target_agent_id=agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
            )
            valid, verification = await self._verify_token_rpc(
                token=pending.decision_token,
                tool_name=tool_name,
                tool_args=clean_args,
                agent_id=agent_id,
                source_agent_id=pending.source_agent_id,
            )
            if not valid:
                raise AgenticDomeDenied(f"AgenticDome blocked delegated execution: {_reason(verification)}")
            self._capture_verified_lineage(state, verification)
            self._audit("delegated_execution_allowed", agent_id=agent_id, source_agent_id=pending.source_agent_id, tool_name=tool_name)
            return

        if self.config.strict_delegated_execution and (
            ns.get("target_agent_id") == agent_id
            or any(key in tool_args for key in (
                "_agenticdome_decision_token",
                "_decision_token",
                "decision_token",
                "agenticdome_decision_token",
                "_agenticdome_source_agent_id",
                "_source_agent_id",
                "source_agent_id",
                "agenticdome_source_agent_id",
            ))
        ):
            raise AgenticDomeDenied("AgenticDome blocked delegated execution: missing valid decision token.")

    async def _authorize_explicit_handoff(
        self,
        state: AgentState,
        *,
        session_id: str,
        manager_agent_id: str,
        handoff: Dict[str, Any],
        fallback_text: str,
    ) -> None:
        target_agent_id = _safe_str(
            handoff.get("target_agent_id")
            or handoff.get("target_agent")
            or handoff.get("assignee")
            or handoff.get("coworker")
            or handoff.get("delegate_to")
            or handoff.get("specialist_agent_id")
        )

        if not target_agent_id:
            raise AgenticDomeConfigurationError("Explicit handoff missing target_agent_id.")

        delegated_tool_name = _safe_str(
            handoff.get("delegated_tool_name")
            or handoff.get("tool_name")
            or handoff.get("target_tool_name")
            or "langgraph.handoff"
        )

        delegated_tool_args = _normalize_tool_args(
            handoff.get("delegated_tool_args")
            or handoff.get("tool_args")
            or handoff.get("target_tool_args")
            or {}
        )

        clean_delegated_args = _strip_private_args(delegated_tool_args)

        tool_platform = self._tool_platform(
            clean_delegated_args,
            override=_safe_str(handoff.get("tool_platform") or ""),
        )

        text = _safe_str(
            handoff.get("text")
            or fallback_text
            or f"[LangGraph] {manager_agent_id} delegates to {target_agent_id}"
        )

        response = await self._client_call(
            ("a2a_authorize_tool", "a2aAuthorizeTool"),
            text=text,
            agent_id=target_agent_id,
            platform=self.config.platform,
            source_platform=self.config.platform,
            tool_platform=tool_platform,
            tool_name=delegated_tool_name,
            tool_args=clean_delegated_args,
            session_id=session_id,
            direction="outbound",
            source_agent_id=manager_agent_id,
            policy_context=self._merged_policy_context(
                state,
                agent_id=manager_agent_id,
                default_request_purpose="delegated_task",
                extra={
                    "source_agent_id": manager_agent_id,
                    "target_agent_id": target_agent_id,
                    "delegation_chain": [manager_agent_id, target_agent_id],
                    "tool_platform": tool_platform,
                    "tool_args_hash": _hash_args(clean_delegated_args),
                },
            ),
        )

        envelope = _extract_result(response)

        if _verdict(envelope) != "ALLOWED":
            raise AgenticDomeDenied(f"AgenticDome blocked delegation: {_reason(envelope)}")

        decision_token = _safe_str(envelope.get("decision_token") or envelope.get("token"))
        decision_id = _safe_str(envelope.get("decision_id") or envelope.get("policy_decision_id") or envelope.get("id"))
        if self.config.require_server_issued_decision_tokens and not decision_token:
            raise AgenticDomeDenied("AgenticDome allowed handoff without a server-issued decision token.")

        if decision_token:
            ns = _state_ns(state)
            ns["decision_token"] = decision_token
            ns["source_agent_id"] = manager_agent_id
            ns["target_agent_id"] = target_agent_id
            ns["authorized_tool_name"] = delegated_tool_name
            ns["authorized_tool_args"] = clean_delegated_args
            ns["handoff_authorized_at"] = time.time()
            if decision_id:
                ns["last_policy_decision_id"] = decision_id

            token_hmac = _token_hmac(
                self.config.token_hmac_secret,
                token=decision_token,
                source_agent_id=manager_agent_id,
                target_agent_id=target_agent_id,
                tool_name=delegated_tool_name,
                tool_args=clean_delegated_args,
            )

            self.token_store.put(
                session_id=session_id,
                target_agent_id=target_agent_id,
                tool_name=delegated_tool_name,
                tool_args=clean_delegated_args,
                record=DecisionTokenRecord(
                    decision_token=decision_token,
                    source_agent_id=manager_agent_id,
                    created_at=time.time(),
                    token_hmac=token_hmac,
                ),
                ttl_s=self.config.handoff_token_ttl_s,
            )

        self._audit("handoff_allowed", agent_id=manager_agent_id, target_agent_id=target_agent_id, tool_name=delegated_tool_name, tool_platform=tool_platform, decision_id=decision_id)
        self._otel_event("agenticdome.langgraph.handoff_allowed", agent_id=manager_agent_id, target_agent_id=target_agent_id)

        ns = _state_ns(state)
        ns.pop("handoff", None)
        cast(Dict[str, Any], state).pop("handoff", None)

    # ------------------------------------------------------------------
    # Public stages
    # ------------------------------------------------------------------

    async def screen_input(self, state: AgentState, *, agent_id: Optional[str] = None) -> AgentState:
        state = cast(AgentState, dict(state))
        last = _get_last_message(state)
        if last is None:
            return state

        text = _message_text(last)
        if not text.strip():
            return state

        effective_agent_id = self._resolve_agent_id(state, agent_id, self.config.orchestrator_agent_id)

        try:
            session_id = self._resolve_session_id(state)
            self._emergency_policy_check(agent_id=effective_agent_id)
            self._check_rate_limit(f"input:{self.config.tenant_id}:{session_id}:{effective_agent_id}")
            text = _bounded_text(text, self.config.max_input_chars, "input")
            response = await self._client_call(
                ("guardrail_validate", "guardrailValidate"),
                session_id=session_id,
                direction="input",
                text=text,
                agent_id=effective_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                policy_context=self._merged_policy_context(
                    state,
                    agent_id=effective_agent_id,
                    default_request_purpose="prompt_input",
                ),
            )

            if _verdict(response) == "BLOCKED":
                return await self._block_state(
                    state,
                    reason=_reason(response),
                    agent_id=effective_agent_id,
                    incident_type="blocked_prompt_input",
                )

            envelope = _extract_result(response)
            decision_id = _safe_str(envelope.get("decision_id") or envelope.get("policy_decision_id") or envelope.get("id"))
            if decision_id:
                _state_ns(state)["last_policy_decision_id"] = decision_id
            self._audit("input_allowed", agent_id=effective_agent_id, session_id=session_id, decision_id=decision_id)
            self._otel_event("agenticdome.langgraph.input_allowed", agent_id=effective_agent_id)
            return state

        except Exception as exc:
            if not self._fail_or_allow(f"AgenticDome input screening error: {exc}", exc=exc):
                return await self._block_state(
                    state,
                    reason=f"firewall input screening error ({exc})",
                    agent_id=effective_agent_id,
                    incident_type="input_screening_error",
                    severity="high",
                )
            return state

    async def authorize_transition(self, state: AgentState, *, agent_id: Optional[str] = None) -> AgentState:
        state = cast(AgentState, dict(state))
        last = _get_last_message(state)
        if last is None:
            return state

        session_id = self._resolve_session_id(state)
        current_agent_id = self._resolve_agent_id(state, agent_id, self.config.orchestrator_agent_id)
        text = _message_text(last)
        tool_calls = _extract_tool_calls(last)

        try:
            self._emergency_policy_check(agent_id=current_agent_id)
            self._check_rate_limit(f"transition:{self.config.tenant_id}:{session_id}:{current_agent_id}")
            text = _bounded_text(text, self.config.max_input_chars, "transition text")
            explicit_handoff = self._extract_explicit_handoff(state)
            if explicit_handoff:
                await self._authorize_explicit_handoff(
                    state,
                    session_id=session_id,
                    manager_agent_id=current_agent_id,
                    handoff=explicit_handoff,
                    fallback_text=text,
                )

            for raw_call in tool_calls:
                tool_name, tool_args = _normalize_tool_call(raw_call)
                clean_tool_args = _strip_private_args(tool_args)
                tool_platform = self._tool_platform(clean_tool_args)
                self._emergency_policy_check(agent_id=current_agent_id, tool_name=tool_name)
                self._enforce_tool_arg_size(tool_name, clean_tool_args)

                await self._verify_delegated_execution_if_needed(
                    state,
                    session_id=session_id,
                    agent_id=current_agent_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                )

                is_delegation, target_agent_id, delegated_tool_name, delegated_tool_args = _detect_delegation_tool_call(
                    tool_name,
                    tool_args,
                )

                if is_delegation and target_agent_id:
                    await self._authorize_explicit_handoff(
                        state,
                        session_id=session_id,
                        manager_agent_id=current_agent_id,
                        handoff={
                            "target_agent_id": target_agent_id,
                            "delegated_tool_name": delegated_tool_name,
                            "delegated_tool_args": delegated_tool_args,
                            "tool_platform": tool_platform,
                            "text": text or f"[LangGraph] {current_agent_id} delegates to {target_agent_id}",
                        },
                        fallback_text=text,
                    )
                    continue

                response = await self._client_call(
                    ("guardrail_validate", "guardrailValidate"),
                    session_id=session_id,
                    direction="outbound",
                    text=text or f"[LangGraph] {current_agent_id} calling {tool_name}",
                    agent_id=current_agent_id,
                    platform=self.config.platform,
                    source_platform=self.config.platform,
                    tool_platform=tool_platform,
                    tool_name=tool_name,
                    tool_args=clean_tool_args,
                    policy_context=self._merged_policy_context(
                        state,
                        agent_id=current_agent_id,
                        default_request_purpose="tool_execution",
                        extra={
                            "tool_args_hash": _hash_args(clean_tool_args),
                            "tool_platform": tool_platform,
                        },
                    ),
                )

                envelope = _extract_result(response)
                if _verdict(envelope) == "BLOCKED":
                    return await self._block_state(
                        state,
                        reason=_reason(envelope),
                        agent_id=current_agent_id,
                        incident_type="blocked_tool_execution",
                    )

                sanitized_args = _extract_sanitized_tool_args(envelope)
                if sanitized_args is not None:
                    self._enforce_tool_arg_size(tool_name, sanitized_args)
                    clean_tool_args = _strip_private_args(sanitized_args)
                    _set_tool_call_args(raw_call, clean_tool_args)

                decision_id = _safe_str(envelope.get("decision_id") or envelope.get("policy_decision_id") or envelope.get("id"))
                if decision_id:
                    _state_ns(state)["last_policy_decision_id"] = decision_id
                self._audit("tool_allowed", agent_id=current_agent_id, session_id=session_id, tool_name=tool_name, tool_platform=tool_platform, decision_id=decision_id)
                self._otel_event("agenticdome.langgraph.tool_allowed", agent_id=current_agent_id, tool_name=tool_name)

            return state

        except AgenticDomeDenied as exc:
            return await self._block_state(
                state,
                reason=str(exc),
                agent_id=current_agent_id,
                incident_type="blocked_delegated_execution",
            )

        except Exception as exc:
            if not self._fail_or_allow(f"AgenticDome transition firewall error: {exc}", exc=exc):
                return await self._block_state(
                    state,
                    reason=f"transition firewall error ({exc})",
                    agent_id=current_agent_id,
                    incident_type="transition_firewall_error",
                    severity="high",
                )
            return state

    async def sanitize_output(
        self,
        state: AgentState,
        *,
        agent_id: Optional[str] = None,
        request_purpose: str = "output_review",
    ) -> AgentState:
        state = cast(AgentState, dict(state))
        last = _get_last_message(state)
        if last is None:
            return state

        text = _message_text(last)
        if not text.strip():
            return state

        session_id = self._resolve_session_id(state)
        effective_agent_id = self._resolve_agent_id(state, agent_id, self.config.final_agent_id)

        try:
            self._emergency_policy_check(agent_id=effective_agent_id)
            self._check_rate_limit(f"output:{self.config.tenant_id}:{session_id}:{effective_agent_id}")
            text = _bounded_text(text, self.config.max_output_chars, "output")
            response = await self._client_call(
                ("mesh_validate", "meshValidate"),
                agent_id=effective_agent_id,
                session_id=session_id,
                direction="output",
                text=text,
                platform=self.config.platform,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._merged_policy_context(
                    state,
                    agent_id=effective_agent_id,
                    default_request_purpose=request_purpose,
                    extra={
                        "redact_pii": self.config.redact_pii,
                        "redact_secrets": self.config.redact_secrets,
                        "block_on_sensitive_output": self.config.block_on_sensitive_output,
                    },
                ),
            )

            envelope = _extract_result(response)
            verdict = _verdict(envelope)

            sanitized_text = (
                envelope.get("text")
                or envelope.get("sanitized_text")
                or envelope.get("output")
                or response.get("text")
                or response.get("sanitized_text")
                if isinstance(response, dict)
                else None
            )

            if verdict == "BLOCKED":
                return await self._block_state(
                    state,
                    reason=_reason(envelope),
                    agent_id=effective_agent_id,
                    incident_type="blocked_output",
                )

            if sanitized_text is not None:
                messages = _get_messages(state)
                if messages:
                    messages[-1] = _replace_message_content(messages[-1], _safe_str(sanitized_text))
                    _set_messages(state, messages)

            decision_id = _safe_str(envelope.get("decision_id") or envelope.get("policy_decision_id") or envelope.get("id"))
            if decision_id:
                _state_ns(state)["last_policy_decision_id"] = decision_id
            self._audit("output_allowed", agent_id=effective_agent_id, session_id=session_id, decision_id=decision_id)
            self._otel_event("agenticdome.langgraph.output_allowed", agent_id=effective_agent_id)
            return state

        except Exception as exc:
            if not self._fail_or_allow(f"AgenticDome output sanitizer error: {exc}", exc=exc):
                return await self._block_state(
                    state,
                    reason=f"output sanitizer error ({exc})",
                    agent_id=effective_agent_id,
                    incident_type="output_mesh_error",
                    severity="high",
                )
            return state

    async def authorize_graph_transition(
        self,
        state: AgentState,
        *,
        from_node: str,
        to_node: str,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentState:
        state = cast(AgentState, dict(state))
        session_id = self._resolve_session_id(state)
        effective_agent_id = self._resolve_agent_id(state, agent_id, self.config.orchestrator_agent_id)
        try:
            self._emergency_policy_check(agent_id=effective_agent_id)
            self._check_rate_limit(f"graph_transition:{self.config.tenant_id}:{session_id}:{effective_agent_id}")
            response = await self._client_call(
                ("guardrail_validate", "guardrailValidate"),
                session_id=session_id,
                direction="graph_transition",
                text=f"[LangGraph] transition {from_node} -> {to_node}",
                agent_id=effective_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform="langgraph",
                tool_name="langgraph.transition",
                tool_args={"from_node": from_node, "to_node": to_node, "metadata": metadata or {}},
                policy_context=self._merged_policy_context(
                    state,
                    agent_id=effective_agent_id,
                    default_request_purpose="graph_transition",
                    extra={"from_node": from_node, "to_node": to_node, **(metadata or {})},
                ),
            )
            envelope = _extract_result(response)
            if _verdict(envelope) == "BLOCKED":
                return await self._block_state(
                    state,
                    reason=_reason(envelope),
                    agent_id=effective_agent_id,
                    incident_type="blocked_graph_transition",
                )
            decision_id = _safe_str(envelope.get("decision_id") or envelope.get("policy_decision_id") or envelope.get("id"))
            if decision_id:
                _state_ns(state)["last_policy_decision_id"] = decision_id
            self._audit("graph_transition_allowed", agent_id=effective_agent_id, session_id=session_id, from_node=from_node, to_node=to_node, decision_id=decision_id)
            return state
        except AgenticDomeDenied as exc:
            return await self._block_state(
                state,
                reason=str(exc),
                agent_id=effective_agent_id,
                incident_type="blocked_graph_transition",
            )
        except Exception as exc:
            if not self._fail_or_allow(f"AgenticDome graph transition authorization error: {exc}", exc=exc):
                return await self._block_state(
                    state,
                    reason=f"graph transition authorization error ({exc})",
                    agent_id=effective_agent_id,
                    incident_type="graph_transition_error",
                    severity="high",
                )
            return state

    def security_route(
        self,
        state: AgentState,
        *,
        allowed_route: str = "continue",
        blocked_route: str = "security_block",
    ) -> str:
        return blocked_route if _state_ns(state).get("blocked") else allowed_route

    async def sanitize_retrieval_documents(
        self,
        documents: Iterable[Any],
        *,
        state: Optional[AgentState] = None,
        agent_id: Optional[str] = None,
        request_purpose: str = "retrieval_context_review",
    ) -> List[Any]:
        working_state: AgentState = cast(AgentState, dict(state or {}))
        if "session_id" not in working_state and state is None and not self.config.require_explicit_session_id:
            working_state["session_id"] = f"langgraph-retrieval-{uuid.uuid4().hex}"
        session_id = self._resolve_session_id(working_state)
        effective_agent_id = self._resolve_agent_id(working_state, agent_id, self.config.orchestrator_agent_id)
        sanitized: List[Any] = []
        for index, doc in enumerate(list(documents)):
            text = _safe_str(
                _safe_getattr(doc, "page_content")
                or _safe_getattr(doc, "content")
                or (doc.get("page_content") if isinstance(doc, dict) else None)
                or (doc.get("content") if isinstance(doc, dict) else None)
                or (doc.get("text") if isinstance(doc, dict) else None)
                or doc
            )
            if not text:
                sanitized.append(doc)
                continue
            text = _bounded_text(text, self.config.max_output_chars, "retrieval document")
            response = await self._client_call(
                ("mesh_validate", "meshValidate"),
                agent_id=effective_agent_id,
                session_id=session_id,
                direction="retrieval",
                text=text,
                platform=self.config.platform,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._merged_policy_context(
                    working_state,
                    agent_id=effective_agent_id,
                    default_request_purpose=request_purpose,
                    extra={"document_index": index},
                ),
            )
            envelope = _extract_result(response)
            if _verdict(envelope) == "BLOCKED":
                raise AgenticDomeDenied(f"AgenticDome blocked retrieval document: {_reason(envelope)}")
            sanitized_text = envelope.get("text") or envelope.get("sanitized_text") or envelope.get("output")
            if sanitized_text is not None and _safe_str(sanitized_text) != text:
                if isinstance(doc, dict):
                    updated = dict(doc)
                    for key in ("page_content", "content", "text"):
                        if key in updated:
                            updated[key] = _safe_str(sanitized_text)
                            break
                    else:
                        updated["text"] = _safe_str(sanitized_text)
                    sanitized.append(updated)
                else:
                    copied = doc
                    changed = False
                    for attr in ("page_content", "content", "text"):
                        if hasattr(copied, attr):
                            try:
                                setattr(copied, attr, _safe_str(sanitized_text))
                                changed = True
                                break
                            except Exception:
                                pass
                    sanitized.append(copied if changed else _safe_str(sanitized_text))
            else:
                sanitized.append(doc)
        self._audit("retrieval_sanitized", agent_id=effective_agent_id, session_id=session_id, document_count=len(sanitized))
        return sanitized

    async def sanitize_streaming_events(
        self,
        events: AsyncIterator[Any],
        *,
        state: AgentState,
        agent_id: Optional[str] = None,
    ) -> AsyncIterator[Any]:
        session_id = self._resolve_session_id(state)
        effective_agent_id = self._resolve_agent_id(state, agent_id, self.config.final_agent_id)
        buffer = ""
        async for event in events:
            text = _safe_str(
                event.get("content") if isinstance(event, dict) else _safe_getattr(event, "content", event)
            )
            if not text:
                yield event
                continue
            buffer = (buffer + text)[-max(1, self.config.streaming_buffer_chars):]
            response = await self._client_call(
                ("mesh_validate", "meshValidate"),
                agent_id=effective_agent_id,
                session_id=session_id,
                direction="stream_output",
                text=buffer,
                platform=self.config.platform,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._merged_policy_context(
                    state,
                    agent_id=effective_agent_id,
                    default_request_purpose="streaming_output_review",
                ),
            )
            envelope = _extract_result(response)
            if _verdict(envelope) == "BLOCKED":
                raise AgenticDomeDenied(f"AgenticDome blocked streaming output: {_reason(envelope)}")
            sanitized_text = envelope.get("text") or envelope.get("sanitized_text") or envelope.get("output")
            if sanitized_text is not None and _safe_str(sanitized_text) != buffer:
                replacement = _safe_str(sanitized_text)[-len(text):] if text else _safe_str(sanitized_text)
                if isinstance(event, dict):
                    updated = dict(event)
                    updated["content"] = replacement
                    yield updated
                elif hasattr(event, "content"):
                    try:
                        setattr(event, "content", replacement)
                        yield event
                    except Exception:
                        yield replacement
                else:
                    yield replacement
            else:
                yield event

    # ------------------------------------------------------------------
    # Node factories
    # ------------------------------------------------------------------

    def input_node(self, *, agent_id: Optional[str] = None) -> Callable[[AgentState], Any]:
        async def _node(state: AgentState) -> AgentState:
            return await self.screen_input(state, agent_id=agent_id)
        return _node

    def transition_node(self, *, agent_id: Optional[str] = None) -> Callable[[AgentState], Any]:
        async def _node(state: AgentState) -> AgentState:
            return await self.authorize_transition(state, agent_id=agent_id)
        return _node

    def graph_transition_node(
        self,
        *,
        from_node: str,
        to_node: str,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Callable[[AgentState], Any]:
        async def _node(state: AgentState) -> AgentState:
            return await self.authorize_graph_transition(
                state,
                from_node=from_node,
                to_node=to_node,
                agent_id=agent_id,
                metadata=metadata,
            )
        return _node

    def output_node(
        self,
        *,
        agent_id: Optional[str] = None,
        request_purpose: str = "output_review",
    ) -> Callable[[AgentState], Any]:
        async def _node(state: AgentState) -> AgentState:
            return await self.sanitize_output(
                state,
                agent_id=agent_id,
                request_purpose=request_purpose,
            )
        return _node

    # Backward-compatible aliases
    input_firewall_node = screen_input
    transition_firewall_node = authorize_transition
    output_firewall_node = sanitize_output

    # ------------------------------------------------------------------
    # Wrappers
    # ------------------------------------------------------------------

    def _merge_state(self, original: AgentState, update: Any) -> AgentState:
        if update is None:
            return cast(AgentState, dict(original))
        if not isinstance(update, dict):
            return cast(AgentState, dict(original))
        merged = dict(original)
        merged.update(update)
        return cast(AgentState, merged)

    def wrap_agent_node(
        self,
        node_fn: Any,
        *,
        agent_id: Optional[str] = None,
        screen_input: bool = True,
        sanitize_output: bool = True,
    ) -> Callable[[AgentState], Any]:
        async def _wrapped(state: AgentState, *args: Any, **kwargs: Any) -> AgentState:
            working = cast(AgentState, dict(state))
            effective_agent_id = self._resolve_agent_id(
                working,
                agent_id,
                self.config.orchestrator_agent_id,
            )
            working["current_agent_id"] = effective_agent_id

            if screen_input:
                working = await self.screen_input(working, agent_id=effective_agent_id)
                if _state_ns(working).get("blocked"):
                    return working

            result = await self._invoke_callable(node_fn, working, *args, **kwargs)
            merged = self._merge_state(working, result)
            merged["current_agent_id"] = effective_agent_id

            if sanitize_output:
                merged = await self.sanitize_output(
                    merged,
                    agent_id=effective_agent_id,
                    request_purpose="agent_node_output",
                )

            return merged

        return _wrapped

    def wrap_tool_node(
        self,
        tool_node: Any,
        *,
        agent_id: Optional[str] = None,
        sanitize_tool_output: bool = True,
    ) -> Callable[[AgentState], Any]:
        async def _wrapped(state: AgentState, *args: Any, **kwargs: Any) -> AgentState:
            working = cast(AgentState, dict(state))
            effective_agent_id = self._resolve_agent_id(
                working,
                agent_id,
                self.config.orchestrator_agent_id,
            )
            working["current_agent_id"] = effective_agent_id

            working = await self.authorize_transition(working, agent_id=effective_agent_id)
            if _state_ns(working).get("blocked"):
                return working

            result = await self._invoke_callable(tool_node, working, *args, **kwargs)
            merged = self._merge_state(working, result)

            if sanitize_tool_output:
                merged = await self.sanitize_output(
                    merged,
                    agent_id=effective_agent_id,
                    request_purpose="tool_output_review",
                )

            return merged

        return _wrapped


    def as_langchain_middleware(
        self,
        *,
        agent_id: Optional[str] = None,
        sanitize_tool_output: bool = True,
    ) -> "AgenticDomeLangChainMiddleware":
        return AgenticDomeLangChainMiddleware(
            firewall=self,
            agent_id=agent_id,
            sanitize_tool_output=sanitize_tool_output,
        )

    async def __call__(self, state: AgentState) -> AgentState:
        state = cast(AgentState, dict(state))
        last = _get_last_message(state)
        if last is None:
            return state

        if self._extract_explicit_handoff(state) or _extract_tool_calls(last):
            return await self.authorize_transition(state)

        role = _message_role(last)
        if role in {"human", "user"}:
            return await self.screen_input(state)

        return await self.sanitize_output(state)

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


class AgenticDomeLangChainMiddleware:
    """Duck-typed LangChain agent middleware for AgenticDome controls.

    LangChain middleware APIs evolve across releases. This adapter intentionally
    avoids importing LangChain classes and exposes the hook names currently used
    by LangChain agents: before_agent, after_agent, and wrap_tool_call.
    """

    name = "agenticdome"

    def __init__(
        self,
        *,
        firewall: AgenticDomeLangGraphFirewall,
        agent_id: Optional[str] = None,
        sanitize_tool_output: bool = True,
    ) -> None:
        self.firewall = firewall
        self.agent_id = agent_id
        self.sanitize_tool_output = sanitize_tool_output

    async def before_agent(self, state: AgentState, runtime: Any = None) -> AgentState:
        return await self.firewall.screen_input(state, agent_id=self.agent_id)

    async def after_agent(self, state: AgentState, runtime: Any = None) -> AgentState:
        return await self.firewall.sanitize_output(state, agent_id=self.agent_id)

    async def wrap_tool_call(self, request: Any, handler: Callable[..., Any]) -> Any:
        state = self._state_from_tool_request(request)
        checked = await self.firewall.authorize_transition(state, agent_id=self.agent_id)
        if _state_ns(checked).get("blocked"):
            raise AgenticDomeDenied(_safe_str(_state_ns(checked).get("reason") or "Tool call blocked"))

        self._apply_checked_tool_call(request, checked)
        result = await self.firewall._invoke_callable(handler, request)
        if not self.sanitize_tool_output or result is None:
            return result

        review_text = _safe_str(result) if not isinstance(result, (dict, list, tuple)) else _canonical_json(result)
        review_state: AgentState = {
            "messages": [("tool", review_text)],
            "session_id": checked.get("session_id", state.get("session_id", "")),
            "agent_id": checked.get("agent_id", state.get("agent_id", self.agent_id or "langchain_agent")),
            "policy_context": {
                "request_purpose": "langchain_tool_output_review",
                "middleware": self.name,
            },
        }
        sanitized_state = await self.firewall.sanitize_output(review_state, agent_id=self.agent_id)
        if _state_ns(sanitized_state).get("blocked"):
            raise AgenticDomeDenied(_safe_str(_state_ns(sanitized_state).get("reason") or "Tool output blocked"))

        sanitized_text = _message_text(_get_last_message(sanitized_state))
        if isinstance(result, (dict, list, tuple)):
            return result if sanitized_text == review_text else _parse_structured_like(result, sanitized_text)
        if isinstance(result, str):
            return sanitized_text
        return result if sanitized_text == review_text else sanitized_text

    def _apply_checked_tool_call(self, request: Any, checked: AgentState) -> None:
        calls = _extract_tool_calls(_get_last_message(checked))
        if not calls:
            return
        sanitized_call = dict(calls[0])
        original = request.get("tool_call") if isinstance(request, dict) else _safe_getattr(request, "tool_call")
        if isinstance(original, dict):
            original.clear()
            original.update(sanitized_call)
            return
        name, args = _normalize_tool_call(sanitized_call)
        if isinstance(request, dict):
            request["tool_call"] = sanitized_call
            request["name"] = name
            request["args"] = args
            return
        try:
            setattr(request, "tool_call", sanitized_call)
        except Exception:
            pass
        for attr, value in (("name", name), ("args", args), ("arguments", args)):
            try:
                setattr(request, attr, value)
            except Exception:
                pass

    def _state_from_tool_request(self, request: Any) -> AgentState:
        tool_call = self._extract_tool_call(request)
        session_id = _safe_str(
            _safe_getattr(request, "session_id")
            or _safe_getattr(request, "run_id")
            or _safe_getattr(request, "thread_id")
            or _safe_getattr(_safe_getattr(request, "runtime"), "thread_id")
            or ""
        )
        state: AgentState = {
            "messages": [{"role": "assistant", "content": "", "tool_calls": [tool_call]}],
            "agent_id": self.agent_id or _safe_str(_safe_getattr(request, "agent_id") or "langchain_agent"),
            "policy_context": {
                "request_purpose": "langchain_tool_authorization",
                "middleware": self.name,
            },
        }
        if session_id:
            state["session_id"] = session_id
        return state

    def _extract_tool_call(self, request: Any) -> Dict[str, Any]:
        raw = request.get("tool_call") if isinstance(request, dict) else _safe_getattr(request, "tool_call")
        if isinstance(raw, dict):
            return raw

        name = (
            _safe_getattr(raw, "name")
            or _safe_getattr(request, "name")
            or _safe_getattr(request, "tool_name")
            or "unknown_tool"
        )
        args = (
            _safe_getattr(raw, "args")
            or _safe_getattr(raw, "arguments")
            or _safe_getattr(request, "args")
            or _safe_getattr(request, "arguments")
            or {}
        )
        return {"name": _safe_str(name), "args": _normalize_tool_args(args)}


__all__ = [
    "FirewallConfig",
    "DEFAULT_CONFIG",
    "AgentState",
    "AgenticDomeError",
    "AgenticDomeDenied",
    "AgenticDomeConfigurationError",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "AgenticDomeLangGraphFirewall",
    "AgenticDomeLangChainMiddleware",
]
