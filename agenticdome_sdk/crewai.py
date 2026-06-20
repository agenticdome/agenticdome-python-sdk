from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from typing import Any, AsyncIterator, Callable, Deque, Dict, List, Optional, Tuple

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
    production_mode: bool = False
    require_explicit_session_id: bool = False
    require_stable_session_id_in_prod: bool = True

    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    require_token_on_delegated_execution: bool = True
    default_tool_platform: str = "unknown"
    handoff_token_ttl_s: int = 900

    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:crewai:handoff"
    token_hmac_secret: str = ""

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

    report_incidents: bool = True
    blocked_incident_severity: str = "medium"


class AgenticDomeCrewAIConfigurationError(RuntimeError):
    """Raised when required AgenticDome CrewAI credentials are missing."""


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


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


CONFIG = FirewallConfig(
    api_base=os.getenv("AGENTICDOME_API_BASE", "").rstrip("/"),
    api_key=os.getenv("AGENTICDOME_API_KEY", ""),
    tenant_id=os.getenv("AGENTICDOME_TENANT_ID", ""),
    platform=os.getenv("AGENTICDOME_PLATFORM", "crewai"),
    timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
    fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
    production_mode=_env_bool("AGENTICDOME_PRODUCTION_MODE", False),
    require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
    require_stable_session_id_in_prod=_env_bool("AGENTICDOME_REQUIRE_STABLE_SESSION_ID_IN_PROD", True),
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
    token_hmac_secret=os.getenv("AGENTICDOME_TOKEN_HMAC_SECRET", ""),
    max_input_chars=_env_int("AGENTICDOME_CREWAI_MAX_INPUT_CHARS", 50_000),
    max_output_chars=_env_int("AGENTICDOME_CREWAI_MAX_OUTPUT_CHARS", 100_000),
    max_tool_arg_chars=_env_int("AGENTICDOME_CREWAI_MAX_TOOL_ARG_CHARS", 20_000),
    streaming_buffer_chars=_env_int("AGENTICDOME_CREWAI_STREAMING_BUFFER_CHARS", 4_000),
    rate_limit_per_minute=_env_int("AGENTICDOME_CREWAI_RATE_LIMIT_PER_MINUTE", 0),
    retry_attempts=_env_int("AGENTICDOME_CREWAI_RETRY_ATTEMPTS", 2),
    retry_backoff_s=_env_float("AGENTICDOME_CREWAI_RETRY_BACKOFF_S", 0.25),
    circuit_breaker_failures=_env_int("AGENTICDOME_CREWAI_CIRCUIT_BREAKER_FAILURES", 5),
    circuit_breaker_reset_s=_env_int("AGENTICDOME_CREWAI_CIRCUIT_BREAKER_RESET_S", 60),
    audit_logging=_env_bool("AGENTICDOME_CREWAI_AUDIT_LOGGING", True),
    otel_enabled=_env_bool("AGENTICDOME_CREWAI_OTEL_ENABLED", True),
    emergency_block_tools=os.getenv("AGENTICDOME_CREWAI_EMERGENCY_BLOCK_TOOLS", ""),
    emergency_block_agents=os.getenv("AGENTICDOME_CREWAI_EMERGENCY_BLOCK_AGENTS", ""),
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


def _configuration_error() -> AgenticDomeCrewAIConfigurationError:
    return AgenticDomeCrewAIConfigurationError(
        "AgenticDome CrewAI firewall requires AGENTICDOME_API_BASE, "
        "AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
    )


def _config_is_complete(config: FirewallConfig) -> bool:
    return bool(config.api_base and config.api_key and config.tenant_id)


# ---------------------------------------------------------------------
# Decision token storage
# ---------------------------------------------------------------------

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
        record = self.get(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        if record is not None:
            self.delete(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        return record


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
            "token_hmac": record.token_hmac,
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
                token_hmac=str(payload.get("token_hmac", "")),
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

    def consume(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        try:
            raw = self.r.execute_command("GETDEL", key)
        except Exception:
            pipe = self.r.pipeline()
            pipe.get(key)
            pipe.delete(key)
            values = pipe.execute()
            raw = values[0] if values else None
        if not raw:
            return None
        try:
            payload = json.loads(raw)
            return DecisionTokenRecord(
                decision_token=str(payload["decision_token"]),
                source_agent_id=str(payload["source_agent_id"]),
                created_at=float(payload.get("created_at", time.time())),
                token_hmac=str(payload.get("token_hmac", "")),
            )
        except Exception:
            return None


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
_RATE_LOCK = Lock()
_RATE_EVENTS: Dict[str, Deque[float]] = defaultdict(deque)
_CIRCUIT_LOCK = Lock()
_CIRCUIT_FAILURES = 0
_CIRCUIT_OPEN_UNTIL = 0.0
_ATTACHED_SCOPES: Dict[int, Dict[str, Any]] = {}


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
        or _safe_getattr(ctx, "request_id")
    )
    if sid:
        return str(sid)
    if CONFIG.require_explicit_session_id or (CONFIG.production_mode and CONFIG.require_stable_session_id_in_prod):
        raise ValueError("Missing stable CrewAI session_id/run_id/trace_id in hook context.")
    return f"crewai-fallback-{uuid.uuid4().hex[:8]}"


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
        or tool_args.get("source_agent_id")
        or tool_args.get("AgenticDome_source_agent_id")
        or _safe_getattr(ctx, "source_agent_id")
    )
    return str(value) if value else None


def _ctx_decision_token(tool_args: Dict[str, Any]) -> Optional[str]:
    value = (
        tool_args.get("_AgenticDome_decision_token")
        or tool_args.get("_decision_token")
        or tool_args.get("decision_token")
        or tool_args.get("AgenticDome_decision_token")
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
        "decision_token",
        "source_agent_id",
        "AgenticDome_decision_token",
        "AgenticDome_source_agent_id",
    }

    return {
        key: value
        for key, value in (args or {}).items()
        if key not in private_keys
        and not key.startswith("_AgenticDome_")
        and not key.startswith("_decision_")
    }


def _circuit_allows_call() -> bool:
    with _CIRCUIT_LOCK:
        return time.time() >= _CIRCUIT_OPEN_UNTIL


def _record_client_success() -> None:
    global _CIRCUIT_FAILURES, _CIRCUIT_OPEN_UNTIL
    with _CIRCUIT_LOCK:
        _CIRCUIT_FAILURES = 0
        _CIRCUIT_OPEN_UNTIL = 0.0


def _record_client_failure() -> None:
    global _CIRCUIT_FAILURES, _CIRCUIT_OPEN_UNTIL
    with _CIRCUIT_LOCK:
        _CIRCUIT_FAILURES += 1
        if CONFIG.circuit_breaker_failures > 0 and _CIRCUIT_FAILURES >= CONFIG.circuit_breaker_failures:
            _CIRCUIT_OPEN_UNTIL = time.time() + max(1, CONFIG.circuit_breaker_reset_s)


def _client_call(method_names: Tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    if CLIENT is None or not _config_is_complete(CONFIG):
        raise _configuration_error()
    if not _circuit_allows_call():
        raise RuntimeError("AgenticDome CrewAI circuit breaker is open.")

    last_error: Optional[Exception] = None
    attempts = max(1, CONFIG.retry_attempts)
    for attempt in range(attempts):
        for method_name in method_names:
            method = getattr(CLIENT, method_name, None)
            if method is None:
                continue
            try:
                result = method(*args, **kwargs)
                _record_client_success()
                return result
            except TypeError as exc:
                last_error = exc
                continue
            except Exception as exc:
                last_error = exc
                _record_client_failure()
                break
        if attempt + 1 < attempts:
            time.sleep(max(0.0, CONFIG.retry_backoff_s) * (2 ** attempt))

    if last_error:
        raise last_error
    raise AttributeError(f"AgenticDome client does not implement any of: {', '.join(method_names)}")



def _bounded_text(text: str, *, limit: int, label: str) -> str:
    if limit > 0 and len(text) > limit:
        return text[:limit] + f"\n[TRUNCATED BY AgenticDome {label}]"
    return text


def _check_rate_limit(*, agent_id: str, session_id: str, purpose: str) -> None:
    limit = CONFIG.rate_limit_per_minute
    if limit <= 0:
        return
    key = f"{agent_id}:{session_id}:{purpose}"
    now = time.time()
    cutoff = now - 60
    with _RATE_LOCK:
        events = _RATE_EVENTS[key]
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= limit:
            raise PermissionError(f"CrewAI rate limit exceeded for {purpose}.")
        events.append(now)


def _enforce_tool_arg_size(tool_name: str, tool_args: Dict[str, Any]) -> None:
    if CONFIG.max_tool_arg_chars > 0 and len(_serialize_result_for_review(tool_args or {})) > CONFIG.max_tool_arg_chars:
        raise PermissionError(f"CrewAI tool arguments exceed max size for {tool_name}.")


def _emergency_policy_check(agent_id: str, tool_name: Optional[str] = None) -> None:
    agents = {item.strip() for item in (CONFIG.emergency_block_agents or "").split(",") if item.strip()}
    tools = {item.strip() for item in (CONFIG.emergency_block_tools or "").split(",") if item.strip()}
    if agent_id in agents:
        raise PermissionError(f"Emergency local policy blocked CrewAI agent: {agent_id}")
    if tool_name and tool_name in tools:
        raise PermissionError(f"Emergency local policy blocked CrewAI tool: {tool_name}")


def _audit(event: str, *, agent_id: str, session_id: str, details: Optional[Dict[str, Any]] = None) -> None:
    if not CONFIG.audit_logging:
        return
    payload = {"event": event, "agent_id": agent_id, "session_id": session_id, "platform": CONFIG.platform}
    if details:
        payload.update(details)
    logger.info("AgenticDome CrewAI audit: %s", json.dumps(payload, sort_keys=True, default=str))


def _otel_event(name: str, attributes: Dict[str, Any]) -> None:
    if not CONFIG.otel_enabled:
        return
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        if span and span.is_recording():
            span.add_event(name, attributes={k: str(v) for k, v in attributes.items()})
    except Exception:
        pass


def _token_hmac(token: str) -> str:
    if not CONFIG.token_hmac_secret or not token:
        return ""
    digest = hmac.new(CONFIG.token_hmac_secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _verify_record_hmac(record: DecisionTokenRecord) -> bool:
    if not CONFIG.token_hmac_secret:
        return True
    return bool(record.token_hmac) and hmac.compare_digest(record.token_hmac, _token_hmac(record.decision_token))


def _sanitized_tool_args(response: Any) -> Optional[Dict[str, Any]]:
    payload = _result_payload(response)
    for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
        value = payload.get(key) if isinstance(payload, dict) else None
        if isinstance(value, dict):
            return _without_agenticdome_private_keys(value)
    return None


def _validate_tool_schema(tool_name: str, tool_args: Dict[str, Any], schema: Optional[Any]) -> None:
    if schema is None:
        return
    if hasattr(schema, "model_validate"):
        schema.model_validate(tool_args)
        return
    if hasattr(schema, "parse_obj"):
        schema.parse_obj(tool_args)
        return
    if not isinstance(schema, dict):
        return
    required = schema.get("required")
    if isinstance(required, list):
        missing = [key for key in required if key not in tool_args]
        if missing:
            raise PermissionError(f"CrewAI tool {tool_name} missing required args: {', '.join(missing)}")
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for key, spec in properties.items():
            if key not in tool_args or not isinstance(spec, dict):
                continue
            expected = spec.get("type")
            value = tool_args[key]
            ok = (
                expected is None
                or expected == "string" and isinstance(value, str)
                or expected == "integer" and isinstance(value, int) and not isinstance(value, bool)
                or expected == "number" and isinstance(value, (int, float)) and not isinstance(value, bool)
                or expected == "boolean" and isinstance(value, bool)
                or expected == "object" and isinstance(value, dict)
                or expected == "array" and isinstance(value, list)
            )
            if not ok:
                raise PermissionError(f"CrewAI tool {tool_name} arg {key} failed schema validation.")

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
        or tool_args.get("delegated_tool_args")
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
        if CLIENT is None or not _config_is_complete(CONFIG):
            raise _configuration_error()

        session_id = _ctx_session_id(context)
        agent_id = _ctx_agent_id(context)
        tool_name, tool_args = _ctx_tool_name_args(context)
        tool_platform = _ctx_tool_platform(context, tool_args)
        _emergency_policy_check(agent_id, tool_name)
        _check_rate_limit(agent_id=agent_id, session_id=session_id, purpose=f"tool:{tool_name}")

        decision_token = _ctx_decision_token(tool_args)
        source_agent_id = _ctx_source_agent_id(context, tool_args)
        clean_tool_args = _without_agenticdome_private_keys(tool_args)

        # Distributed/same-process fallback:
        # If a manager stored a token but CrewAI did not pass it directly,
        # retrieve it by session, target agent, tool, and clean args.
        if not decision_token:
            pending = TOKEN_STORE.consume(
                session_id=session_id,
                target_agent_id=agent_id,
                tool_name=tool_name,
                tool_args=clean_tool_args,
            )

            if pending:
                if not _verify_record_hmac(pending):
                    raise PermissionError("Invalid AgenticDome decision token HMAC for delegated CrewAI execution.")
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

            if not bool(payload.get("valid") or payload.get("allowed")):
                raise PermissionError(
                    f"AgenticDome blocked delegated CrewAI execution: {_reason(response)}"
                )

            TOKEN_STORE.delete(
                session_id=session_id,
                target_agent_id=agent_id,
                tool_name=tool_name,
                tool_args=clean_tool_args,
            )
            _audit("crewai_delegated_execution_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": tool_name})
            return True

        # Case B: Manager handoff routing
        if _is_handoff_tool(tool_name, tool_args):
            target_agent_id = _target_agent_id(tool_args)
            target_tool_name = _target_tool_name(tool_name, tool_args)
            target_args = _target_tool_args(tool_args)
            clean_target_args = _without_agenticdome_private_keys(target_args)
            _enforce_tool_arg_size(target_tool_name, clean_target_args)

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
                        token_hmac=_token_hmac(decision_token),
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

            _audit("crewai_handoff_allowed", agent_id=agent_id, session_id=session_id, details={"target_agent_id": target_agent_id, "tool_name": target_tool_name})
            return True

        # Case C: Direct tool authorization
        _enforce_tool_arg_size(tool_name, clean_tool_args)
        _validate_tool_schema(tool_name, clean_tool_args, _safe_getattr(context, "tool_schema") or _safe_getattr(context, "args_schema"))
        response = _client_call(
            ("guardrail_validate", "guardrailValidate"),
            text=_bounded_text(f"CrewAI agent {agent_id} executing tool {tool_name}", limit=CONFIG.max_input_chars, label="CREWAI TOOL"),
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

        sanitized = _sanitized_tool_args(response)
        if sanitized is not None:
            _validate_tool_schema(tool_name, sanitized, _safe_getattr(context, "tool_schema") or _safe_getattr(context, "args_schema"))
            _write_back_tool_args(context, sanitized)
        _audit("crewai_tool_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": tool_name})
        _otel_event("agenticdome.crewai.tool_allowed", {"agent_id": agent_id, "session_id": session_id, "tool_name": tool_name})
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

        if CLIENT is None or not _config_is_complete(CONFIG):
            raise _configuration_error()

        session_id = _ctx_session_id(context)
        agent_id = _ctx_agent_id(context)

        review_text = _serialize_result_for_review(tool_result)

        _check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="output")
        response = _client_call(
            ("mesh_validate", "meshValidate"),
            agent_id=agent_id,
            session_id=session_id,
            direction="output",
            text=_bounded_text(review_text, limit=CONFIG.max_output_chars, label="CREWAI OUTPUT"),
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
            if isinstance(tool_result, (dict, list, tuple)):
                if sanitized_text == review_text:
                    return tool_result
                try:
                    parsed = json.loads(sanitized_text)
                    if isinstance(parsed, (dict, list)):
                        _safe_setattr_or_dict(context, "tool_result", parsed)
                        return parsed
                except Exception:
                    pass
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
        if CLIENT is None or not _config_is_complete(CONFIG):
            raise _configuration_error()

        session_id = _ctx_session_id(context)
        agent_id = _ctx_agent_id(context)
        _emergency_policy_check(agent_id)
        _check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="input")
        prompt = _extract_prompt(context)

        if not prompt.strip():
            return True

        response = _client_call(
            ("guardrail_validate", "guardrailValidate"),
            text=_bounded_text(prompt, limit=CONFIG.max_input_chars, label="CREWAI INPUT"),
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
        _audit("crewai_prompt_allowed", agent_id=agent_id, session_id=session_id)
        _otel_event("agenticdome.crewai.prompt_allowed", {"agent_id": agent_id, "session_id": session_id})
        return True

    except Exception as exc:
        _report_incident(
            agent_id=agent_id,
            incident_type="crewai_prompt_blocked_or_failed",
            severity=CONFIG.blocked_incident_severity,
            details=str(exc),
        )
        return _block_or_allow_on_error("before_llm_call", exc, agent_id)


async def sanitize_streaming_response(
    chunks: AsyncIterator[Any],
    *,
    agent_id: str,
    session_id: str,
    policy_context: Optional[Dict[str, Any]] = None,
) -> AsyncIterator[str]:
    tail = ""
    async for chunk in chunks:
        text = str(chunk)
        review_text = (tail + text)[-max(1, CONFIG.streaming_buffer_chars):]
        response = _client_call(
            ("mesh_validate", "meshValidate"),
            agent_id=agent_id,
            session_id=session_id,
            direction="output",
            text=_bounded_text(review_text, limit=CONFIG.max_output_chars, label="CREWAI STREAM"),
            platform=CONFIG.platform,
            redact_pii=CONFIG.redact_pii,
            redact_secrets=CONFIG.redact_secrets,
            block_on_sensitive_output=CONFIG.block_on_sensitive_output,
            policy_context={
                "source_agent_id": agent_id,
                "request_purpose": "crewai_streaming_output_review",
                "platform": CONFIG.platform,
                **(policy_context or {}),
            },
        )
        if _verdict(response) == "BLOCKED":
            yield "[OUTPUT BLOCKED BY AGENTICDOME SECURITY POLICY]"
            return
        payload = _result_payload(response)
        sanitized = payload.get("sanitized_text") or payload.get("text") or payload.get("output")
        sanitized_text = str(sanitized) if sanitized is not None else review_text
        if len(sanitized_text) >= len(text) and sanitized_text.endswith(text):
            yield text
        else:
            single = _client_call(
                ("mesh_validate", "meshValidate"),
                agent_id=agent_id,
                session_id=session_id,
                direction="output",
                text=text,
                platform=CONFIG.platform,
                redact_pii=CONFIG.redact_pii,
                redact_secrets=CONFIG.redact_secrets,
                block_on_sensitive_output=CONFIG.block_on_sensitive_output,
                policy_context={"request_purpose": "crewai_streaming_output_review", **(policy_context or {})},
            )
            payload = _result_payload(single)
            yield str(payload.get("sanitized_text") or payload.get("text") or payload.get("output") or text)
        tail = review_text


def _append_hook(existing: Any, hook: Callable[..., Any]) -> List[Any]:
    hooks = list(existing) if isinstance(existing, (list, tuple)) else ([] if existing is None else [existing])
    if hook not in hooks:
        hooks.append(hook)
    return hooks


class AgenticDomeCrewAIFirewall:
    """Class facade for scoped CrewAI integration and tests.

    The module import still registers CrewAI global hooks. This class provides a
    non-global facade for callers that want explicit hook functions or scoped
    attach/unregister behavior on objects that expose hook lists.
    """

    def __init__(
        self,
        *,
        config: Optional[FirewallConfig] = None,
        client: Optional[AgentGuardClient] = None,
        token_store: Optional[DecisionTokenStore] = None,
    ) -> None:
        self.config = config or CONFIG
        self.client = client or CLIENT
        self.token_store = token_store or TOKEN_STORE
        if self.client is None or not _config_is_complete(self.config):
            raise _configuration_error()
        self._attached: Dict[int, Dict[str, Any]] = {}

    def _with_scope(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        global CONFIG, CLIENT, TOKEN_STORE
        old = (CONFIG, CLIENT, TOKEN_STORE)
        CONFIG, CLIENT, TOKEN_STORE = self.config, self.client, self.token_store
        try:
            return fn(*args, **kwargs)
        finally:
            CONFIG, CLIENT, TOKEN_STORE = old

    def before_tool_call(self, context: Any) -> bool:
        return self._with_scope(AgenticDome_before_tool_call, context)

    def after_tool_call(self, context: Any) -> Any:
        return self._with_scope(AgenticDome_after_tool_call, context)

    def before_llm_call(self, context: Any) -> bool:
        return self._with_scope(AgenticDome_before_llm_call, context)

    def attach(self, crew_or_agent: Any) -> Any:
        ident = id(crew_or_agent)
        if ident not in self._attached:
            self._attached[ident] = {
                "before_tool_call_hooks": _safe_getattr(crew_or_agent, "before_tool_call_hooks"),
                "after_tool_call_hooks": _safe_getattr(crew_or_agent, "after_tool_call_hooks"),
                "before_llm_call_hooks": _safe_getattr(crew_or_agent, "before_llm_call_hooks"),
            }
        _safe_setattr_or_dict(crew_or_agent, "before_tool_call_hooks", _append_hook(_safe_getattr(crew_or_agent, "before_tool_call_hooks"), self.before_tool_call))
        _safe_setattr_or_dict(crew_or_agent, "after_tool_call_hooks", _append_hook(_safe_getattr(crew_or_agent, "after_tool_call_hooks"), self.after_tool_call))
        _safe_setattr_or_dict(crew_or_agent, "before_llm_call_hooks", _append_hook(_safe_getattr(crew_or_agent, "before_llm_call_hooks"), self.before_llm_call))
        return crew_or_agent

    def unregister(self, crew_or_agent: Any) -> Any:
        previous = self._attached.pop(id(crew_or_agent), None)
        if not previous:
            return crew_or_agent
        for name, value in previous.items():
            _safe_setattr_or_dict(crew_or_agent, name, value)
        return crew_or_agent

    def secure_tool(
        self,
        *,
        tool_name: str,
        tool_platform: Optional[str] = None,
        tool_schema: Optional[Any] = None,
        sanitize_output: bool = True,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = kwargs.pop("context", None) or (args[0] if args else {})
                tool_args = {k: v for k, v in kwargs.items() if k not in {"session_id", "agent_id", "policy_context"}}
                context = ctx if hasattr(ctx, "__dict__") else type("CrewAIContext", (), {})()
                _safe_setattr_or_dict(context, "tool_name", tool_name)
                _safe_setattr_or_dict(context, "tool_input", dict(tool_args))
                _safe_setattr_or_dict(context, "tool_platform", tool_platform or self.config.default_tool_platform)
                if tool_schema is not None:
                    _safe_setattr_or_dict(context, "tool_schema", tool_schema)
                for key in ("session_id", "agent_id", "policy_context"):
                    if key in kwargs:
                        _safe_setattr_or_dict(context, key, kwargs[key])
                self.before_tool_call(context)
                effective_args = _ctx_tool_name_args(context)[1]
                result = fn(*args, **{**kwargs, **effective_args})
                if not sanitize_output:
                    return result
                out_ctx = type("CrewAIToolOutput", (), {})()
                _safe_setattr_or_dict(out_ctx, "tool_result", result)
                _safe_setattr_or_dict(out_ctx, "session_id", _ctx_session_id(context))
                _safe_setattr_or_dict(out_ctx, "agent_id", _ctx_agent_id(context))
                return self.after_tool_call(out_ctx)
            wrapper.__name__ = getattr(fn, "__name__", "secured_crewai_tool")
            wrapper.__doc__ = getattr(fn, "__doc__", None)
            return wrapper
        return decorator


def attach_firewall(crew_or_agent: Any, *, firewall: Optional[AgenticDomeCrewAIFirewall] = None) -> Any:
    fw = firewall or AgenticDomeCrewAIFirewall()
    return fw.attach(crew_or_agent)


def unregister_firewall(crew_or_agent: Any, *, firewall: Optional[AgenticDomeCrewAIFirewall] = None) -> Any:
    fw = firewall or AgenticDomeCrewAIFirewall()
    return fw.unregister(crew_or_agent)


__all__ = [
    "CONFIG",
    "CLIENT",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "AgenticDomeCrewAIFirewall",
    "AgenticDomeCrewAIConfigurationError",
    "sanitize_streaming_response",
    "attach_firewall",
    "unregister_firewall",
    "AgenticDome_before_tool_call",
    "AgenticDome_after_tool_call",
    "AgenticDome_before_llm_call",
]
