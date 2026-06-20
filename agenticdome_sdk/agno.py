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

from agenticdome_sdk.client import AgentGuardClient

try:
    from agenticdome_sdk.exceptions import AgentGuardHTTPError
except Exception:  # pragma: no cover
    try:
        from agenticdome_sdk.client import AgentGuardHTTPError  # type: ignore
    except Exception:
        class AgentGuardHTTPError(Exception):  # type: ignore
            pass


logger = logging.getLogger("agenticdome.agno")
logger.setLevel(logging.INFO)


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

def _env(name: str, default: str = "") -> str:
    legacy = name.replace("AGENTICDOME", "AgenticDome")
    return os.getenv(name, os.getenv(legacy, default))


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


@dataclass(frozen=True)
class FirewallConfig:
    api_base: str
    api_key: str
    tenant_id: str

    platform: str = "agno"
    timeout_s: int = 20
    fail_closed: bool = True
    require_explicit_session_id: bool = False
    production_mode: bool = False
    require_stable_session_id_in_prod: bool = True

    default_tool_platform: str = "unknown"
    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:agno:handoff"
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


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE", "https://au.agenticdome.io").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        platform=_env("AGENTICDOME_PLATFORM", "agno"),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        production_mode=_env_bool("AGENTICDOME_PRODUCTION_MODE", False),
        require_stable_session_id_in_prod=_env_bool("AGENTICDOME_REQUIRE_STABLE_SESSION_ID_IN_PROD", True),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "unknown"),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
        redis_url=_env("AGENTICDOME_REDIS_URL", "").strip(),
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:agno:handoff"),
        token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET", ""),
        max_input_chars=_env_int("AGENTICDOME_AGNO_MAX_INPUT_CHARS", 50_000),
        max_output_chars=_env_int("AGENTICDOME_AGNO_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_AGNO_MAX_TOOL_ARG_CHARS", 20_000),
        streaming_buffer_chars=_env_int("AGENTICDOME_AGNO_STREAMING_BUFFER_CHARS", 4_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_AGNO_RATE_LIMIT_PER_MINUTE", 0),
        retry_attempts=_env_int("AGENTICDOME_AGNO_RETRY_ATTEMPTS", 2),
        retry_backoff_s=float(_env("AGENTICDOME_AGNO_RETRY_BACKOFF_S", "0.25") or "0.25"),
        circuit_breaker_failures=_env_int("AGENTICDOME_AGNO_CIRCUIT_BREAKER_FAILURES", 5),
        circuit_breaker_reset_s=_env_int("AGENTICDOME_AGNO_CIRCUIT_BREAKER_RESET_S", 60),
        audit_logging=_env_bool("AGENTICDOME_AGNO_AUDIT_LOGGING", True),
        otel_enabled=_env_bool("AGENTICDOME_AGNO_OTEL_ENABLED", True),
        emergency_block_tools=_env("AGENTICDOME_AGNO_EMERGENCY_BLOCK_TOOLS", ""),
        emergency_block_agents=_env("AGENTICDOME_AGNO_EMERGENCY_BLOCK_AGENTS", ""),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
    )


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

class AgenticDomeAgnoError(RuntimeError):
    """Base Agno integration exception."""


class AgenticDomeAgnoDenied(AgenticDomeAgnoError):
    """Raised when AgenticDome blocks Agno execution."""


class AgenticDomeAgnoConfigurationError(AgenticDomeAgnoError):
    """Raised when required Agno runtime context is missing."""


# Backward-compatible aliases for early examples.
AgenticDomeError = AgenticDomeAgnoError
AgenticDomeDenied = AgenticDomeAgnoDenied
AgenticDomeConfigurationError = AgenticDomeAgnoConfigurationError


# -----------------------------------------------------------------------------
# Token stores
# -----------------------------------------------------------------------------

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


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        return json.dumps(str(value))


def _tool_fingerprint(tool_name: str, tool_args: Dict[str, Any]) -> str:
    payload = {"tool_name": tool_name or "", "tool_args": tool_args or {}}
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
                created_at=float(payload.get("created_at", time.time())),
                token_hmac=str(payload.get("token_hmac", "")),
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
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        try:
            raw = self._client.execute_command("GETDEL", key)
        except Exception:
            pipe = self._client.pipeline()
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


def _build_token_store(config: FirewallConfig) -> DecisionTokenStore:
    if config.redis_url:
        try:
            logger.info("AgenticDome Agno firewall using Redis token store.")
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id)
        except Exception as exc:
            logger.warning("Redis token store unavailable; falling back to memory. reason=%s", exc)
    return InMemoryDecisionTokenStore(config.tenant_id)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        if isinstance(obj, dict) and name in obj:
            return obj.get(name)
        return getattr(obj, name)
    except Exception:
        return default


def _safe_setattr_or_dict(obj: Any, name: str, value: Any) -> None:
    if obj is None:
        return
    if isinstance(obj, dict):
        obj[name] = value
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


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        return repr(value)


def _normalize_args(raw: Any) -> Dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"_raw": parsed}
        except Exception:
            return {"_raw": raw}
    return {"_raw": _safe_str(raw)}


def _strip_private_args(args: Dict[str, Any]) -> Dict[str, Any]:
    private_keys = {
        "decision_token",
        "_decision_token",
        "AgenticDome_decision_token",
        "_AgenticDome_decision_token",
        "source_agent_id",
        "_source_agent_id",
        "AgenticDome_source_agent_id",
        "_AgenticDome_source_agent_id",
    }
    return {
        key: value
        for key, value in (args or {}).items()
        if key not in private_keys
        and not str(key).startswith("_AgenticDome_")
        and not str(key).startswith("_decision_")
    }


def _extract_result(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    result = payload.get("result")
    return result if isinstance(result, dict) else payload


def _verdict(payload: Any) -> str:
    result = _extract_result(payload)
    return _safe_str(result.get("verdict") or result.get("decision")).upper()


def _reason(payload: Any) -> str:
    result = _extract_result(payload)
    return _safe_str(result.get("reason") or result.get("message") or payload)


def _callable_name(fn: Callable[..., Any], default: str) -> str:
    return _safe_str(getattr(fn, "__name__", None) or getattr(fn, "name", None) or default)


def _same_hook(left: Any, right: Any) -> bool:
    if left is right:
        return True
    return (
        getattr(left, "__self__", None) is getattr(right, "__self__", object())
        and getattr(left, "__func__", None) is getattr(right, "__func__", object())
    )


def _append_unique_hook(existing: Any, hook: Any) -> List[Any]:
    if existing is None:
        return [hook]
    hooks = list(existing) if isinstance(existing, (list, tuple)) else [existing]
    if all(not _same_hook(item, hook) for item in hooks):
        hooks.append(hook)
    return hooks


def _serialize_for_review(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return _canonical_json(value)
    return _safe_str(value)


def _extract_output_text(run_output: Any) -> str:
    content = _safe_getattr(run_output, "content")
    if content is not None:
        return _safe_str(content)
    text = _safe_getattr(run_output, "text")
    if text is not None:
        return _safe_str(text)
    return _serialize_for_review(run_output)


def _apply_output_text(run_output: Any, new_text: str, original_text: Optional[str] = None) -> Any:
    if isinstance(run_output, str):
        return new_text
    if isinstance(run_output, (dict, list, tuple)):
        if original_text is not None and new_text == original_text:
            return run_output
        try:
            parsed = json.loads(new_text)
            if isinstance(parsed, (dict, list)):
                return parsed
        except Exception:
            pass
    for attr in ("content", "text"):
        if _safe_getattr(run_output, attr) is not None:
            try:
                setattr(run_output, attr, new_text)
                return run_output
            except Exception:
                pass
    return new_text


# -----------------------------------------------------------------------------
# Main firewall
# -----------------------------------------------------------------------------

class AgenticDomeAgnoFirewall:
    """AgenticDome runtime firewall for Agno agents, teams, and workflows."""

    def __init__(
        self,
        *,
        config: Optional[FirewallConfig] = None,
        client: Optional[AgentGuardClient] = None,
        token_store: Optional[DecisionTokenStore] = None,
    ) -> None:
        self.config = config or load_config()

        if not self.config.api_base or not self.config.api_key or not self.config.tenant_id:
            raise AgenticDomeAgnoConfigurationError(
                "AgenticDome Agno firewall misconfigured. "
                "Set AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
            )

        self.client = client or AgentGuardClient(
            api_base=self.config.api_base,
            api_key=self.config.api_key,
            tenant_id=self.config.tenant_id,
            timeout=self.config.timeout_s,
        )
        self.token_store = token_store or _build_token_store(self.config)
        self._rate_lock = Lock()
        self._rate_events: Dict[str, Deque[float]] = defaultdict(deque)
        self._circuit_lock = Lock()
        self._circuit_failures = 0
        self._circuit_open_until = 0.0


    def _circuit_allows_call(self) -> bool:
        with self._circuit_lock:
            return time.time() >= self._circuit_open_until

    def _record_client_success(self) -> None:
        with self._circuit_lock:
            self._circuit_failures = 0
            self._circuit_open_until = 0.0

    def _record_client_failure(self) -> None:
        with self._circuit_lock:
            self._circuit_failures += 1
            if self.config.circuit_breaker_failures > 0 and self._circuit_failures >= self.config.circuit_breaker_failures:
                self._circuit_open_until = time.time() + max(1, self.config.circuit_breaker_reset_s)

    def _client_call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if not self._circuit_allows_call():
            raise AgenticDomeAgnoDenied("AgenticDome Agno circuit breaker is open.")
        last_error: Optional[Exception] = None
        for attempt in range(max(1, self.config.retry_attempts)):
            try:
                result = fn(*args, **kwargs)
                self._record_client_success()
                return result
            except Exception as exc:
                last_error = exc
                self._record_client_failure()
                if attempt + 1 >= max(1, self.config.retry_attempts):
                    break
                time.sleep(max(0.0, self.config.retry_backoff_s) * (2 ** attempt))
        assert last_error is not None
        raise last_error

    def _bounded_text(self, text: str, *, limit: int, label: str) -> str:
        if limit > 0 and len(text) > limit:
            return text[:limit] + f"\n[TRUNCATED BY AgenticDome {label}]"
        return text

    def _check_rate_limit(self, *, agent_id: str, session_id: str, purpose: str) -> None:
        limit = self.config.rate_limit_per_minute
        if limit <= 0:
            return
        key = f"{agent_id}:{session_id}:{purpose}"
        now = time.time()
        cutoff = now - 60
        with self._rate_lock:
            events = self._rate_events[key]
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= limit:
                raise AgenticDomeAgnoDenied(f"Agno rate limit exceeded for {purpose}.")
            events.append(now)

    def _enforce_tool_arg_size(self, *, tool_name: str, tool_args: Dict[str, Any]) -> None:
        if self.config.max_tool_arg_chars > 0 and len(_serialize_for_review(tool_args or {})) > self.config.max_tool_arg_chars:
            raise AgenticDomeAgnoDenied(f"Agno tool arguments exceed max size for {tool_name}.")

    def _emergency_policy_check(self, *, agent_id: str, tool_name: Optional[str] = None) -> None:
        agents = {item.strip() for item in (self.config.emergency_block_agents or "").split(",") if item.strip()}
        tools = {item.strip() for item in (self.config.emergency_block_tools or "").split(",") if item.strip()}
        if agent_id in agents:
            raise AgenticDomeAgnoDenied(f"Emergency local policy blocked Agno agent: {agent_id}")
        if tool_name and tool_name in tools:
            raise AgenticDomeAgnoDenied(f"Emergency local policy blocked Agno tool: {tool_name}")

    def _audit(self, event: str, *, agent_id: str, session_id: str, details: Optional[Dict[str, Any]] = None) -> None:
        if not self.config.audit_logging:
            return
        payload = {"event": event, "agent_id": agent_id, "session_id": session_id, "platform": self.config.platform}
        if details:
            payload.update(details)
        logger.info("AgenticDome Agno audit: %s", json.dumps(payload, sort_keys=True, default=str))

    def _otel_event(self, name: str, attributes: Dict[str, Any]) -> None:
        if not self.config.otel_enabled:
            return
        try:
            from opentelemetry import trace
            span = trace.get_current_span()
            if span and span.is_recording():
                span.add_event(name, attributes={k: _safe_str(v) for k, v in attributes.items()})
        except Exception:
            pass

    def _token_hmac(self, token: str) -> str:
        if not self.config.token_hmac_secret or not token:
            return ""
        digest = hmac.new(self.config.token_hmac_secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _verify_record_hmac(self, record: DecisionTokenRecord) -> bool:
        if not self.config.token_hmac_secret:
            return True
        return bool(record.token_hmac) and hmac.compare_digest(record.token_hmac, self._token_hmac(record.decision_token))

    def _validate_tool_schema(self, *, tool_name: str, tool_args: Dict[str, Any], schema: Optional[Any]) -> None:
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
                raise AgenticDomeAgnoDenied(f"Agno tool {tool_name} missing required args: {', '.join(missing)}")
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
                    raise AgenticDomeAgnoDenied(f"Agno tool {tool_name} arg {key} failed schema validation.")

    def _sanitized_args(self, response: Any) -> Optional[Dict[str, Any]]:
        result = _extract_result(response)
        for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
            value = result.get(key) if isinstance(result, dict) else None
            if isinstance(value, dict):
                return _strip_private_args(value)
        return None

    def _identity_context(self, agent: Any, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}
        for key in (
            "user_id", "principal_id", "caller_id", "tenant_id", "organization_id", "workspace_id",
            "team_id", "workflow_id", "agentos_app_id", "session_id", "run_id", "trace_id",
            "data_classification", "sensitivity_label", "roles", "scopes",
        ):
            value = kwargs.get(key) if isinstance(kwargs, dict) else None
            if value is None:
                value = _safe_getattr(agent, key)
            if value is not None:
                ctx[key] = value
        return ctx

    def _agent_id(self, agent: Any) -> str:
        value = (
            _safe_getattr(agent, "id")
            or _safe_getattr(agent, "agent_id")
            or _safe_getattr(agent, "name")
            or _safe_getattr(agent, "description")
        )
        return _safe_str(value) or "agno_agent"

    def _session_id(self, agent: Any, kwargs: Dict[str, Any]) -> str:
        for key in ("session_id", "conversation_id", "run_id", "task_id", "trace_id", "request_id"):
            value = kwargs.get(key) or _safe_getattr(agent, key)
            if value:
                return _safe_str(value)

        if self.config.require_explicit_session_id or (self.config.production_mode and self.config.require_stable_session_id_in_prod):
            raise AgenticDomeAgnoConfigurationError(
                "Missing stable Agno session_id/run_id/trace_id. Pass a stable session identifier "
                "from the host application or disable production stable-session enforcement for local demos."
            )

        runtime = None
        if hasattr(agent, "__dict__"):
            runtime = agent.__dict__.setdefault("_agenticdome_runtime", {})
            if not runtime.get("ephemeral_session_id"):
                runtime["ephemeral_session_id"] = f"agno-ephemeral-{uuid.uuid4().hex}"
            return _safe_str(runtime["ephemeral_session_id"])

        return f"agno-ephemeral-{uuid.uuid4().hex}"

    def _extract_text(self, kwargs: Dict[str, Any]) -> str:
        value = (
            kwargs.get("input")
            or kwargs.get("text")
            or kwargs.get("prompt")
            or kwargs.get("message")
            or kwargs.get("content")
            or ""
        )
        return _serialize_for_review(value) if isinstance(value, (dict, list, tuple)) else _safe_str(value)

    def _detect_tool_call(self, kwargs: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
        raw_tool = kwargs.get("tool_call") or kwargs.get("tool_execution") or kwargs.get("tool")
        if isinstance(raw_tool, dict):
            name = raw_tool.get("name") or raw_tool.get("tool_name") or raw_tool.get("function", {}).get("name")
            args = raw_tool.get("args") or raw_tool.get("arguments") or raw_tool.get("tool_args") or {}
            return (_safe_str(name) if name else None), _normalize_args(args)

        name = kwargs.get("tool_name") or kwargs.get("tool") or kwargs.get("action") or _safe_getattr(raw_tool, "name")
        args = (
            kwargs.get("tool_args")
            or kwargs.get("tool_input")
            or kwargs.get("arguments")
            or _safe_getattr(raw_tool, "args")
            or _safe_getattr(raw_tool, "arguments")
            or {}
        )
        return (_safe_str(name) if name else None), _normalize_args(args)

    def _tool_platform(self, kwargs: Dict[str, Any], tool_args: Dict[str, Any]) -> str:
        return _safe_str(
            kwargs.get("tool_platform")
            or tool_args.get("tool_platform")
            or tool_args.get("platform")
            or self.config.default_tool_platform
        )

    def _policy_context(
        self,
        kwargs: Dict[str, Any],
        *,
        agent_id: str,
        session_id: str,
        request_purpose: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        raw = kwargs.get("policy_context")
        ctx = dict(raw) if isinstance(raw, dict) else {}
        ctx.setdefault("source_agent_id", agent_id)
        ctx.setdefault("session_id", session_id)
        ctx.setdefault("request_id", str(uuid.uuid4()))
        ctx.setdefault("request_ts_ms", int(time.time() * 1000))
        ctx.setdefault("request_purpose", request_purpose)
        ctx.setdefault("platform", self.config.platform)
        ctx.update({k: v for k, v in self._identity_context(kwargs.get("agent") or {}, kwargs).items() if v is not None and v != ""})
        if extra:
            ctx.update(extra)
        return ctx

    def _incoming_token(self, kwargs: Dict[str, Any], tool_args: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        raw_policy = kwargs.get("policy_context")
        policy_context = raw_policy if isinstance(raw_policy, dict) else {}
        token = (
            kwargs.get("decision_token")
            or kwargs.get("AgenticDome_decision_token")
            or kwargs.get("_AgenticDome_decision_token")
            or kwargs.get("_decision_token")
            or tool_args.get("decision_token")
            or tool_args.get("AgenticDome_decision_token")
            or tool_args.get("_AgenticDome_decision_token")
            or tool_args.get("_decision_token")
            or policy_context.get("decision_token")
            or policy_context.get("AgenticDome_decision_token")
        )
        source = (
            kwargs.get("source_agent_id")
            or kwargs.get("AgenticDome_source_agent_id")
            or kwargs.get("_AgenticDome_source_agent_id")
            or kwargs.get("_source_agent_id")
            or tool_args.get("source_agent_id")
            or tool_args.get("AgenticDome_source_agent_id")
            or tool_args.get("_AgenticDome_source_agent_id")
            or tool_args.get("_source_agent_id")
            or policy_context.get("source_agent_id")
        )
        return (_safe_str(token) if token else None), (_safe_str(source) if source else None)

    def _detect_delegation(
        self,
        agent: Any,
        kwargs: Dict[str, Any],
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
    ) -> Tuple[bool, Optional[str], str, Dict[str, Any]]:
        target = (
            kwargs.get("target_agent_id")
            or kwargs.get("target_agent")
            or kwargs.get("specialist_agent_id")
            or tool_args.get("target_agent_id")
            or tool_args.get("target_agent")
            or tool_args.get("coworker")
            or tool_args.get("assignee")
            or tool_args.get("delegate_to")
            or tool_args.get("specialist_agent_id")
        )
        target_agent_id = _safe_str(target) if target else None
        if not target_agent_id:
            return False, None, tool_name or "agno.delegation", {}

        has_team_semantics = bool(_safe_getattr(agent, "team")) or bool(_safe_getattr(agent, "members"))
        name = (tool_name or "").lower()
        name_indicates_delegation = any(
            marker in name
            for marker in ("route", "coordinate", "delegate", "handoff", "handover", "assign", "transfer")
        )
        if not (has_team_semantics or name_indicates_delegation):
            return False, target_agent_id, tool_name or "agno.delegation", {}

        delegated_tool_name = _safe_str(
            tool_args.get("target_tool_name")
            or tool_args.get("delegated_tool_name")
            or kwargs.get("target_tool_name")
            or tool_name
            or "agno.delegation"
        )
        delegated_tool_args = _normalize_args(
            tool_args.get("target_tool_args")
            or tool_args.get("delegated_tool_args")
            or kwargs.get("target_tool_args")
            or tool_args
        )
        return True, target_agent_id, delegated_tool_name, _strip_private_args(delegated_tool_args)

    def _report_incident_best_effort(
        self,
        *,
        agent_id: str,
        incident_type: str,
        details: str,
        severity: Optional[str] = None,
    ) -> None:
        if not self.config.report_incidents:
            return
        try:
            self._client_call(
                self.client.report_incident,
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

    def _handle_error(self, exc: Exception, context: str) -> bool:
        if isinstance(exc, AgenticDomeAgnoDenied):
            raise exc
        if self.config.fail_closed:
            raise AgenticDomeAgnoDenied(f"AgenticDome fail-closed during {context}: {exc}") from exc
        logger.warning("AgenticDome fail-open during %s: %s", context, exc)
        return True

    def screen_input(self, *, agent: Any, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        session_id = self._session_id(agent, kwargs)
        agent_id = self._agent_id(agent)
        text = self._extract_text(kwargs)
        if not text.strip():
            return {}

        self._emergency_policy_check(agent_id=agent_id)
        self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="input")
        response = self._client_call(
            self.client.guardrail_validate,
            text=self._bounded_text(text, limit=self.config.max_input_chars, label="AGNO INPUT"),
            agent_id=agent_id,
            direction="input",
            session_id=session_id,
            platform=self.config.platform,
            source_platform=self.config.platform,
            policy_context=self._policy_context(
                kwargs,
                agent_id=agent_id,
                session_id=session_id,
                request_purpose="agno_prompt_input",
            ),
        )
        if _verdict(response) == "BLOCKED":
            self._report_incident_best_effort(
                agent_id=agent_id,
                incident_type="blocked_prompt_input",
                details=_reason(response),
            )
            raise AgenticDomeAgnoDenied(f"AgenticDome blocked Agno prompt: {_reason(response)}")
        self._audit("agno_input_allowed", agent_id=agent_id, session_id=session_id)
        self._otel_event("agenticdome.agno.input_allowed", {"agent_id": agent_id, "session_id": session_id})
        return _extract_result(response) or response

    def verify_specialist_execution(
        self,
        *,
        agent_id: str,
        session_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        decision_token: Optional[str] = None,
        source_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_args = _strip_private_args(tool_args)
        token = decision_token
        source = source_agent_id
        if not token:
            pending = self.token_store.consume(
                session_id=session_id,
                target_agent_id=agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
            )
            if pending:
                if not self._verify_record_hmac(pending):
                    raise AgenticDomeAgnoDenied("Invalid AgenticDome decision token HMAC for Agno delegated execution.")
                token = pending.decision_token
                source = pending.source_agent_id

        if not token or not source:
            return {}

        response = self._client_call(
            self.client.a2a_verify_decision_token_rpc,
            token,
            tool_name=tool_name,
            tool_args=clean_args,
            agent_id=agent_id,
            source_agent_id=source,
            platform=self.config.platform,
            require_allowed=True,
        )
        result = _extract_result(response)
        if not bool(result.get("valid") or result.get("allowed")):
            self._report_incident_best_effort(
                agent_id=agent_id,
                incident_type="invalid_delegation_token",
                details=_reason(result),
                severity="high",
            )
            raise AgenticDomeAgnoDenied(f"AgenticDome blocked delegated Agno execution: {_reason(result)}")

        self.token_store.delete(
            session_id=session_id,
            target_agent_id=agent_id,
            tool_name=tool_name,
            tool_args=clean_args,
        )
        self._audit("agno_delegated_execution_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": tool_name})
        return result

    def authorize_manager_handoff(
        self,
        *,
        agent: Any,
        kwargs: Dict[str, Any],
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Dict[str, Any]:
        session_id = self._session_id(agent, kwargs)
        agent_id = self._agent_id(agent)
        clean_args = _strip_private_args(tool_args)
        tool_platform = self._tool_platform(kwargs, clean_args)
        text = self._extract_text(kwargs) or f"[Agno] {agent_id} delegates {tool_name} to {target_agent_id}"

        self._emergency_policy_check(agent_id=agent_id, tool_name=tool_name)
        self._emergency_policy_check(agent_id=target_agent_id, tool_name=tool_name)
        self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose=f"handoff:{target_agent_id}")
        self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_args)
        response = self._client_call(
            self.client.a2a_authorize_tool,
            text=self._bounded_text(text, limit=self.config.max_input_chars, label="AGNO HANDOFF"),
            agent_id=target_agent_id,
            platform=self.config.platform,
            source_platform=self.config.platform,
            tool_platform=tool_platform,
            tool_name=tool_name,
            tool_args=clean_args,
            session_id=session_id,
            direction="outbound",
            source_agent_id=agent_id,
            policy_context=self._policy_context(
                kwargs,
                agent_id=agent_id,
                session_id=session_id,
                request_purpose="agno_delegated_task",
                extra={
                    "target_agent_id": target_agent_id,
                    "delegation_chain": [agent_id, target_agent_id],
                    "tool_platform": tool_platform,
                },
            ),
        )
        result = _extract_result(response)
        if _verdict(result) != "ALLOWED":
            self._report_incident_best_effort(
                agent_id=agent_id,
                incident_type="blocked_delegation",
                details=_reason(result),
            )
            raise AgenticDomeAgnoDenied(f"AgenticDome blocked Agno delegation: {_reason(result)}")

        decision_token = _safe_str(result.get("decision_token") or result.get("token"))
        if decision_token:
            self.token_store.put(
                session_id=session_id,
                target_agent_id=target_agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
                record=DecisionTokenRecord(
                    decision_token=decision_token,
                    source_agent_id=agent_id,
                    created_at=time.time(),
                    token_hmac=self._token_hmac(decision_token),
                ),
                ttl_s=self.config.handoff_token_ttl_s,
            )
        self._audit("agno_handoff_allowed", agent_id=agent_id, session_id=session_id, details={"target_agent_id": target_agent_id, "tool_name": tool_name})
        return result

    def authorize_tool_call(self, *, agent: Any, kwargs: Dict[str, Any], tool_name: str, tool_args: Dict[str, Any], tool_schema: Optional[Any] = None) -> Dict[str, Any]:
        session_id = self._session_id(agent, kwargs)
        agent_id = self._agent_id(agent)
        clean_args = _strip_private_args(tool_args)
        tool_platform = self._tool_platform(kwargs, clean_args)

        self._emergency_policy_check(agent_id=agent_id, tool_name=tool_name)
        self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose=f"tool:{tool_name}")
        self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_args)
        self._validate_tool_schema(tool_name=tool_name, tool_args=clean_args, schema=tool_schema)
        response = self._client_call(
            self.client.guardrail_validate,
            text=self._bounded_text(self._extract_text(kwargs) or f"[Agno] {agent_id} executes {tool_name}", limit=self.config.max_input_chars, label="AGNO TOOL"),
            agent_id=agent_id,
            direction="outbound",
            session_id=session_id,
            platform=self.config.platform,
            source_platform=self.config.platform,
            tool_platform=tool_platform,
            tool_name=tool_name,
            tool_args=clean_args,
            policy_context=self._policy_context(
                kwargs,
                agent_id=agent_id,
                session_id=session_id,
                request_purpose="agno_tool_execution",
                extra={"tool_platform": tool_platform},
            ),
        )
        if _verdict(response) == "BLOCKED":
            self._report_incident_best_effort(
                agent_id=agent_id,
                incident_type="blocked_tool_execution",
                details=_reason(response),
            )
            raise AgenticDomeAgnoDenied(f"AgenticDome blocked Agno tool: {_reason(response)}")
        result = _extract_result(response) or response
        sanitized = self._sanitized_args(response)
        if sanitized is not None:
            self._validate_tool_schema(tool_name=tool_name, tool_args=sanitized, schema=tool_schema)
            result = dict(result or {})
            result["sanitized_tool_args"] = sanitized
        self._audit("agno_tool_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": tool_name})
        self._otel_event("agenticdome.agno.tool_allowed", {"agent_id": agent_id, "session_id": session_id, "tool_name": tool_name})
        return result

    def pre_hook(self, agent: Any = None, *args: Any, **kwargs: Any) -> bool:
        hook_kwargs = dict(kwargs)
        if args and "input" not in hook_kwargs:
            hook_kwargs["input"] = args[0]

        if agent is None:
            agent = hook_kwargs.get("agent") or hook_kwargs.get("team") or hook_kwargs.get("workflow")
        if agent is not None:
            hook_kwargs.setdefault("agent", agent)

        try:
            tool_name, tool_args = self._detect_tool_call(hook_kwargs)
            session_id = self._session_id(agent, hook_kwargs)
            agent_id = self._agent_id(agent)

            if tool_name:
                token, source_agent_id = self._incoming_token(hook_kwargs, tool_args)
                self.verify_specialist_execution(
                    agent_id=agent_id,
                    session_id=session_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    decision_token=token,
                    source_agent_id=source_agent_id,
                )

            is_delegation, target_agent_id, delegated_tool_name, delegated_tool_args = self._detect_delegation(
                agent,
                hook_kwargs,
                tool_name,
                tool_args,
            )
            if is_delegation and target_agent_id:
                self.authorize_manager_handoff(
                    agent=agent,
                    kwargs=hook_kwargs,
                    target_agent_id=target_agent_id,
                    tool_name=delegated_tool_name,
                    tool_args=delegated_tool_args,
                )
                return True

            if tool_name:
                decision = self.authorize_tool_call(
                    agent=agent,
                    kwargs=hook_kwargs,
                    tool_name=tool_name,
                    tool_args=tool_args,
                )
                sanitized = self._sanitized_args(decision)
                if sanitized is not None:
                    hook_kwargs["tool_args"] = sanitized
                    if isinstance(kwargs.get("tool_args"), dict):
                        kwargs["tool_args"].clear()
                        kwargs["tool_args"].update(sanitized)
            else:
                self.screen_input(agent=agent, kwargs=hook_kwargs)
            return True
        except (AgenticDomeAgnoDenied, AgenticDomeAgnoConfigurationError, AgentGuardHTTPError) as exc:
            return self._handle_error(exc, "agno pre_hook")
        except Exception as exc:
            return self._handle_error(exc, "agno pre_hook")

    def tool_hook(self, *args: Any, **kwargs: Any) -> Any:
        agent = kwargs.get("agent") or kwargs.get("team") or kwargs.get("workflow")
        if args and agent is None:
            agent = args[0]
        if agent is None:
            agent = {}
        self.pre_hook(agent, **kwargs)
        return kwargs.get("tool_result") or kwargs.get("result") or True

    def sanitize_output(self, *, run_output: Any, agent: Any, kwargs: Dict[str, Any]) -> Any:
        session_id = self._session_id(agent, kwargs)
        agent_id = self._agent_id(agent)
        output_text = _extract_output_text(run_output)

        self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="output")
        response = self._client_call(
            self.client.mesh_validate,
            agent_id=agent_id,
            session_id=session_id,
            direction="output",
            text=self._bounded_text(output_text, limit=self.config.max_output_chars, label="AGNO OUTPUT"),
            platform=self.config.platform,
            redact_pii=self.config.redact_pii,
            redact_secrets=self.config.redact_secrets,
            block_on_sensitive_output=self.config.block_on_sensitive_output,
            policy_context=self._policy_context(
                kwargs,
                agent_id=agent_id,
                session_id=session_id,
                request_purpose="agno_output_review",
                extra={
                    "redact_pii": self.config.redact_pii,
                    "redact_secrets": self.config.redact_secrets,
                    "block_on_sensitive_output": self.config.block_on_sensitive_output,
                },
            ),
        )
        result = _extract_result(response)
        if _verdict(result) == "BLOCKED":
            self._report_incident_best_effort(
                agent_id=agent_id,
                incident_type="blocked_output",
                details=_reason(result),
            )
            return _apply_output_text(run_output, "[OUTPUT BLOCKED BY AgenticDome]", original_text=output_text)

        sanitized = (
            result.get("text")
            or result.get("sanitized_text")
            or result.get("output")
            or (response.get("text") if isinstance(response, dict) else None)
            or (response.get("sanitized_text") if isinstance(response, dict) else None)
        )
        if sanitized is not None:
            return _apply_output_text(run_output, _safe_str(sanitized), original_text=output_text)
        return run_output

    def post_hook(self, run_output: Any = None, agent: Any = None, *args: Any, **kwargs: Any) -> Any:
        if run_output is None and args:
            run_output = args[0]
        if agent is None:
            agent = kwargs.get("agent") or kwargs.get("team") or kwargs.get("workflow")
        if agent is None:
            agent = {}

        try:
            return self.sanitize_output(run_output=run_output, agent=agent, kwargs=dict(kwargs))
        except Exception as exc:
            if self.config.fail_closed:
                logger.warning("AgenticDome Agno output review failed closed: %s", exc)
                return _apply_output_text(run_output, "[OUTPUT BLOCKED BY AgenticDome]", original_text=_extract_output_text(run_output))
            logger.warning("AgenticDome Agno output review failed open: %s", exc)
            return run_output

    def sanitize_retrieved_text(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="retrieval")
        response = self._client_call(
            self.client.mesh_validate,
            agent_id=agent_id,
            session_id=session_id,
            direction="output",
            text=self._bounded_text(text, limit=self.config.max_output_chars, label="AGNO RETRIEVAL"),
            platform=self.config.platform,
            redact_pii=self.config.redact_pii,
            redact_secrets=self.config.redact_secrets,
            block_on_sensitive_output=self.config.block_on_sensitive_output,
            policy_context={
                "request_purpose": "agno_retrieved_context_review",
                "platform": self.config.platform,
                **(policy_context or {}),
            },
        )
        result = _extract_result(response)
        if _verdict(result) == "BLOCKED":
            return "[RETRIEVED CONTEXT BLOCKED BY AgenticDome]"
        sanitized = result.get("text") or result.get("sanitized_text") or result.get("output")
        return _safe_str(sanitized) if sanitized is not None else text

    def secure_tool(
        self,
        *,
        tool_name: Optional[str] = None,
        tool_platform: Optional[str] = None,
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
        tool_schema: Optional[Any] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            name = tool_name or _callable_name(fn, "agno_tool")

            def wrapper(*args: Any, **kwargs: Any) -> Any:
                agent = kwargs.pop("agent", None) or kwargs.pop("ctx", None) or (args[0] if args else {})
                control_keys = {
                    "session_id",
                    "conversation_id",
                    "run_id",
                    "task_id",
                    "trace_id",
                    "request_id",
                    "policy_context",
                    "tool_platform",
                    "source_agent_id",
                    "decision_token",
                    "AgenticDome_decision_token",
                    "_AgenticDome_decision_token",
                    "_decision_token",
                    "AgenticDome_source_agent_id",
                    "_AgenticDome_source_agent_id",
                    "_source_agent_id",
                }
                call_kwargs = dict(kwargs)
                call_kwargs.setdefault("agent", agent)
                if tool_platform:
                    call_kwargs["tool_platform"] = tool_platform
                tool_args = {key: value for key, value in kwargs.items() if key not in control_keys}
                decision = self.authorize_tool_call(agent=agent, kwargs=call_kwargs, tool_name=name, tool_args=tool_args, tool_schema=tool_schema)
                sanitized_args = self._sanitized_args(decision)
                effective_args = sanitized_args if sanitized_args is not None else tool_args
                user_kwargs = {key: value for key, value in kwargs.items() if key not in control_keys}
                if sanitized_args is not None:
                    user_kwargs.update(sanitized_args)
                result = fn(*args, **user_kwargs)
                if not sanitize_output:
                    return result
                output_text = _serialize_for_review(result)
                sanitized = self.sanitize_retrieved_text(
                    text=output_text,
                    agent_id=self._agent_id(agent),
                    session_id=self._session_id(agent, call_kwargs),
                    policy_context={"request_purpose": "agno_tool_output_review", "tool_name": name},
                )
                if preserve_structured_output and isinstance(result, (dict, list, tuple)):
                    if sanitized == output_text:
                        return result
                    try:
                        return json.loads(sanitized)
                    except Exception:
                        pass
                return sanitized

            wrapper.__name__ = getattr(fn, "__name__", "secured_agno_tool")
            wrapper.__doc__ = getattr(fn, "__doc__", None)
            return wrapper

        return decorator


    async def sanitize_streaming_response(
        self,
        chunks: AsyncIterator[Any],
        *,
        agent_id: str,
        session_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        tail = ""
        async for chunk in chunks:
            text = _safe_str(chunk)
            review_text = (tail + text)[-max(1, self.config.streaming_buffer_chars):]
            sanitized = self.sanitize_retrieved_text(
                text=review_text,
                agent_id=agent_id,
                session_id=session_id,
                policy_context={**(policy_context or {}), "request_purpose": "agno_streaming_output_review"},
            )
            if sanitized in {"[RETRIEVED CONTEXT BLOCKED BY AgenticDome]", "[OUTPUT BLOCKED BY AgenticDome]"}:
                yield "[OUTPUT BLOCKED BY AgenticDome]"
                return
            if len(sanitized) >= len(text) and sanitized.endswith(text):
                yield text
            else:
                yield self.sanitize_retrieved_text(
                    text=text,
                    agent_id=agent_id,
                    session_id=session_id,
                    policy_context={**(policy_context or {}), "request_purpose": "agno_streaming_output_review"},
                )
            tail = review_text

    def create_hook_bundle(self, *, include_tool_hook: bool = True) -> Dict[str, List[Callable[..., Any]]]:
        bundle = {"pre_hooks": [self.pre_hook], "post_hooks": [self.post_hook]}
        if include_tool_hook:
            bundle["tool_hooks"] = [self.tool_hook]
        return bundle

    def create_middleware(self) -> Any:
        firewall = self

        class AgenticDomeAgnoMiddleware:
            name = "agenticdome_agno_firewall"
            pre_hook = firewall.pre_hook
            post_hook = firewall.post_hook
            tool_hook = firewall.tool_hook

            def hooks(self) -> Dict[str, List[Callable[..., Any]]]:
                return firewall.create_hook_bundle()

            def attach(self, agent_or_team: Any) -> Any:
                return firewall.attach_firewall(agent_or_team)

        return AgenticDomeAgnoMiddleware()

    def create_plugin(self) -> Any:
        return self.create_middleware()

    def attach_firewall(self, agent_or_team: Any, *, include_tool_hook: bool = True) -> Any:
        _safe_setattr_or_dict(
            agent_or_team,
            "pre_hooks",
            _append_unique_hook(_safe_getattr(agent_or_team, "pre_hooks"), self.pre_hook),
        )
        _safe_setattr_or_dict(
            agent_or_team,
            "post_hooks",
            _append_unique_hook(_safe_getattr(agent_or_team, "post_hooks"), self.post_hook),
        )
        if include_tool_hook:
            _safe_setattr_or_dict(
                agent_or_team,
                "tool_hooks",
                _append_unique_hook(_safe_getattr(agent_or_team, "tool_hooks"), self.tool_hook),
            )
        return agent_or_team

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


_DEFAULT_FIREWALL: Optional[AgenticDomeAgnoFirewall] = None


def get_default_firewall() -> AgenticDomeAgnoFirewall:
    global _DEFAULT_FIREWALL
    if _DEFAULT_FIREWALL is None:
        _DEFAULT_FIREWALL = AgenticDomeAgnoFirewall()
    return _DEFAULT_FIREWALL


def cybersec_pre_hook(agent: Any = None, *args: Any, **kwargs: Any) -> bool:
    return get_default_firewall().pre_hook(agent, *args, **kwargs)


def cybersec_post_hook(run_output: Any = None, agent: Any = None, *args: Any, **kwargs: Any) -> Any:
    return get_default_firewall().post_hook(run_output, agent, *args, **kwargs)


def cybersec_tool_hook(*args: Any, **kwargs: Any) -> Any:
    return get_default_firewall().tool_hook(*args, **kwargs)


def sanitize_retrieved_text(
    *,
    text: str,
    agent_id: str,
    session_id: str,
    policy_context: Optional[Dict[str, Any]] = None,
) -> str:
    return get_default_firewall().sanitize_retrieved_text(
        text=text,
        agent_id=agent_id,
        session_id=session_id,
        policy_context=policy_context,
    )


def attach_firewall(agent_or_team: Any, *, include_tool_hook: bool = True) -> Any:
    return get_default_firewall().attach_firewall(agent_or_team, include_tool_hook=include_tool_hook)


__all__ = [
    "FirewallConfig",
    "load_config",
    "AgenticDomeAgnoError",
    "AgenticDomeAgnoDenied",
    "AgenticDomeAgnoConfigurationError",
    "AgenticDomeError",
    "AgenticDomeDenied",
    "AgenticDomeConfigurationError",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "AgenticDomeAgnoFirewall",
    "get_default_firewall",
    "cybersec_pre_hook",
    "cybersec_post_hook",
    "cybersec_tool_hook",
    "sanitize_retrieved_text",
    "attach_firewall",
]
