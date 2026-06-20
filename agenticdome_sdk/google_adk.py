
from __future__ import annotations

import asyncio
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
from inspect import isawaitable
from threading import Lock
from typing import Any, AsyncIterator, Awaitable, Callable, Deque, Dict, Iterable, Optional, Tuple

from agenticdome_sdk.client import AgentGuardClient

try:
    from agenticdome_sdk.exceptions import AgentGuardHTTPError
except Exception:  # pragma: no cover
    try:
        from agenticdome_sdk.client import AgentGuardHTTPError  # type: ignore
    except Exception:  # pragma: no cover
        class AgentGuardHTTPError(Exception):  # type: ignore
            pass


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

logger = logging.getLogger("agenticdome.google_adk")
logger.setLevel(logging.INFO)


@dataclass(frozen=True)
class FirewallConfig:
    api_base: str
    api_key: str
    tenant_id: str
    platform: str = "google_adk"
    default_tool_platform: str = "google_adk"
    default_agent_id: str = "google_adk_agent"
    timeout_s: int = 20
    fail_closed: bool = True
    require_explicit_session_id: bool = False
    production_mode: bool = False
    require_stable_session_id_in_prod: bool = True
    sanitize_model_output: bool = True
    sanitize_tool_output: bool = True
    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False
    report_incidents: bool = True
    blocked_incident_severity: str = "medium"

    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:google_adk:handoff"
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


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE", "").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        platform=_env("AGENTICDOME_PLATFORM", "google_adk"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "google_adk"),
        default_agent_id=_env("AGENTICDOME_GOOGLE_ADK_AGENT_ID", "google_adk_agent"),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        production_mode=_env_bool("AGENTICDOME_PRODUCTION_MODE", False),
        require_stable_session_id_in_prod=_env_bool("AGENTICDOME_REQUIRE_STABLE_SESSION_ID_IN_PROD", True),
        sanitize_model_output=_env_bool("AGENTICDOME_SANITIZE_MODEL_OUTPUT", True),
        sanitize_tool_output=_env_bool("AGENTICDOME_SANITIZE_TOOL_OUTPUT", True),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
        handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
        redis_url=_env("AGENTICDOME_REDIS_URL", "").strip(),
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:google_adk:handoff"),
        token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET", ""),
        max_input_chars=_env_int("AGENTICDOME_GOOGLE_ADK_MAX_INPUT_CHARS", 50_000),
        max_output_chars=_env_int("AGENTICDOME_GOOGLE_ADK_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_GOOGLE_ADK_MAX_TOOL_ARG_CHARS", 20_000),
        streaming_buffer_chars=_env_int("AGENTICDOME_GOOGLE_ADK_STREAMING_BUFFER_CHARS", 4_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_GOOGLE_ADK_RATE_LIMIT_PER_MINUTE", 0),
        retry_attempts=_env_int("AGENTICDOME_GOOGLE_ADK_RETRY_ATTEMPTS", 2),
        retry_backoff_s=float(_env("AGENTICDOME_GOOGLE_ADK_RETRY_BACKOFF_S", "0.25") or "0.25"),
        circuit_breaker_failures=_env_int("AGENTICDOME_GOOGLE_ADK_CIRCUIT_BREAKER_FAILURES", 5),
        circuit_breaker_reset_s=_env_int("AGENTICDOME_GOOGLE_ADK_CIRCUIT_BREAKER_RESET_S", 60),
        audit_logging=_env_bool("AGENTICDOME_GOOGLE_ADK_AUDIT_LOGGING", True),
        otel_enabled=_env_bool("AGENTICDOME_GOOGLE_ADK_OTEL_ENABLED", True),
        emergency_block_tools=_env("AGENTICDOME_GOOGLE_ADK_EMERGENCY_BLOCK_TOOLS", ""),
        emergency_block_agents=_env("AGENTICDOME_GOOGLE_ADK_EMERGENCY_BLOCK_AGENTS", ""),
    )


class GoogleADKFirewallError(RuntimeError):
    """Base Google ADK firewall exception."""


class GoogleADKConfigurationError(GoogleADKFirewallError):
    """Raised when required AgenticDome configuration is missing."""


class GoogleADKDenied(GoogleADKFirewallError):
    """Raised when AgenticDome blocks or fail-closes an ADK operation."""




@dataclass(frozen=True)
class DecisionTokenRecord:
    decision_token: str
    source_agent_id: str
    created_at: float
    token_hmac: str = ""


class DecisionTokenStore:
    def put(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any], record: DecisionTokenRecord, ttl_s: int) -> None:
        raise NotImplementedError

    def get(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        raise NotImplementedError

    def delete(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> None:
        raise NotImplementedError

    def consume(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        record = self.get(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        if record is not None:
            self.delete(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        return record


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _tool_fingerprint(tool_name: str, tool_args: Dict[str, Any]) -> str:
    return hashlib.sha256(_stable_json({"tool_name": tool_name or "", "tool_args": tool_args or {}}).encode("utf-8")).hexdigest()


class InMemoryDecisionTokenStore(DecisionTokenStore):
    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id or "google_adk"
        self._lock = Lock()
        self._data: Dict[str, Tuple[float, DecisionTokenRecord]] = {}

    def _key(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
        return f"{self._tenant_id}:{session_id}:{target_agent_id}:{_tool_fingerprint(tool_name, tool_args)}"

    def _cleanup(self) -> None:
        now = time.time()
        for key in [key for key, (expires, _) in self._data.items() if expires <= now]:
            self._data.pop(key, None)

    def put(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any], record: DecisionTokenRecord, ttl_s: int) -> None:
        with self._lock:
            self._cleanup()
            self._data[self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)] = (time.time() + ttl_s, record)

    def get(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        with self._lock:
            self._cleanup()
            item = self._data.get(self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args))
            return item[1] if item else None

    def delete(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> None:
        with self._lock:
            self._data.pop(self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args), None)


class RedisDecisionTokenStore(DecisionTokenStore):
    def __init__(self, redis_url: str, key_prefix: str, tenant_id: str) -> None:
        import redis

        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = f"{key_prefix.rstrip(':')}:{tenant_id or 'google_adk'}"

    def _key(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
        return f"{self._prefix}:{session_id}:{target_agent_id}:{_tool_fingerprint(tool_name, tool_args)}"

    def put(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any], record: DecisionTokenRecord, ttl_s: int) -> None:
        self._client.setex(self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args), ttl_s, _stable_json({
            "decision_token": record.decision_token,
            "source_agent_id": record.source_agent_id,
            "created_at": record.created_at,
            "token_hmac": record.token_hmac,
        }))

    def _record_from_raw(self, raw: Any) -> Optional[DecisionTokenRecord]:
        if not raw:
            return None
        try:
            payload = json.loads(raw)
            return DecisionTokenRecord(str(payload["decision_token"]), str(payload["source_agent_id"]), float(payload.get("created_at", time.time())), str(payload.get("token_hmac", "")))
        except Exception:
            return None

    def get(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        return self._record_from_raw(self._client.get(self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)))

    def delete(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> None:
        self._client.delete(self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args))

    def consume(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        try:
            raw = self._client.execute_command("GETDEL", key)
        except Exception:
            pipe = self._client.pipeline()
            pipe.get(key)
            pipe.delete(key)
            values = pipe.execute()
            raw = values[0] if values else None
        return self._record_from_raw(raw)


def _build_token_store(config: FirewallConfig) -> DecisionTokenStore:
    if config.redis_url:
        try:
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id)
        except Exception as exc:
            logger.warning("Redis token store unavailable; using in-memory Google ADK token store. reason=%s", exc)
    return InMemoryDecisionTokenStore(config.tenant_id)


class AgenticDomeGoogleADKFirewall:
    """AgenticDome firewall for Google ADK model/tool callback boundaries."""

    def __init__(self, *, config: Optional[FirewallConfig] = None, client: Optional[AgentGuardClient] = None) -> None:
        self.config = config or load_config()
        if not (self.config.api_base and self.config.api_key and self.config.tenant_id):
            raise GoogleADKConfigurationError(
                "AgenticDome Google ADK firewall misconfigured. Set AGENTICDOME_API_BASE, "
                "AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
            )
        self.client = client or AgentGuardClient(
            api_base=self.config.api_base,
            api_key=self.config.api_key,
            tenant_id=self.config.tenant_id,
            timeout=self.config.timeout_s,
        )
        self.token_store = _build_token_store(self.config)
        self._rate_lock = Lock()
        self._rate_events: Dict[str, Deque[float]] = defaultdict(deque)
        self._circuit_lock = Lock()
        self._circuit_failures = 0
        self._circuit_open_until = 0.0

    def close(self) -> None:
        close = getattr(self.client, "close", None)
        if callable(close):
            close()

    async def _to_thread(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(fn, *args, **kwargs)

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

    async def _client_call(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if not self._circuit_allows_call():
            raise GoogleADKDenied("AgenticDome Google ADK circuit breaker is open.")
        last_error: Optional[Exception] = None
        for attempt in range(max(1, self.config.retry_attempts)):
            try:
                result = await self._to_thread(fn, *args, **kwargs)
                if inspect.isawaitable(result):
                    result = await result
                self._record_client_success()
                return result
            except Exception as exc:
                last_error = exc
                self._record_client_failure()
                if attempt + 1 >= max(1, self.config.retry_attempts):
                    break
                await asyncio.sleep(max(0.0, self.config.retry_backoff_s) * (2 ** attempt))
        assert last_error is not None
        raise last_error

    @staticmethod
    def _safe_str(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        try:
            return str(value)
        except Exception:
            return repr(value)

    @staticmethod
    def _serialize_for_review(value: Any) -> str:
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return AgenticDomeGoogleADKFirewall._safe_str(value)

    @staticmethod
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
        return {"_raw": AgenticDomeGoogleADKFirewall._safe_str(raw)}

    def _ctx_attr(self, ctx: Any, *names: str, default: Any = None) -> Any:
        for name in names:
            try:
                if isinstance(ctx, dict) and ctx.get(name) is not None:
                    return ctx.get(name)
                value = getattr(ctx, name)
                if value is not None:
                    return value
            except Exception:
                pass
        state = self._ctx_attr(ctx, "state", default=None) if ctx is not None and "state" not in names else None
        if isinstance(state, dict):
            for name in names:
                if state.get(name) is not None:
                    return state.get(name)
        return default

    def _agent_id(self, ctx: Any = None) -> str:
        value = self._ctx_attr(ctx, "agent_id", "agent_name", "agentName", "name")
        return self._safe_str(value) or self.config.default_agent_id

    def _session_id(self, ctx: Any = None) -> str:
        for key in ("session_id", "sessionId", "run_id", "trace_id", "conversation_id", "request_id", "invocation_id"):
            value = self._ctx_attr(ctx, key)
            if value:
                return self._safe_str(value)
        if self.config.require_explicit_session_id or (self.config.production_mode and self.config.require_stable_session_id_in_prod):
            raise GoogleADKDenied("Missing stable session_id/run_id/trace_id in Google ADK context.")
        return f"google-adk-{uuid.uuid4().hex}"

    def _identity_context(self, source: Any) -> Dict[str, Any]:
        state = self._ctx_attr(source, "state", default={})
        identity = self._ctx_attr(source, "identity", "user", "principal", default=None)
        out: Dict[str, Any] = {}
        for key in (
            "user_id", "principal_id", "caller_id", "tenant_id", "project_id", "project",
            "google_cloud_project", "gcp_project", "service_account", "service_account_email",
            "email", "subject", "sub", "audience", "aud", "scopes", "roles",
            "location", "region", "vertex_ai_project", "data_classification", "sensitivity_label",
        ):
            value = self._ctx_attr(source, key, default=None)
            if value is None and isinstance(state, dict):
                value = state.get(key)
            if value is None and identity is not None:
                value = self._ctx_attr(identity, key, default=None)
            if value is not None:
                out[key] = value
        return out

    def _policy_context(self, *, agent_id: str, session_id: str, request_purpose: str, source: Any = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ctx = {
            "request_id": str(uuid.uuid4()),
            "request_ts_ms": int(time.time() * 1000),
            "request_purpose": request_purpose,
            "session_id": session_id,
            "source_agent_id": agent_id,
            "platform": self.config.platform,
        }
        ctx.update(self._identity_context(source))
        if extra:
            ctx.update(extra)
        return ctx

    @staticmethod
    def _strip_internal_args(args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            key: value
            for key, value in (args or {}).items()
            if not str(key).startswith("_AgenticDome_")
            and not str(key).startswith("_decision_")
            and str(key) not in {"decision_token", "source_agent_id"}
        }

    def _sanitized_args(self, response: Any) -> Optional[Dict[str, Any]]:
        view = self._decision_view(response)
        for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
            value = view.get(key) if isinstance(view, dict) else None
            if isinstance(value, dict):
                return self._strip_internal_args(value)
        return None

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
                raise GoogleADKDenied(f"Google ADK rate limit exceeded for {purpose}.")
            events.append(now)

    def _enforce_tool_arg_size(self, *, tool_name: str, tool_args: Dict[str, Any]) -> None:
        if self.config.max_tool_arg_chars <= 0:
            return
        if len(self._serialize_for_review(tool_args or {})) > self.config.max_tool_arg_chars:
            raise GoogleADKDenied(f"Google ADK tool arguments exceed max size for {tool_name}.")

    def _emergency_policy_check(self, *, agent_id: str, tool_name: Optional[str] = None) -> None:
        agents = {item.strip() for item in (self.config.emergency_block_agents or "").split(",") if item.strip()}
        tools = {item.strip() for item in (self.config.emergency_block_tools or "").split(",") if item.strip()}
        if agent_id in agents:
            raise GoogleADKDenied(f"Emergency local policy blocked Google ADK agent: {agent_id}")
        if tool_name and tool_name in tools:
            raise GoogleADKDenied(f"Emergency local policy blocked Google ADK tool: {tool_name}")

    def _token_hmac(self, token: str) -> str:
        if not self.config.token_hmac_secret or not token:
            return ""
        digest = hmac.new(self.config.token_hmac_secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _verify_record_hmac(self, record: DecisionTokenRecord) -> bool:
        if not self.config.token_hmac_secret:
            return True
        return bool(record.token_hmac) and hmac.compare_digest(record.token_hmac, self._token_hmac(record.decision_token))

    def _audit(self, event: str, *, agent_id: str, session_id: str, details: Optional[Dict[str, Any]] = None) -> None:
        if not self.config.audit_logging:
            return
        payload = {"event": event, "agent_id": agent_id, "session_id": session_id, "platform": self.config.platform}
        if details:
            payload.update(details)
        logger.info("AgenticDome Google ADK audit: %s", json.dumps(payload, sort_keys=True, default=str))

    def _otel_event(self, name: str, attributes: Dict[str, Any]) -> None:
        if not self.config.otel_enabled:
            return
        try:
            from opentelemetry import trace
            span = trace.get_current_span()
            if span and span.is_recording():
                span.add_event(name, attributes={k: self._safe_str(v) for k, v in attributes.items()})
        except Exception:
            pass

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
                raise GoogleADKDenied(f"Google ADK tool {tool_name} missing required args: {', '.join(missing)}")
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
                    raise GoogleADKDenied(f"Google ADK tool {tool_name} arg {key} failed schema validation.")

    def _decision_view(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        for candidate in (payload, payload.get("result"), payload.get("decision"), payload.get("analysis")):
            if isinstance(candidate, dict) and any(k in candidate for k in ("verdict", "decision", "blocked", "allowed", "reason")):
                return candidate
        return payload

    def _is_blocked(self, payload: Any) -> bool:
        view = self._decision_view(payload)
        if "blocked" in view:
            return bool(view["blocked"])
        if "allowed" in view:
            return not bool(view["allowed"])
        verdict = self._safe_str(view.get("verdict") or view.get("decision")).upper()
        return verdict in {"BLOCKED", "DENY", "DENIED", "REJECTED"}

    def _reason(self, payload: Any) -> str:
        view = self._decision_view(payload)
        return self._safe_str(view.get("reason") or view.get("message") or view.get("explanation") or payload)

    def _sanitized_text(self, response: Any) -> Optional[str]:
        view = self._decision_view(response)
        value = None
        if isinstance(view, dict):
            value = view.get("text") or view.get("sanitized_text") or view.get("output") or view.get("content")
        if value is None and isinstance(response, dict):
            value = response.get("text") or response.get("sanitized_text")
        return self._safe_str(value) if value is not None else None

    async def _report_incident_best_effort(self, *, agent_id: str, incident_type: str, details: str, severity: Optional[str] = None) -> None:
        if not self.config.report_incidents:
            return
        try:
            await self._client_call(
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

    async def _handle_error(self, exc: Exception, context: str) -> None:
        if isinstance(exc, GoogleADKDenied):
            raise exc
        if self.config.fail_closed:
            raise GoogleADKDenied(f"AgenticDome fail-closed: {context}: {exc}") from exc
        logger.warning("AgenticDome fail-open: %s: %s", context, exc)

    def extract_text(self, value: Any) -> str:
        parts = []
        def walk(item: Any) -> None:
            if item is None:
                return
            if isinstance(item, str):
                parts.append(item)
                return
            if isinstance(item, dict):
                for key in ("text", "content", "parts", "messages", "prompt", "instruction", "function_call", "function_response"):
                    if key in item:
                        walk(item[key])
                return
            if isinstance(item, (list, tuple)):
                for child in item:
                    walk(child)
                return
            for attr in ("text", "content", "parts", "messages", "instruction"):
                try:
                    attr_value = getattr(item, attr)
                    if attr_value is not None:
                        walk(attr_value)
                except Exception:
                    pass
        walk(value)
        return "\n".join(p for p in parts if p).strip() or self._serialize_for_review(value)

    async def screen_model_request(self, *, callback_context: Any, llm_request: Any) -> Dict[str, Any]:
        agent_id = self._agent_id(callback_context)
        session_id = self._session_id(callback_context)
        text = self.extract_text(llm_request)
        try:
            self._emergency_policy_check(agent_id=agent_id)
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="model")
            response = await self._client_call(
                self.client.guardrail_validate,
                text=self._bounded_text(text, limit=self.config.max_input_chars, label="GOOGLE ADK INPUT"),
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="input",
                session_id=session_id,
                policy_context=self._policy_context(agent_id=agent_id, session_id=session_id, request_purpose="google_adk.before_model", source=callback_context),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_prompt_input", details=reason)
                raise GoogleADKDenied(f"AgenticDome blocked Google ADK model request: {reason}")
            self._audit("google_adk_model_allowed", agent_id=agent_id, session_id=session_id)
            self._otel_event("agenticdome.google_adk.model_allowed", {"agent_id": agent_id, "session_id": session_id})
            return response
        except Exception as exc:
            await self._handle_error(exc, "screen_model_request")
            return {}

    async def authorize_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_context: Any,
        text: Optional[str] = None,
        tool_platform: Optional[str] = None,
        tool_schema: Optional[Any] = None,
    ) -> Dict[str, Any]:
        agent_id = self._agent_id(tool_context)
        session_id = self._session_id(tool_context)
        clean_args = self._strip_internal_args(tool_args)
        effective_tool_platform = tool_platform or clean_args.get("tool_platform") or clean_args.get("platform") or self.config.default_tool_platform
        try:
            self._emergency_policy_check(agent_id=agent_id, tool_name=tool_name)
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose=f"tool:{tool_name}")
            self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_args)
            self._validate_tool_schema(tool_name=tool_name, tool_args=clean_args, schema=tool_schema)
            response = await self._client_call(
                self.client.guardrail_validate,
                text=self._bounded_text(text or f"[Google ADK] {agent_id} intends to execute {tool_name}", limit=self.config.max_input_chars, label="GOOGLE ADK TOOL"),
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="outbound",
                session_id=session_id,
                tool_platform=self._safe_str(effective_tool_platform),
                tool_name=tool_name,
                tool_args=clean_args,
                policy_context=self._policy_context(
                    agent_id=agent_id,
                    session_id=session_id,
                    request_purpose="google_adk.before_tool",
                    source=tool_context,
                    extra={"tool_name": tool_name, "tool_platform": effective_tool_platform},
                ),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_tool_execution", details=reason)
                raise GoogleADKDenied(f"AgenticDome blocked Google ADK tool execution: {reason}")
            sanitized = self._sanitized_args(response)
            if sanitized is not None:
                self._validate_tool_schema(tool_name=tool_name, tool_args=sanitized, schema=tool_schema)
                response = dict(response or {})
                response["sanitized_tool_args"] = sanitized
            self._audit("google_adk_tool_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": tool_name})
            self._otel_event("agenticdome.google_adk.tool_allowed", {"agent_id": agent_id, "session_id": session_id, "tool_name": tool_name})
            return response
        except Exception as exc:
            await self._handle_error(exc, "authorize_tool_call")
            return {}

    async def sanitize_text(self, *, text: str, agent_id: str, session_id: str, request_purpose: str = "google_adk.output_review") -> str:
        try:
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="output")
            response = await self._client_call(
                self.client.mesh_validate,
                text=self._bounded_text(text, limit=self.config.max_output_chars, label="GOOGLE ADK OUTPUT"),
                agent_id=agent_id,
                direction="output",
                session_id=session_id,
                platform=self.config.platform,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._policy_context(agent_id=agent_id, session_id=session_id, request_purpose=request_purpose),
            )
            if self._is_blocked(response):
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_output", details=self._reason(response))
                return "[OUTPUT BLOCKED BY AgenticDome]"
            sanitized = self._sanitized_text(response)
            return sanitized if sanitized is not None else text
        except Exception as exc:
            await self._handle_error(exc, "sanitize_text")
            return text

    def _decision_token(self, payload: Any) -> str:
        view = self._decision_view(payload)
        for source in (view, payload if isinstance(payload, dict) else {}):
            if not isinstance(source, dict):
                continue
            for key in ("decision_token", "delegation_token", "handoff_token", "token"):
                value = source.get(key)
                if value:
                    return self._safe_str(value)
        return ""

    def _tool_name(self, tool: Any) -> str:
        return self._safe_str(getattr(tool, "name", None) or getattr(tool, "__name__", None) or tool or "unknown_tool")

    def _is_handoff_tool(self, *, tool_name: str, tool_args: Dict[str, Any]) -> bool:
        lowered = tool_name.lower()
        if any(marker in lowered for marker in ("handoff", "delegate", "delegation", "transfer", "route_agent")):
            return True
        return any(key in tool_args for key in ("target_agent_id", "target_agent", "delegate_to", "specialist_agent_id", "target_tool_name"))

    def _target_agent_id(self, tool_args: Dict[str, Any]) -> str:
        for key in ("target_agent_id", "target_agent", "delegate_to", "specialist_agent_id", "agent_id"):
            if tool_args.get(key):
                return self._safe_str(tool_args[key])
        return self.config.default_agent_id

    def _target_tool_name(self, *, fallback: str, tool_args: Dict[str, Any]) -> str:
        for key in ("target_tool_name", "tool_name", "delegated_tool", "specialist_tool_name"):
            if tool_args.get(key):
                return self._safe_str(tool_args[key])
        return fallback

    def _target_tool_args(self, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        for key in ("target_tool_args", "delegated_tool_args", "specialist_tool_args", "args"):
            value = tool_args.get(key)
            if isinstance(value, dict):
                return self._strip_internal_args(value)
        return self._strip_internal_args(tool_args)

    def _token_from_args(self, tool_args: Dict[str, Any]) -> str:
        for key in ("_AgenticDome_decision_token", "decision_token", "delegation_token", "handoff_token"):
            value = tool_args.get(key)
            if value:
                return self._safe_str(value)
        return ""

    def _mutate_args(self, original: Any, replacement: Dict[str, Any]) -> Dict[str, Any]:
        clean = self._strip_internal_args(replacement)
        if isinstance(original, dict):
            original.clear()
            original.update(clean)
            return original
        return clean

    async def authorize_manager_handoff(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        target_tool_name: str,
        target_tool_args: Dict[str, Any],
        tool_context: Any,
        session_id: Optional[str] = None,
        handoff_reason: Optional[str] = None,
    ) -> DecisionTokenRecord:
        session_id = session_id or self._session_id(tool_context)
        clean_args = self._strip_internal_args(target_tool_args)
        try:
            self._emergency_policy_check(agent_id=source_agent_id, tool_name=target_tool_name)
            self._emergency_policy_check(agent_id=target_agent_id, tool_name=target_tool_name)
            self._check_rate_limit(agent_id=source_agent_id, session_id=session_id, purpose=f"handoff:{target_agent_id}")
            self._enforce_tool_arg_size(tool_name=target_tool_name, tool_args=clean_args)
            response = await self._client_call(
                self.client.guardrail_validate,
                text=self._bounded_text(
                    handoff_reason or f"[Google ADK] {source_agent_id} delegates {target_tool_name} to {target_agent_id}",
                    limit=self.config.max_input_chars,
                    label="GOOGLE ADK HANDOFF",
                ),
                agent_id=source_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="handoff",
                session_id=session_id,
                tool_platform=self.config.default_tool_platform,
                tool_name=target_tool_name,
                tool_args=clean_args,
                policy_context=self._policy_context(
                    agent_id=source_agent_id,
                    session_id=session_id,
                    request_purpose="google_adk.manager_handoff",
                    source=tool_context,
                    extra={"target_agent_id": target_agent_id, "target_tool_name": target_tool_name},
                ),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=source_agent_id, incident_type="blocked_agent_handoff", details=reason)
                raise GoogleADKDenied(f"AgenticDome blocked Google ADK handoff: {reason}")
            token = self._decision_token(response) or f"gadk-{uuid.uuid4().hex}"
            record = DecisionTokenRecord(
                decision_token=token,
                source_agent_id=source_agent_id,
                created_at=time.time(),
                token_hmac=self._token_hmac(token),
            )
            self.token_store.put(
                session_id=session_id,
                target_agent_id=target_agent_id,
                tool_name=target_tool_name,
                tool_args=clean_args,
                record=record,
                ttl_s=self.config.handoff_token_ttl_s,
            )
            self._audit("google_adk_handoff_allowed", agent_id=source_agent_id, session_id=session_id, details={"target_agent_id": target_agent_id, "target_tool_name": target_tool_name})
            self._otel_event("agenticdome.google_adk.handoff_allowed", {"source_agent_id": source_agent_id, "target_agent_id": target_agent_id, "session_id": session_id})
            return record
        except Exception as exc:
            await self._handle_error(exc, "authorize_manager_handoff")
            return DecisionTokenRecord("", source_agent_id, time.time())

    async def verify_delegated_execution(
        self,
        *,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_context: Any,
        source_agent_id: Optional[str] = None,
        decision_token: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        session_id = session_id or self._session_id(tool_context)
        clean_args = self._strip_internal_args(tool_args)
        record = None
        token = self._safe_str(decision_token or self._token_from_args(tool_args))
        if not token:
            record = self.token_store.consume(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=clean_args)
            if record:
                token = record.decision_token
                source_agent_id = source_agent_id or record.source_agent_id
        if not token:
            raise GoogleADKDenied("Missing Google ADK delegated execution decision token.")
        if record and not self._verify_record_hmac(record):
            raise GoogleADKDenied("Invalid Google ADK delegated execution decision token HMAC.")
        try:
            response = await self._client_call(
                self.client.guardrail_validate,
                text=f"[Google ADK] Verify delegated execution of {tool_name} by {target_agent_id}",
                agent_id=target_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="delegated_execution",
                session_id=session_id,
                tool_platform=self.config.default_tool_platform,
                tool_name=tool_name,
                tool_args=clean_args,
                decision_token=token,
                source_agent_id=source_agent_id or (record.source_agent_id if record else ""),
                policy_context=self._policy_context(
                    agent_id=target_agent_id,
                    session_id=session_id,
                    request_purpose="google_adk.delegated_execution",
                    source=tool_context,
                    extra={"source_agent_id": source_agent_id or (record.source_agent_id if record else "")},
                ),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=target_agent_id, incident_type="blocked_delegated_execution", details=reason)
                raise GoogleADKDenied(f"AgenticDome blocked Google ADK delegated execution: {reason}")
            self._audit("google_adk_delegated_execution_allowed", agent_id=target_agent_id, session_id=session_id, details={"tool_name": tool_name})
            self._otel_event("agenticdome.google_adk.delegated_execution_allowed", {"agent_id": target_agent_id, "session_id": session_id, "tool_name": tool_name})
            return response
        except Exception as exc:
            await self._handle_error(exc, "verify_delegated_execution")
            return {}

    async def before_agent(self, callback_context: Any) -> None:
        agent_id = self._agent_id(callback_context)
        session_id = self._session_id(callback_context)
        self._emergency_policy_check(agent_id=agent_id)
        self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="agent")
        self._audit("google_adk_agent_start", agent_id=agent_id, session_id=session_id)
        self._otel_event("agenticdome.google_adk.agent_start", {"agent_id": agent_id, "session_id": session_id})
        return None

    async def after_agent(self, callback_context: Any, result: Any = None) -> Any:
        agent_id = self._agent_id(callback_context)
        session_id = self._session_id(callback_context)
        self._audit("google_adk_agent_end", agent_id=agent_id, session_id=session_id)
        self._otel_event("agenticdome.google_adk.agent_end", {"agent_id": agent_id, "session_id": session_id})
        return result

    async def before_model(self, callback_context: Any, llm_request: Any) -> None:
        await self.screen_model_request(callback_context=callback_context, llm_request=llm_request)
        return None

    async def after_model(self, callback_context: Any, llm_response: Any) -> Any:
        if not self.config.sanitize_model_output:
            return llm_response
        agent_id = self._agent_id(callback_context)
        session_id = self._session_id(callback_context)
        text = self.extract_text(llm_response)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, request_purpose="google_adk.after_model")
        return self._apply_text(llm_response, sanitized)

    async def before_tool(self, tool: Any, args: Any = None, tool_context: Any = None) -> None:
        tool_name = self._tool_name(tool)
        tool_args = self._normalize_args(args)
        agent_id = self._agent_id(tool_context)
        if self._is_handoff_tool(tool_name=tool_name, tool_args=tool_args):
            clean_target_args = self._target_tool_args(tool_args)
            record = await self.authorize_manager_handoff(
                source_agent_id=agent_id,
                target_agent_id=self._target_agent_id(tool_args),
                target_tool_name=self._target_tool_name(fallback=tool_name, tool_args=tool_args),
                target_tool_args=clean_target_args,
                tool_context=tool_context,
                handoff_reason=self._safe_str(tool_args.get("reason") or tool_args.get("task") or ""),
            )
            if isinstance(args, dict) and record.decision_token:
                args["_AgenticDome_decision_token"] = record.decision_token
                args["_AgenticDome_source_agent_id"] = agent_id
                for nested_key in ("target_tool_args", "delegated_tool_args", "specialist_tool_args"):
                    if isinstance(args.get(nested_key), dict):
                        args[nested_key]["_AgenticDome_decision_token"] = record.decision_token
                        args[nested_key]["_AgenticDome_source_agent_id"] = agent_id
            return None
        stored_record = self.token_store.get(session_id=self._session_id(tool_context), target_agent_id=agent_id, tool_name=tool_name, tool_args=self._strip_internal_args(tool_args))
        if self._token_from_args(tool_args) or stored_record is not None:
            await self.verify_delegated_execution(
                target_agent_id=agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
                tool_context=tool_context,
                source_agent_id=self._safe_str(tool_args.get("_AgenticDome_source_agent_id") or tool_args.get("source_agent_id") or ""),
            )
            return None
        response = await self.authorize_tool_call(tool_name=tool_name, tool_args=tool_args, tool_context=tool_context, tool_schema=getattr(tool, "args_schema", None) or getattr(tool, "schema", None))
        sanitized = self._sanitized_args(response)
        if sanitized is not None:
            self._mutate_args(args, sanitized)
        return None

    async def after_tool(self, tool: Any, args: Any = None, tool_context: Any = None, tool_response: Any = None) -> Any:
        if not self.config.sanitize_tool_output:
            return tool_response
        agent_id = self._agent_id(tool_context)
        session_id = self._session_id(tool_context)
        text = self._serialize_for_review(tool_response)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, request_purpose="google_adk.after_tool")
        if isinstance(tool_response, (dict, list, tuple)):
            if sanitized == text:
                return tool_response
            try:
                parsed = json.loads(sanitized)
                if isinstance(parsed, (dict, list)):
                    return parsed
            except Exception:
                pass
        return sanitized

    async def sanitize_streaming_response(
        self,
        chunks: AsyncIterator[Any],
        *,
        agent_id: str,
        session_id: str,
        request_purpose: str = "google_adk.streaming_output",
    ) -> AsyncIterator[str]:
        tail = ""
        async for chunk in chunks:
            text = self._safe_str(chunk)
            review_text = (tail + text)[-max(1, self.config.streaming_buffer_chars):]
            sanitized = await self.sanitize_text(text=review_text, agent_id=agent_id, session_id=session_id, request_purpose=request_purpose)
            if sanitized == "[OUTPUT BLOCKED BY AgenticDome]":
                yield sanitized
                return
            if len(sanitized) >= len(text) and sanitized.endswith(text):
                yield text
            else:
                yield await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, request_purpose=request_purpose)
            tail = review_text

    def _run_sync(self, coro: Awaitable[Any]) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        raise GoogleADKDenied("Synchronous Google ADK callback called inside a running event loop; register the async callback methods instead.")

    def before_agent_callback(self, callback_context: Any) -> None:
        return self._run_sync(self.before_agent(callback_context))

    def after_agent_callback(self, callback_context: Any, result: Any = None) -> Any:
        return self._run_sync(self.after_agent(callback_context, result))

    def before_model_callback(self, callback_context: Any, llm_request: Any) -> None:
        return self._run_sync(self.before_model(callback_context, llm_request))

    def after_model_callback(self, callback_context: Any, llm_response: Any) -> Any:
        return self._run_sync(self.after_model(callback_context, llm_response))

    def before_tool_callback(self, tool: Any, args: Any = None, tool_context: Any = None) -> None:
        return self._run_sync(self.before_tool(tool, args, tool_context))

    def after_tool_callback(self, tool: Any, args: Any = None, tool_context: Any = None, tool_response: Any = None) -> Any:
        return self._run_sync(self.after_tool(tool, args, tool_context, tool_response))

    def build_callback_kwargs(self, *, prefer_async: bool = True) -> Dict[str, Callable[..., Any]]:
        return {
            "before_agent_callback": self.before_agent if prefer_async else self.before_agent_callback,
            "after_agent_callback": self.after_agent if prefer_async else self.after_agent_callback,
            "before_model_callback": self.before_model if prefer_async else self.before_model_callback,
            "after_model_callback": self.after_model if prefer_async else self.after_model_callback,
            "before_tool_callback": self.before_tool if prefer_async else self.before_tool_callback,
            "after_tool_callback": self.after_tool if prefer_async else self.after_tool_callback,
        }

    def create_plugin(self, *, prefer_async: bool = True) -> Any:
        callbacks = self.build_callback_kwargs(prefer_async=prefer_async)

        class AgenticDomeGoogleADKPlugin:
            name = "agenticdome_google_adk_firewall"

            def __getattr__(self, item: str) -> Any:
                if item in callbacks:
                    return callbacks[item]
                raise AttributeError(item)

        plugin = AgenticDomeGoogleADKPlugin()
        for name, fn in callbacks.items():
            setattr(plugin, name, fn)
        return plugin

    def install_on_agent(self, agent: Any, *, prefer_async: bool = True, overwrite: bool = True) -> Any:
        for name, fn in self.build_callback_kwargs(prefer_async=prefer_async).items():
            if overwrite or not getattr(agent, name, None):
                setattr(agent, name, fn)
        return agent

    def _apply_text(self, value: Any, text: str) -> Any:
        def replace_in_dict(item: Dict[str, Any]) -> bool:
            for key in ("text", "output", "message"):
                if isinstance(item.get(key), str):
                    item[key] = text
                    return True
            content = item.get("content")
            if isinstance(content, str):
                item["content"] = text
                return True
            for key in ("parts", "contents", "messages", "candidates"):
                child = item.get(key)
                if replace_nested(child):
                    return True
            return False

        def replace_nested(item: Any) -> bool:
            if isinstance(item, dict):
                return replace_in_dict(item)
            if isinstance(item, list):
                for child in item:
                    if replace_nested(child):
                        return True
                return False
            for attr in ("text", "output", "message"):
                try:
                    if isinstance(getattr(item, attr), str):
                        setattr(item, attr, text)
                        return True
                except Exception:
                    pass
            for attr in ("content", "parts", "contents", "messages", "candidates"):
                try:
                    child = getattr(item, attr)
                    if isinstance(child, str):
                        setattr(item, attr, text)
                        return True
                    if replace_nested(child):
                        return True
                except Exception:
                    pass
            return False

        if isinstance(value, dict):
            out = dict(value)
            return out if replace_in_dict(out) else text
        return value if replace_nested(value) else text

    def wrap_tool_handler(
        self,
        *,
        tool_name: str,
        handler: Callable[..., Any],
        tool_platform: Optional[str] = None,
        tool_schema: Optional[Any] = None,
        sanitize_output: Optional[bool] = None,
    ) -> Callable[..., Awaitable[Any]]:
        async def secured(tool_context: Any, args: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args)
            agent_id = self._agent_id(tool_context)
            session_id = self._session_id(tool_context)
            stored_record = self.token_store.get(session_id=session_id, target_agent_id=agent_id, tool_name=tool_name, tool_args=self._strip_internal_args(tool_args))
            if self._token_from_args(tool_args) or stored_record is not None:
                await self.verify_delegated_execution(target_agent_id=agent_id, tool_name=tool_name, tool_args=tool_args, tool_context=tool_context, session_id=session_id)
            else:
                response = await self.authorize_tool_call(tool_name=tool_name, tool_args=tool_args, tool_context=tool_context, tool_platform=tool_platform, tool_schema=tool_schema)
                sanitized = self._sanitized_args(response)
                if sanitized is not None:
                    tool_args = self._mutate_args(args, sanitized)
            result = handler(tool_context, tool_args, *a, **kw)
            if isawaitable(result):
                result = await result
            if sanitize_output is False or (sanitize_output is None and not self.config.sanitize_tool_output):
                return result
            return await self.after_tool(tool_name, tool_args, tool_context, result)
        return secured

    def secure_tool(
        self,
        *,
        tool_name: str,
        tool_platform: Optional[str] = None,
        tool_schema: Optional[Any] = None,
        sanitize_output: Optional[bool] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_handler(tool_name=tool_name, handler=handler, tool_platform=tool_platform, tool_schema=tool_schema, sanitize_output=sanitize_output)
        return decorator


__all__ = [
    "AgenticDomeGoogleADKFirewall",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "FirewallConfig",
    "GoogleADKConfigurationError",
    "GoogleADKDenied",
    "GoogleADKFirewallError",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "load_config",
]
