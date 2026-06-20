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
from threading import Lock
from typing import Any, AsyncIterator, Awaitable, Callable, Deque, Dict, Iterable, List, Optional, Tuple

from agenticdome_sdk.client import AgentGuardClient

try:
    from agenticdome_sdk.exceptions import AgentGuardHTTPError
except Exception:  # pragma: no cover
    try:
        from agenticdome_sdk.client import AgentGuardHTTPError  # type: ignore
    except Exception:
        class AgentGuardHTTPError(Exception):  # type: ignore
            pass


logger = logging.getLogger("agenticdome.microsoft_ai_foundry")
logger.setLevel(logging.INFO)

AsyncHandler = Callable[..., Awaitable[Any]]
SyncHandler = Callable[..., Any]


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
    bearer_token: str

    api_key: str = ""
    tenant_id: str = ""

    platform: str = "microsoft_ai_foundry"
    default_tool_platform: str = "microsoft_ai_foundry"

    timeout_s: int = 20
    fail_closed: bool = True
    require_explicit_session_id: bool = False
    production_mode: bool = False
    require_stable_session_id_in_prod: bool = True
    require_output_sanitization_in_prod: bool = True

    api_version: str = "2025-09-01"

    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    report_incidents: bool = True
    blocked_incident_severity: str = "medium"

    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:microsoft_ai_foundry:handoff"
    token_hmac_secret: str = ""

    max_input_chars: int = 50_000
    max_output_chars: int = 100_000
    max_tool_arg_chars: int = 20_000
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
        bearer_token=_env("AGENTICDOME_BEARER_TOKEN", ""),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        platform=_env("AGENTICDOME_PLATFORM", "microsoft_ai_foundry"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "microsoft_ai_foundry"),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        production_mode=_env_bool("AGENTICDOME_PRODUCTION_MODE", False),
        require_stable_session_id_in_prod=_env_bool("AGENTICDOME_REQUIRE_STABLE_SESSION_ID_IN_PROD", True),
        require_output_sanitization_in_prod=_env_bool("AGENTICDOME_FOUNDRY_REQUIRE_OUTPUT_SANITIZATION_IN_PROD", True),
        api_version=_env("AGENTICDOME_COPILOT_API_VERSION", "2025-09-01"),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
        handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
        redis_url=_env("AGENTICDOME_REDIS_URL", "").strip(),
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:microsoft_ai_foundry:handoff"),
        token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET", ""),
        max_input_chars=_env_int("AGENTICDOME_FOUNDRY_MAX_INPUT_CHARS", 50_000),
        max_output_chars=_env_int("AGENTICDOME_FOUNDRY_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_FOUNDRY_MAX_TOOL_ARG_CHARS", 20_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_FOUNDRY_RATE_LIMIT_PER_MINUTE", 0),
        retry_attempts=_env_int("AGENTICDOME_FOUNDRY_RETRY_ATTEMPTS", 2),
        retry_backoff_s=float(_env("AGENTICDOME_FOUNDRY_RETRY_BACKOFF_S", "0.25") or "0.25"),
        circuit_breaker_failures=_env_int("AGENTICDOME_FOUNDRY_CIRCUIT_BREAKER_FAILURES", 5),
        circuit_breaker_reset_s=_env_int("AGENTICDOME_FOUNDRY_CIRCUIT_BREAKER_RESET_S", 60),
        audit_logging=_env_bool("AGENTICDOME_FOUNDRY_AUDIT_LOGGING", True),
        otel_enabled=_env_bool("AGENTICDOME_FOUNDRY_OTEL_ENABLED", True),
        emergency_block_tools=_env("AGENTICDOME_FOUNDRY_EMERGENCY_BLOCK_TOOLS", ""),
        emergency_block_agents=_env("AGENTICDOME_FOUNDRY_EMERGENCY_BLOCK_AGENTS", ""),
    )




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

    def _key(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
        return f"{self._tenant_id}:{session_id}:{target_agent_id}:{_tool_fingerprint(tool_name, tool_args)}"

    def _cleanup(self) -> None:
        now = time.time()
        for key in [key for key, (expires_at, _) in self._data.items() if expires_at <= now]:
            self._data.pop(key, None)

    def put(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any], record: DecisionTokenRecord, ttl_s: int) -> None:
        with self._lock:
            self._cleanup()
            self._data[self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)] = (time.time() + ttl_s, record)

    def get(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        with self._lock:
            self._cleanup()
            entry = self._data.get(self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args))
            return entry[1] if entry else None

    def delete(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> None:
        with self._lock:
            self._data.pop(self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args), None)


class RedisDecisionTokenStore(DecisionTokenStore):
    def __init__(self, redis_url: str, key_prefix: str, tenant_id: str) -> None:
        import redis

        self._tenant_id = tenant_id
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = key_prefix.rstrip(":")

    def _key(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
        return f"{self._prefix}:{self._tenant_id}:{session_id}:{target_agent_id}:{_tool_fingerprint(tool_name, tool_args)}"

    def put(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any], record: DecisionTokenRecord, ttl_s: int) -> None:
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        self._client.setex(key, ttl_s, _canonical_json({
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
            return DecisionTokenRecord(
                decision_token=str(payload["decision_token"]),
                source_agent_id=str(payload["source_agent_id"]),
                created_at=float(payload["created_at"]),
                token_hmac=str(payload.get("token_hmac", "")),
            )
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
            logger.info("AgenticDome Microsoft AI Foundry firewall using Redis token store.")
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id or "foundry")
        except Exception as exc:
            logger.warning("Redis token store unavailable; falling back to memory. reason=%s", exc)
    return InMemoryDecisionTokenStore(config.tenant_id or "foundry")


class MicrosoftAIFoundryFirewallError(RuntimeError):
    """Base Microsoft AI Foundry firewall exception."""


class MicrosoftAIFoundryDenied(MicrosoftAIFoundryFirewallError):
    """Raised when AgenticDome blocks or fail-closes execution."""


class MicrosoftAIFoundryConfigurationError(MicrosoftAIFoundryFirewallError):
    """Raised when required Foundry runtime configuration is missing."""


# -----------------------------------------------------------------------------
# Main firewall
# -----------------------------------------------------------------------------

class AgenticDomeMicrosoftAIFoundryFirewall:
    """Threat-contract-first firewall for Azure AI Foundry local boundaries."""

    def __init__(self, *, config: Optional[FirewallConfig] = None, client: Optional[AgentGuardClient] = None) -> None:
        self.config = config or load_config()
        if not (
            self.config.api_base
            and self.config.api_key
            and self.config.tenant_id
            and self.config.bearer_token
        ):
            raise MicrosoftAIFoundryConfigurationError(
                "AgenticDome Microsoft AI Foundry firewall misconfigured. "
                "Set AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, "
                "AGENTICDOME_TENANT_ID, and AGENTICDOME_BEARER_TOKEN."
            )

        self.client = client or AgentGuardClient(
            api_base=self.config.api_base,
            api_key=self.config.api_key,
            tenant_id=self.config.tenant_id or None,
            bearer_token=self.config.bearer_token,
            timeout=self.config.timeout_s,
        )
        self.token_store = _build_token_store(self.config)
        self._rate_lock = Lock()
        self._rate_events: Dict[str, Deque[float]] = defaultdict(deque)
        self._circuit_lock = Lock()
        self._circuit_failures = 0
        self._circuit_open_until = 0.0

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
            raise MicrosoftAIFoundryDenied("AgenticDome circuit breaker is open for Microsoft AI Foundry firewall calls.")
        last_error: Optional[Exception] = None
        for attempt in range(max(1, self.config.retry_attempts)):
            try:
                if inspect.iscoroutinefunction(fn):
                    result = await fn(*args, **kwargs)
                else:
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
        return AgenticDomeMicrosoftAIFoundryFirewall._safe_str(value)

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
        return {"_raw": AgenticDomeMicrosoftAIFoundryFirewall._safe_str(raw)}

    def _csv_set(self, value: str) -> set:
        return {item.strip() for item in (value or "").split(",") if item.strip()}

    def _bounded_text(self, text: str, *, limit: int, label: str) -> str:
        if limit > 0 and len(text) > limit:
            return text[:limit] + f"\n[TRUNCATED BY AgenticDome {label}]"
        return text

    def _rate_key(self, *, agent_id: str, session_id: str, purpose: str) -> str:
        return f"{agent_id}:{session_id}:{purpose}"

    def _check_rate_limit(self, *, agent_id: str, session_id: str, purpose: str) -> None:
        limit = self.config.rate_limit_per_minute
        if limit <= 0:
            return
        key = self._rate_key(agent_id=agent_id, session_id=session_id, purpose=purpose)
        now = time.time()
        cutoff = now - 60
        with self._rate_lock:
            events = self._rate_events[key]
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= limit:
                raise MicrosoftAIFoundryDenied(f"Microsoft AI Foundry rate limit exceeded for {purpose}.")
            events.append(now)

    def _enforce_tool_arg_size(self, *, tool_name: str, tool_args: Dict[str, Any]) -> None:
        if self.config.max_tool_arg_chars <= 0:
            return
        serialized = json.dumps(tool_args or {}, sort_keys=True, default=str)
        if len(serialized) > self.config.max_tool_arg_chars:
            raise MicrosoftAIFoundryDenied(f"Microsoft AI Foundry tool arguments exceed max size for {tool_name}.")

    def _emergency_policy_check(self, *, agent_id: str, tool_name: Optional[str] = None) -> None:
        if agent_id in self._csv_set(self.config.emergency_block_agents):
            raise MicrosoftAIFoundryDenied(f"Emergency local policy blocked Foundry agent: {agent_id}")
        if tool_name and tool_name in self._csv_set(self.config.emergency_block_tools):
            raise MicrosoftAIFoundryDenied(f"Emergency local policy blocked Foundry tool: {tool_name}")

    @staticmethod
    def _strip_internal_tool_args(args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            key: value
            for key, value in (args or {}).items()
            if not str(key).startswith("_AgenticDome_")
            and str(key) not in {"decision_token", "source_agent_id", "AgenticDome_decision_token", "AgenticDome_source_agent_id"}
        }

    def _sanitized_args(self, payload: Any) -> Optional[Dict[str, Any]]:
        view = self._extract_decision_view(payload)
        for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
            value = view.get(key) if isinstance(view, dict) else None
            if isinstance(value, dict):
                return self._strip_internal_tool_args(value)
        return None

    def _validate_tool_schema(self, *, tool_name: str, tool_args: Dict[str, Any], schema: Optional[Dict[str, Any]]) -> None:
        if not schema:
            return
        required = schema.get("required")
        if isinstance(required, list):
            missing = [key for key in required if key not in tool_args]
            if missing:
                raise MicrosoftAIFoundryDenied(f"Microsoft AI Foundry tool {tool_name} missing required args: {', '.join(missing)}")
        properties = schema.get("properties")
        if isinstance(properties, dict):
            for key, spec in properties.items():
                if key not in tool_args or not isinstance(spec, dict):
                    continue
                expected = spec.get("type")
                value = tool_args[key]
                type_ok = (
                    expected == "string" and isinstance(value, str)
                    or expected == "number" and isinstance(value, (int, float)) and not isinstance(value, bool)
                    or expected == "integer" and isinstance(value, int) and not isinstance(value, bool)
                    or expected == "boolean" and isinstance(value, bool)
                    or expected == "object" and isinstance(value, dict)
                    or expected == "array" and isinstance(value, list)
                    or expected is None
                )
                if not type_ok:
                    raise MicrosoftAIFoundryDenied(f"Microsoft AI Foundry tool {tool_name} arg {key} failed schema validation.")

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
        logger.info("AgenticDome Microsoft AI Foundry audit: %s", json.dumps(payload, sort_keys=True, default=str))

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
        return default

    def _agent_id(self, ctx: Any, default: str = "microsoft_ai_foundry_agent") -> str:
        agent = self._ctx_attr(ctx, "agent", default=None)
        value = (
            self._ctx_attr(ctx, "agent_id", "agent_name", "name")
            or getattr(agent, "id", None)
            or getattr(agent, "agent_id", None)
            or getattr(agent, "name", None)
        )
        return self._safe_str(value) or default

    def _session_id(self, ctx: Any) -> str:
        for key in ("session_id", "run_id", "trace_id", "conversation_id", "request_id", "thread_id"):
            value = self._ctx_attr(ctx, key)
            if value:
                return self._safe_str(value)
        if self.config.require_explicit_session_id or (
            self.config.production_mode and self.config.require_stable_session_id_in_prod
        ):
            raise MicrosoftAIFoundryDenied("Missing stable session_id/run_id/trace_id in Microsoft AI Foundry context.")
        return f"foundry-{uuid.uuid4().hex}"

    def _user_id(self, ctx: Any) -> Optional[str]:
        value = self._ctx_attr(ctx, "user_id", "principal_id", "caller_id")
        text = self._safe_str(value)
        return text or None

    def _prompt_text(self, ctx: Any) -> str:
        for key in ("prompt", "input_text", "input", "text", "message", "content"):
            value = self._ctx_attr(ctx, key)
            if value:
                return self._serialize_for_review(value)
        return ""

    def _identity_context(self, ctx: Any, policy_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        source = dict(policy_context or {})
        identity = self._ctx_attr(ctx, "identity", "entra_identity", "user", "principal", default=None)
        for key in (
            "tenant_id", "entra_tenant_id", "oid", "object_id", "appid", "app_id", "client_id",
            "upn", "username", "email", "roles", "scp", "azp", "purview_label",
            "sensitivity_label", "data_classification", "foundry_project_id", "foundry_agent_id",
        ):
            value = self._ctx_attr(ctx, key, default=None)
            if value is None and identity is not None:
                value = self._ctx_attr(identity, key, default=None)
            if value is not None and key not in source:
                source[key] = value
        return source

    def _policy_context(
        self,
        *,
        agent_id: str,
        session_id: str,
        request_purpose: str,
        policy_context: Optional[Dict[str, Any]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ctx = dict(policy_context or {})
        ctx.setdefault("request_id", str(uuid.uuid4()))
        ctx.setdefault("request_ts_ms", int(time.time() * 1000))
        ctx.setdefault("request_purpose", request_purpose)
        ctx.setdefault("session_id", session_id)
        ctx.setdefault("source_agent_id", agent_id)
        ctx.setdefault("platform", self.config.platform)
        if extra:
            ctx.update(extra)
        return ctx

    def _tool_platform(self, tool_platform: Optional[str], tool_args: Dict[str, Any]) -> str:
        return (
            self._safe_str(tool_platform)
            or self._safe_str(tool_args.get("tool_platform"))
            or self._safe_str(tool_args.get("platform"))
            or self.config.default_tool_platform
        )

    def _extract_decision_view(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        candidates = [payload]
        for key in ("result", "decision", "analysis", "evaluation", "output", "safety", "moderation"):
            value = payload.get(key)
            if isinstance(value, dict):
                candidates.append(value)
        for candidate in candidates:
            if any(key in candidate for key in ("blocked", "is_blocked", "allowed", "allow", "action", "verdict", "reason", "message")):
                return candidate
            decision = candidate.get("decision")
            if decision is not None and not isinstance(decision, dict):
                return candidate
        return payload

    def _is_blocked(self, payload: Any) -> bool:
        view = self._extract_decision_view(payload)
        for positive_block_key in ("blocked", "is_blocked"):
            if positive_block_key in view:
                return bool(view[positive_block_key])
        for allow_key in ("allowed", "allow"):
            if allow_key in view:
                return not bool(view[allow_key])
        verdict = self._safe_str(view.get("verdict") or view.get("decision")).upper()
        if verdict in {"BLOCKED", "DENY", "DENIED", "REJECTED"}:
            return True
        if verdict in {"ALLOWED", "ALLOW", "APPROVED", "REDACTED"}:
            return False
        action = self._safe_str(view.get("action")).lower()
        return action in {"block", "deny", "denied", "reject", "rejected"}

    def _reason(self, payload: Any) -> str:
        view = self._extract_decision_view(payload)
        return self._safe_str(view.get("reason") or view.get("message") or view.get("explanation") or payload)

    def _sanitized_text(self, response: Any) -> Optional[str]:
        view = self._extract_decision_view(response)
        value = None
        if isinstance(view, dict):
            value = view.get("text") or view.get("sanitized_text") or view.get("output") or view.get("content")
        if value is None and isinstance(response, dict):
            value = response.get("text") or response.get("sanitized_text") or response.get("output") or response.get("content")
        return self._safe_str(value) if value is not None else None

    async def _report_incident_best_effort(
        self,
        *,
        agent_id: str,
        incident_type: str,
        details: str,
        severity: Optional[str] = None,
    ) -> None:
        if not self.config.report_incidents or not self.config.api_key:
            return
        try:
            await self._to_thread(
                self.client.report_incident,
                agent_id=agent_id,
                incident_type=incident_type,
                severity=severity or self.config.blocked_incident_severity,
                details=details,
                tenant_id=self.config.tenant_id or None,
                is_agent=True,
                platform=self.config.platform,
            )
        except Exception as exc:
            logger.warning("AgenticDome incident reporting failed; continuing. reason=%s", exc)

    async def _handle_error(self, exc: Exception, context: str) -> None:
        if isinstance(exc, MicrosoftAIFoundryDenied):
            raise exc
        if self.config.fail_closed:
            raise MicrosoftAIFoundryDenied(f"AgenticDome fail-closed: {context}: {exc}") from exc
        logger.warning("AgenticDome fail-open: %s: %s", context, exc)

    def build_prompt_validation_payload(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        user_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "agentId": agent_id,
            "sessionId": session_id,
            "userId": user_id,
            "input": {"text": text},
            "context": self._policy_context(
                agent_id=agent_id,
                session_id=session_id,
                request_purpose="microsoft_ai_foundry.prompt_input",
                policy_context=policy_context,
            ),
        }

    def build_tool_analysis_payload(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        user_id: Optional[str],
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_platform: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "agentId": agent_id,
            "sessionId": session_id,
            "userId": user_id,
            "conversation": {"text": text},
            "tool": {
                "name": tool_name,
                "platform": tool_platform,
                "arguments": tool_args,
            },
            "context": self._policy_context(
                agent_id=agent_id,
                session_id=session_id,
                request_purpose="microsoft_ai_foundry.tool_execution",
                policy_context=policy_context,
                extra={"tool_platform": tool_platform, "tool_name": tool_name},
            ),
        }

    async def validate_prompt_contract(self, *, payload: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        try:
            self._check_rate_limit(agent_id=agent_id, session_id=self._safe_str(payload.get("sessionId") or payload.get("session_id") or "stateless"), purpose="prompt")
            self._emergency_policy_check(agent_id=agent_id)
            response = await self._client_call(
                self.client.copilot_validate,
                payload,
                api_version=self.config.api_version,
            )
            if self._is_blocked(response):
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type="blocked_prompt_input",
                    details=self._reason(response),
                )
                raise MicrosoftAIFoundryDenied(f"AgenticDome blocked Foundry prompt: {self._reason(response)}")
            self._audit("foundry_prompt_allowed", agent_id=agent_id, session_id=self._safe_str(payload.get("sessionId") or payload.get("session_id") or "stateless"))
            self._otel_event("agenticdome.foundry.prompt_allowed", {"agent_id": agent_id})
            return response
        except Exception as exc:
            await self._handle_error(exc, "validate_prompt_contract")
            return {}

    async def analyze_tool_execution(self, *, payload: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        try:
            payload = dict(payload or {})
            if isinstance(payload.get("tool"), dict):
                tool_payload = dict(payload["tool"])
                if isinstance(tool_payload.get("arguments"), dict):
                    tool_payload["arguments"] = self._strip_internal_tool_args(tool_payload["arguments"])
                payload["tool"] = tool_payload
            session_id = self._safe_str(payload.get("sessionId") or payload.get("session_id") or "stateless")
            tool = payload.get("tool") if isinstance(payload.get("tool"), dict) else {}
            tool_name = self._safe_str(tool.get("name") or payload.get("tool_name") or "foundry_tool")
            if isinstance(tool.get("arguments"), dict):
                self._enforce_tool_arg_size(tool_name=tool_name, tool_args=tool["arguments"])
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose=f"tool:{tool_name}")
            self._emergency_policy_check(agent_id=agent_id, tool_name=tool_name)
            response = await self._client_call(
                self.client.copilot_analyze_tool_execution,
                payload,
                api_version=self.config.api_version,
            )
            if self._is_blocked(response):
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type="blocked_tool_execution",
                    details=self._reason(response),
                )
                raise MicrosoftAIFoundryDenied(f"AgenticDome blocked Foundry tool execution: {self._reason(response)}")
            self._audit("foundry_tool_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": tool_name})
            return response
        except Exception as exc:
            await self._handle_error(exc, "analyze_tool_execution")
            return {}

    async def sanitize_text(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> str:
        try:
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="output")
            bounded_text = self._bounded_text(text, limit=self.config.max_output_chars, label="FOUNDRY OUTPUT")
            response = await self._client_call(
                self.client.mesh_validate,
                text=bounded_text,
                agent_id=agent_id,
                direction="output",
                session_id=session_id,
                platform=self.config.platform,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._policy_context(
                    agent_id=agent_id,
                    session_id=session_id,
                    request_purpose="microsoft_ai_foundry.output_review",
                    policy_context=policy_context,
                    extra={
                        "redact_pii": self.config.redact_pii,
                        "redact_secrets": self.config.redact_secrets,
                        "block_on_sensitive_output": self.config.block_on_sensitive_output,
                    },
                ),
            )
            if self._is_blocked(response):
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type="blocked_output",
                    details=self._reason(response),
                )
                return "[OUTPUT BLOCKED BY AgenticDome]"
            sanitized = self._sanitized_text(response)
            return sanitized if sanitized is not None else bounded_text
        except Exception as exc:
            await self._handle_error(exc, "sanitize_text")
            return text

    async def _sanitize_handler_result(
        self,
        *,
        raw_result: Any,
        agent_id: str,
        session_id: str,
        policy_context: Dict[str, Any],
        preserve_structured_output: bool,
    ) -> Any:
        result_text = self._serialize_for_review(raw_result)
        sanitized = await self.sanitize_text(
            text=result_text,
            agent_id=agent_id,
            session_id=session_id,
            policy_context=policy_context,
        )
        if preserve_structured_output and isinstance(raw_result, (dict, list, tuple)):
            if sanitized == result_text:
                return raw_result
            try:
                parsed = json.loads(sanitized)
                if isinstance(parsed, (dict, list)):
                    return parsed
            except Exception:
                pass
        return sanitized

    def wrap_tool_executor(
        self,
        *,
        tool_name: str,
        handler: Callable[..., Any],
        tool_platform: Optional[str] = None,
        text_builder: Optional[Callable[[Any, Dict[str, Any]], str]] = None,
        policy_context_builder: Optional[Callable[[Any, Dict[str, Any]], Dict[str, Any]]] = None,
        analysis_payload_builder: Optional[Callable[[Any, Dict[str, Any]], Dict[str, Any]]] = None,
        tool_schema: Optional[Dict[str, Any]] = None,
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
    ) -> Callable[..., Awaitable[Any]]:
        async def secured(ctx: Any, args: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args)
            clean_args = self._strip_internal_tool_args(tool_args)
            agent_id = self._agent_id(ctx)
            session_id = self._session_id(ctx)
            user_id = self._user_id(ctx)
            prompt_text = (
                text_builder(ctx, clean_args)
                if text_builder
                else self._prompt_text(ctx) or f"[Microsoft AI Foundry] {agent_id} intends to execute {tool_name}"
            )
            self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_args)
            self._validate_tool_schema(tool_name=tool_name, tool_args=clean_args, schema=tool_schema)
            policy_context = self._identity_context(
                ctx,
                policy_context_builder(ctx, clean_args)
                if policy_context_builder
                else {"framework": "microsoft_ai_foundry", "agent_name": agent_id},
            )
            effective_tool_platform = self._tool_platform(tool_platform, clean_args)
            payload = (
                analysis_payload_builder(ctx, clean_args)
                if analysis_payload_builder
                else self.build_tool_analysis_payload(
                    text=self._bounded_text(prompt_text, limit=self.config.max_input_chars, label="FOUNDRY TOOL"),
                    agent_id=agent_id,
                    session_id=session_id,
                    user_id=user_id,
                    tool_name=tool_name,
                    tool_args=clean_args,
                    tool_platform=effective_tool_platform,
                    policy_context=policy_context,
                )
            )
            decision = await self.analyze_tool_execution(payload=payload, agent_id=agent_id)
            execution_args = self._sanitized_args(decision) or clean_args
            self._validate_tool_schema(tool_name=tool_name, tool_args=execution_args, schema=tool_schema)
            if asyncio.iscoroutinefunction(handler):
                raw_result = await handler(ctx, execution_args, *a, **kw)
            else:
                raw_result = await asyncio.to_thread(handler, ctx, execution_args, *a, **kw)
            if not sanitize_output:
                return raw_result
            return await self._sanitize_handler_result(
                raw_result=raw_result,
                agent_id=agent_id,
                session_id=session_id,
                preserve_structured_output=preserve_structured_output,
                policy_context={
                    **policy_context,
                    "request_purpose": "microsoft_ai_foundry.tool_output_review",
                    "tool_name": tool_name,
                },
            )
        return secured

    def secure_tool(
        self,
        *,
        tool_name: Optional[str] = None,
        tool_platform: Optional[str] = None,
        tool_schema: Optional[Dict[str, Any]] = None,
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
    ) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_executor(
                tool_name=tool_name or getattr(handler, "__name__", "foundry_tool"),
                handler=handler,
                tool_platform=tool_platform,
                tool_schema=tool_schema,
                sanitize_output=sanitize_output,
                preserve_structured_output=preserve_structured_output,
            )
        return decorator

    async def run_secure(
        self,
        *,
        run_callable: Callable[..., Any],
        input_text: str,
        ctx: Any,
        validation_payload_builder: Optional[Callable[[Any, str], Dict[str, Any]]] = None,
        output_extractor: Optional[Callable[[Any], str]] = None,
        sanitize_output: bool = True,
        **kwargs: Any,
    ) -> Any:
        agent_id = self._agent_id(ctx)
        session_id = self._session_id(ctx)
        user_id = self._user_id(ctx)
        policy_context = self._identity_context(ctx, self._ctx_attr(ctx, "policy_context", default={}) or {})
        bounded_input = self._bounded_text(input_text, limit=self.config.max_input_chars, label="FOUNDRY INPUT")
        payload = (
            validation_payload_builder(ctx, bounded_input)
            if validation_payload_builder
            else self.build_prompt_validation_payload(
                text=bounded_input,
                agent_id=agent_id,
                session_id=session_id,
                user_id=user_id,
                policy_context=policy_context,
            )
        )
        await self.validate_prompt_contract(payload=payload, agent_id=agent_id)
        if asyncio.iscoroutinefunction(run_callable):
            result = await run_callable(input_text=bounded_input, session_id=session_id, **kwargs)
        else:
            result = await asyncio.to_thread(run_callable, input_text=bounded_input, session_id=session_id, **kwargs)
        if not sanitize_output:
            return result
        output_text = output_extractor(result) if output_extractor else self._serialize_for_review(result)
        return await self.sanitize_text(
            text=output_text,
            agent_id=agent_id,
            session_id=session_id,
            policy_context={**policy_context, "request_purpose": "microsoft_ai_foundry.final_user_output"},
        )

    async def authorize_manager_handoff(
        self,
        *,
        text: str,
        manager_agent_id: str,
        specialist_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_id: str,
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_args = self._strip_internal_tool_args(tool_args)
        self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_args)
        effective_tool_platform = self._tool_platform(tool_platform, clean_args)
        try:
            response = await self._client_call(
                self.client.a2a_authorize_tool,
                text=self._bounded_text(text or f"[Microsoft AI Foundry] Manager {manager_agent_id} delegates {tool_name} to {specialist_agent_id}", limit=self.config.max_input_chars, label="FOUNDRY HANDOFF"),
                agent_id=specialist_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform=effective_tool_platform,
                tool_name=tool_name,
                tool_args=clean_args,
                session_id=session_id,
                direction="outbound",
                source_agent_id=manager_agent_id,
                policy_context=self._policy_context(
                    agent_id=manager_agent_id,
                    session_id=session_id,
                    request_purpose="microsoft_ai_foundry.delegated_task",
                    policy_context=policy_context,
                    extra={
                        "source_agent_id": manager_agent_id,
                        "delegation_chain": [manager_agent_id, specialist_agent_id],
                        "tool_platform": effective_tool_platform,
                    },
                ),
            )
            view = self._extract_decision_view(response)
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=manager_agent_id, incident_type="blocked_delegation", details=reason)
                raise MicrosoftAIFoundryDenied(f"AgenticDome blocked Foundry delegation: {reason}")
            token = self._safe_str(view.get("decision_token") or view.get("token"))
            if token:
                self.token_store.put(
                    session_id=session_id,
                    target_agent_id=specialist_agent_id,
                    tool_name=tool_name,
                    tool_args=clean_args,
                    record=DecisionTokenRecord(token, manager_agent_id, time.time(), self._token_hmac(token)),
                    ttl_s=self.config.handoff_token_ttl_s,
                )
            self._audit("foundry_handoff_authorized", agent_id=manager_agent_id, session_id=session_id, details={"specialist_agent_id": specialist_agent_id, "tool_name": tool_name})
            return response
        except Exception as exc:
            await self._handle_error(exc, "authorize_manager_handoff")
            return {}

    async def verify_delegated_execution(
        self,
        *,
        specialist_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_id: str,
        decision_token: Optional[str] = None,
        source_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_args = self._strip_internal_tool_args(tool_args)
        token = decision_token
        source = source_agent_id
        if not token:
            pending = self.token_store.consume(session_id=session_id, target_agent_id=specialist_agent_id, tool_name=tool_name, tool_args=clean_args)
            if pending:
                if not self._verify_record_hmac(pending):
                    raise MicrosoftAIFoundryDenied("Stored AgenticDome Foundry decision token failed local HMAC verification.")
                token = pending.decision_token
                source = pending.source_agent_id
        if not token or not source:
            await self._report_incident_best_effort(agent_id=specialist_agent_id, incident_type="missing_delegation_token", details=f"tool={tool_name}", severity="high")
            raise MicrosoftAIFoundryDenied("Missing AgenticDome decision token or source_agent_id for delegated Foundry execution.")
        try:
            response = await self._client_call(
                self.client.a2a_verify_decision_token_rpc,
                token,
                tool_name=tool_name,
                tool_args=clean_args,
                agent_id=specialist_agent_id,
                source_agent_id=source,
                platform=self.config.platform,
                require_allowed=True,
            )
            view = self._extract_decision_view(response)
            if not bool(view.get("valid") or view.get("allowed")):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=specialist_agent_id, incident_type="invalid_delegation_token", details=reason, severity="high")
                raise MicrosoftAIFoundryDenied(f"AgenticDome blocked delegated Foundry execution: {reason}")
            self._audit("foundry_delegation_verified", agent_id=specialist_agent_id, session_id=session_id, details={"tool_name": tool_name, "source_agent_id": source})
            return view or response
        except Exception as exc:
            await self._handle_error(exc, "verify_delegated_execution")
            return {}

    async def sanitize_streaming_response(
        self,
        *,
        chunks: Any,
        agent_id: str,
        session_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[Any]:
        if hasattr(chunks, "__aiter__"):
            async for chunk in chunks:
                yield await self._sanitize_stream_chunk(chunk=chunk, agent_id=agent_id, session_id=session_id, policy_context=policy_context)
            return
        if isinstance(chunks, Iterable) and not isinstance(chunks, (str, bytes, dict)):
            for chunk in chunks:
                yield await self._sanitize_stream_chunk(chunk=chunk, agent_id=agent_id, session_id=session_id, policy_context=policy_context)
            return
        yield await self._sanitize_stream_chunk(chunk=chunks, agent_id=agent_id, session_id=session_id, policy_context=policy_context)

    async def _sanitize_stream_chunk(self, *, chunk: Any, agent_id: str, session_id: str, policy_context: Optional[Dict[str, Any]] = None) -> Any:
        if isinstance(chunk, str):
            return await self.sanitize_text(text=chunk, agent_id=agent_id, session_id=session_id, policy_context=policy_context)
        if isinstance(chunk, dict):
            return await self._sanitize_handler_result(raw_result=chunk, agent_id=agent_id, session_id=session_id, policy_context=policy_context or {}, preserve_structured_output=True)
        text = self._safe_str(chunk)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, policy_context=policy_context)
        for attr in ("text", "content", "message", "output"):
            if hasattr(chunk, attr):
                try:
                    setattr(chunk, attr, sanitized)
                    return chunk
                except Exception:
                    pass
        return sanitized

    async def before_run(self, ctx: Any, input_text: str, policy_context: Optional[Dict[str, Any]] = None) -> None:
        agent_id = self._agent_id(ctx)
        session_id = self._session_id(ctx)
        payload = self.build_prompt_validation_payload(
            text=self._bounded_text(input_text, limit=self.config.max_input_chars, label="FOUNDRY INPUT"),
            agent_id=agent_id,
            session_id=session_id,
            user_id=self._user_id(ctx),
            policy_context=self._identity_context(ctx, policy_context),
        )
        await self.validate_prompt_contract(payload=payload, agent_id=agent_id)

    async def after_run(self, ctx: Any, output: Any, policy_context: Optional[Dict[str, Any]] = None) -> Any:
        agent_id = self._agent_id(ctx)
        session_id = self._session_id(ctx)
        return await self.sanitize_text(text=self._serialize_for_review(output), agent_id=agent_id, session_id=session_id, policy_context=self._identity_context(ctx, policy_context))

    async def before_tool_call(
        self,
        ctx: Any,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        tool_schema: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        secured_args = self._strip_internal_tool_args(tool_args)
        self._enforce_tool_arg_size(tool_name=tool_name, tool_args=secured_args)
        self._validate_tool_schema(tool_name=tool_name, tool_args=secured_args, schema=tool_schema)
        agent_id = self._agent_id(ctx)
        session_id = self._session_id(ctx)
        payload = self.build_tool_analysis_payload(
            text=self._prompt_text(ctx) or f"[Microsoft AI Foundry] {agent_id} intends to execute {tool_name}",
            agent_id=agent_id,
            session_id=session_id,
            user_id=self._user_id(ctx),
            tool_name=tool_name,
            tool_args=secured_args,
            tool_platform=self._tool_platform(tool_platform, secured_args),
            policy_context=self._identity_context(ctx, policy_context),
        )
        decision = await self.analyze_tool_execution(payload=payload, agent_id=agent_id)
        execution_args = self._sanitized_args(decision) or secured_args
        self._validate_tool_schema(tool_name=tool_name, tool_args=execution_args, schema=tool_schema)
        return execution_args

    async def after_tool_call(self, ctx: Any, *, tool_name: str, result: Any, policy_context: Optional[Dict[str, Any]] = None) -> Any:
        return await self._sanitize_handler_result(
            raw_result=result,
            agent_id=self._agent_id(ctx),
            session_id=self._session_id(ctx),
            policy_context={**self._identity_context(ctx, policy_context), "tool_name": tool_name},
            preserve_structured_output=True,
        )

    def create_middleware(self) -> Any:
        firewall = self

        class AgenticDomeFoundryMiddleware:
            async def before_run(self, ctx: Any, input_text: str, **kwargs: Any) -> None:
                await firewall.before_run(ctx, input_text, policy_context=kwargs.get("policy_context"))

            async def after_run(self, ctx: Any, output: Any, **kwargs: Any) -> Any:
                return await firewall.after_run(ctx, output, policy_context=kwargs.get("policy_context"))

            async def before_tool_call(self, ctx: Any, tool_name: str, tool_args: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
                return await firewall.before_tool_call(
                    ctx,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    tool_platform=kwargs.get("tool_platform"),
                    policy_context=kwargs.get("policy_context"),
                    tool_schema=kwargs.get("tool_schema"),
                )

            async def after_tool_call(self, ctx: Any, tool_name: str, result: Any, **kwargs: Any) -> Any:
                return await firewall.after_tool_call(ctx, tool_name=tool_name, result=result, policy_context=kwargs.get("policy_context"))

        return AgenticDomeFoundryMiddleware()

    def install_on_client(self, foundry_client: Any, *, attr_name: str = "agenticdome_middleware") -> Any:
        middleware = self.create_middleware()
        existing = getattr(foundry_client, attr_name, None)
        if isinstance(existing, list):
            existing.append(middleware)
        elif existing is None:
            setattr(foundry_client, attr_name, [middleware])
        else:
            setattr(foundry_client, attr_name, [existing, middleware])
        return foundry_client

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


__all__ = [
    "FirewallConfig",
    "load_config",
    "MicrosoftAIFoundryFirewallError",
    "MicrosoftAIFoundryDenied",
    "MicrosoftAIFoundryConfigurationError",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "AgenticDomeMicrosoftAIFoundryFirewall",
]
