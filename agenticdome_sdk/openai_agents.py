from __future__ import annotations

import asyncio
import base64
import functools
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
from typing import Any, AsyncIterator, Awaitable, Callable, Deque, Dict, Optional, Tuple

from agenticdome_sdk.client import AgentGuardClient
from agenticdome_sdk._mode import credentials_or_local_sim

try:
    from agenticdome_sdk.exceptions import AgentGuardHTTPError
except Exception:  # pragma: no cover
    try:
        from agenticdome_sdk.client import AgentGuardHTTPError  # type: ignore
    except Exception:
        class AgentGuardHTTPError(Exception):  # type: ignore
            pass


logger = logging.getLogger("agenticdome.openai_agents")
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

    platform: str = "openai_agents_sdk"
    default_tool_platform: str = "openai_agents_sdk"

    timeout_s: int = 20
    fail_closed: bool = True
    require_explicit_session_id: bool = False
    production_mode: bool = False
    require_stable_session_id_in_prod: bool = True

    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:openai_agents:handoff"
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
        api_base=_env("AGENTICDOME_API_BASE", "").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        platform=_env("AGENTICDOME_PLATFORM", "openai_agents_sdk"),
        default_tool_platform=_env("AGENTICDOME_TOOL_PLATFORM", _env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "openai_agents_sdk")),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        production_mode=_env_bool("AGENTICDOME_PRODUCTION_MODE", False),
        require_stable_session_id_in_prod=_env_bool("AGENTICDOME_REQUIRE_STABLE_SESSION_ID_IN_PROD", True),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
        redis_url=_env("AGENTICDOME_REDIS_URL", "").strip(),
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:openai_agents:handoff"),
        token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET", ""),
        max_input_chars=_env_int("AGENTICDOME_OPENAI_AGENTS_MAX_INPUT_CHARS", 50_000),
        max_output_chars=_env_int("AGENTICDOME_OPENAI_AGENTS_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_OPENAI_AGENTS_MAX_TOOL_ARG_CHARS", 20_000),
        streaming_buffer_chars=_env_int("AGENTICDOME_OPENAI_AGENTS_STREAMING_BUFFER_CHARS", 4_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_OPENAI_AGENTS_RATE_LIMIT_PER_MINUTE", 0),
        retry_attempts=_env_int("AGENTICDOME_OPENAI_AGENTS_RETRY_ATTEMPTS", 2),
        retry_backoff_s=float(_env("AGENTICDOME_OPENAI_AGENTS_RETRY_BACKOFF_S", "0.25") or "0.25"),
        circuit_breaker_failures=_env_int("AGENTICDOME_OPENAI_AGENTS_CIRCUIT_BREAKER_FAILURES", 5),
        circuit_breaker_reset_s=_env_int("AGENTICDOME_OPENAI_AGENTS_CIRCUIT_BREAKER_RESET_S", 60),
        audit_logging=_env_bool("AGENTICDOME_OPENAI_AGENTS_AUDIT_LOGGING", True),
        otel_enabled=_env_bool("AGENTICDOME_OPENAI_AGENTS_OTEL_ENABLED", True),
        emergency_block_tools=_env("AGENTICDOME_OPENAI_AGENTS_EMERGENCY_BLOCK_TOOLS", ""),
        emergency_block_agents=_env("AGENTICDOME_OPENAI_AGENTS_EMERGENCY_BLOCK_AGENTS", ""),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
    )


# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------

class OpenAIAgentsFirewallError(RuntimeError):
    """Base OpenAI Agents SDK firewall exception."""


class OpenAIAgentsFirewallDenied(OpenAIAgentsFirewallError):
    """Raised when AgenticDome blocks or fail-closes execution."""

    def __init__(self, reason: str, decision: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.decision = decision or {}


class OpenAIAgentsFirewallConfigurationError(OpenAIAgentsFirewallError):
    """Raised when required configuration or runtime context is missing."""


# Backward-compatible aliases for early draft names.
ToolBlocked = OpenAIAgentsFirewallDenied
FirewallMisconfigured = OpenAIAgentsFirewallConfigurationError


# -----------------------------------------------------------------------------
# Decision-token stores
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

    def _key(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
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
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
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
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
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
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        with self._lock:
            self._data.pop(key, None)


class RedisDecisionTokenStore(DecisionTokenStore):
    def __init__(self, redis_url: str, key_prefix: str, tenant_id: str) -> None:
        import redis

        self._tenant_id = tenant_id
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = key_prefix.rstrip(":")

    def _key(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
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
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        self._client.setex(key, ttl_s, _canonical_json({
            "decision_token": record.decision_token,
            "source_agent_id": record.source_agent_id,
            "created_at": record.created_at,
            "token_hmac": record.token_hmac,
        }))

    def get(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
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
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
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
            logger.info("AgenticDome OpenAI Agents firewall using Redis token store.")
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id)
        except Exception as exc:
            logger.warning("Redis token store unavailable; falling back to memory. reason=%s", exc)
    return InMemoryDecisionTokenStore(config.tenant_id)


# -----------------------------------------------------------------------------
# Main firewall
# -----------------------------------------------------------------------------

class AgenticDomeOpenAIAgentsFirewall:
    """AgenticDome firewall for OpenAI Agents SDK local run/tool boundaries."""

    def __init__(
        self,
        config: Optional[FirewallConfig] = None,
        *,
        client: Optional[AgentGuardClient] = None,
        token_store: Optional[DecisionTokenStore] = None,
    ) -> None:
        self.config = config or load_config()
        if not credentials_or_local_sim(self.config.api_base, self.config.api_key, self.config.tenant_id):
            raise OpenAIAgentsFirewallConfigurationError(
                "Missing AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, or AGENTICDOME_TENANT_ID."
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

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass

    async def _call_sync(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
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
            raise OpenAIAgentsFirewallDenied("AgenticDome OpenAI Agents circuit breaker is open.")
        last_error: Optional[Exception] = None
        for attempt in range(max(1, self.config.retry_attempts)):
            try:
                result = await self._call_sync(fn, *args, **kwargs)
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
            return _canonical_json(value)
        return AgenticDomeOpenAIAgentsFirewall._safe_str(value)

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
        return {"_raw": AgenticDomeOpenAIAgentsFirewall._safe_str(raw)}

    @staticmethod
    def _extract_result(payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        result = payload.get("result")
        return result if isinstance(result, dict) else payload

    @staticmethod
    def _verdict(decision: Any) -> str:
        env = AgenticDomeOpenAIAgentsFirewall._extract_result(decision)
        return str(env.get("verdict") or env.get("decision") or "").upper()

    @staticmethod
    def _reason(decision: Any) -> str:
        env = AgenticDomeOpenAIAgentsFirewall._extract_result(decision)
        return str(env.get("reason") or env.get("message") or decision)

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

    def _ctx_agent_id(self, ctx: Any) -> str:
        agent = self._ctx_attr(ctx, "agent", default=None)
        return (
            self._safe_str(getattr(agent, "name", None))
            or self._safe_str(getattr(agent, "agent_id", None))
            or self._safe_str(getattr(agent, "id", None))
            or self._safe_str(self._ctx_attr(ctx, "agent_name", "agent_id", "name"))
            or "openai_agent"
        )

    def _ctx_session_id(self, ctx: Any) -> str:
        direct = self._ctx_attr(ctx, "session_id", "run_id", "trace_id", "conversation_id", "request_id", "thread_id")
        if direct:
            return self._safe_str(direct)
        context_obj = self._ctx_attr(ctx, "context", default=None)
        if context_obj is not None:
            nested = self._ctx_attr(context_obj, "session_id", "run_id", "trace_id", "conversation_id", "thread_id")
            if nested:
                return self._safe_str(nested)
        if self.config.require_explicit_session_id or (self.config.production_mode and self.config.require_stable_session_id_in_prod):
            raise OpenAIAgentsFirewallDenied("Missing stable session_id/run_id/trace_id in OpenAI Agents context.")
        return f"openai-agents-{uuid.uuid4().hex}"

    def _ctx_source_agent_id(self, ctx: Any) -> Optional[str]:
        value = self._ctx_attr(ctx, "source_agent_id") or self._ctx_attr(self._ctx_attr(ctx, "context", default=None), "source_agent_id")
        text = self._safe_str(value)
        return text or None

    def _identity_context(self, source: Any = None) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        context_obj = self._ctx_attr(source, "context", default=None) if source is not None else None
        for key in (
            "user_id", "principal_id", "caller_id", "organization_id", "project_id", "workspace_id",
            "thread_id", "conversation_id", "run_id", "trace_id", "model", "model_id", "agent_group",
            "data_classification", "sensitivity_label", "roles", "scopes",
        ):
            value = self._ctx_attr(source, key, default=None) if source is not None else None
            if value is None and context_obj is not None:
                value = self._ctx_attr(context_obj, key, default=None)
            if value is not None:
                out[key] = value
        return out

    def _policy_context(
        self,
        *,
        session_id: str,
        request_purpose: str,
        policy_context: Optional[Dict[str, Any]] = None,
        source: Any = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ctx = dict(policy_context or {})
        ctx.setdefault("request_id", str(uuid.uuid4()))
        ctx.setdefault("request_ts_ms", int(time.time() * 1000))
        ctx["request_purpose"] = request_purpose
        ctx.setdefault("session_id", session_id)
        ctx.setdefault("platform", self.config.platform)
        ctx.update({k: v for k, v in self._identity_context(source).items() if v is not None and v != ""})
        if extra:
            ctx.update(extra)
        return ctx

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

    async def _handle_failure(self, context: str, exc: Exception) -> None:
        if isinstance(exc, OpenAIAgentsFirewallDenied):
            raise exc
        if self.config.fail_closed:
            raise OpenAIAgentsFirewallDenied(f"AgenticDome fail-closed: {context}: {exc}") from exc
        logger.warning("AgenticDome fail-open: %s: %s", context, exc)

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
                raise OpenAIAgentsFirewallDenied(f"OpenAI Agents rate limit exceeded for {purpose}.")
            events.append(now)

    def _enforce_tool_arg_size(self, *, tool_name: str, tool_args: Dict[str, Any]) -> None:
        if self.config.max_tool_arg_chars > 0 and len(self._serialize_for_review(tool_args or {})) > self.config.max_tool_arg_chars:
            raise OpenAIAgentsFirewallDenied(f"OpenAI Agents tool arguments exceed max size for {tool_name}.")

    def _emergency_policy_check(self, *, agent_id: str, tool_name: Optional[str] = None) -> None:
        agents = {item.strip() for item in (self.config.emergency_block_agents or "").split(",") if item.strip()}
        tools = {item.strip() for item in (self.config.emergency_block_tools or "").split(",") if item.strip()}
        if agent_id in agents:
            raise OpenAIAgentsFirewallDenied(f"Emergency local policy blocked OpenAI Agents agent: {agent_id}")
        if tool_name and tool_name in tools:
            raise OpenAIAgentsFirewallDenied(f"Emergency local policy blocked OpenAI Agents tool: {tool_name}")

    def _audit(self, event: str, *, agent_id: str, session_id: str, details: Optional[Dict[str, Any]] = None) -> None:
        if not self.config.audit_logging:
            return
        payload = {"event": event, "agent_id": agent_id, "session_id": session_id, "platform": self.config.platform}
        if details:
            payload.update(details)
        logger.info("AgenticDome OpenAI Agents audit: %s", json.dumps(payload, sort_keys=True, default=str))

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
                raise OpenAIAgentsFirewallDenied(f"OpenAI Agents tool {tool_name} missing required args: {', '.join(missing)}")
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
                    raise OpenAIAgentsFirewallDenied(f"OpenAI Agents tool {tool_name} arg {key} failed schema validation.")

    def _sanitized_args(self, response: Any) -> Optional[Dict[str, Any]]:
        envelope = self._extract_result(response)
        for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
            value = envelope.get(key) if isinstance(envelope, dict) else None
            if isinstance(value, dict):
                return self._strip_private_args(value)
        return None

    def _mutate_args(self, original: Any, replacement: Dict[str, Any]) -> Dict[str, Any]:
        clean = self._strip_private_args(replacement)
        if isinstance(original, dict):
            original.clear()
            original.update(clean)
            return original
        return clean

    def _tool_platform(self, override: Optional[str], tool_args: Dict[str, Any]) -> str:
        return (
            self._safe_str(override)
            or self._safe_str(tool_args.get("tool_platform"))
            or self._safe_str(tool_args.get("platform"))
            or self.config.default_tool_platform
        )

    @staticmethod
    def _strip_private_args(tool_args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            key: value
            for key, value in (tool_args or {}).items()
            if not str(key).startswith("_AgenticDome_")
            and key not in {"_decision_token", "_source_agent_id", "decision_token", "source_agent_id"}
        }

    async def screen_input(self, *, session_id: str, agent_id: str, text: str, policy_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            self._emergency_policy_check(agent_id=agent_id)
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="input")
            response = await self._client_call(
                self.client.guardrail_validate,
                text=self._bounded_text(text, limit=self.config.max_input_chars, label="OPENAI AGENTS INPUT"),
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="input",
                session_id=session_id,
                policy_context=self._policy_context(
                    session_id=session_id,
                    request_purpose="openai_agents_prompt_input",
                    policy_context=policy_context,
                ),
            )
            if self._verdict(response) == "BLOCKED":
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_prompt_input", details=reason)
                raise OpenAIAgentsFirewallDenied(f"AgenticDome blocked OpenAI Agents prompt: {reason}", decision=response)
            self._audit("openai_agents_input_allowed", agent_id=agent_id, session_id=session_id)
            self._otel_event("agenticdome.openai_agents.input_allowed", {"agent_id": agent_id, "session_id": session_id})
            return self._extract_result(response) or response
        except Exception as exc:
            await self._handle_failure("input screening", exc)
            return {}

    async def authorize_direct_tool_call(
        self,
        *,
        session_id: str,
        agent_id: str,
        source_agent_id: Optional[str],
        tool_name: str,
        tool_args: Dict[str, Any],
        text: str,
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        tool_schema: Optional[Any] = None,
    ) -> Dict[str, Any]:
        clean_args = self._strip_private_args(tool_args)
        effective_tool_platform = self._tool_platform(tool_platform, clean_args)
        try:
            self._emergency_policy_check(agent_id=agent_id, tool_name=tool_name)
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose=f"tool:{tool_name}")
            self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_args)
            self._validate_tool_schema(tool_name=tool_name, tool_args=clean_args, schema=tool_schema)
            response = await self._client_call(
                self.client.guardrail_validate,
                text=self._bounded_text(text, limit=self.config.max_input_chars, label="OPENAI AGENTS TOOL"),
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="outbound",
                session_id=session_id,
                tool_platform=effective_tool_platform,
                tool_name=tool_name,
                tool_args=clean_args,
                policy_context=self._policy_context(
                    session_id=session_id,
                    request_purpose="openai_agents_tool_call",
                    policy_context=policy_context,
                    extra={"source_agent_id": source_agent_id or agent_id, "tool_platform": effective_tool_platform},
                ),
                source_agent_id=source_agent_id,
            )
            if self._verdict(response) == "BLOCKED":
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_tool_execution", details=reason)
                raise OpenAIAgentsFirewallDenied(f"AgenticDome blocked OpenAI Agents tool: {reason}", decision=response)
            sanitized = self._sanitized_args(response)
            envelope = self._extract_result(response) or response
            if sanitized is not None:
                self._validate_tool_schema(tool_name=tool_name, tool_args=sanitized, schema=tool_schema)
                envelope = dict(envelope or {})
                envelope["sanitized_tool_args"] = sanitized
            self._audit("openai_agents_tool_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": tool_name})
            self._otel_event("agenticdome.openai_agents.tool_allowed", {"agent_id": agent_id, "session_id": session_id, "tool_name": tool_name})
            return envelope
        except Exception as exc:
            await self._handle_failure("tool authorization", exc)
            return {"verdict": "ALLOWED", "reason": "fail-open"}

    async def authorize_manager_handoff(
        self,
        *,
        session_id: str,
        manager_agent_id: str,
        specialist_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        text: str,
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_args = self._strip_private_args(tool_args)
        effective_tool_platform = self._tool_platform(tool_platform, clean_args)
        try:
            self._emergency_policy_check(agent_id=manager_agent_id, tool_name=tool_name)
            self._emergency_policy_check(agent_id=specialist_agent_id, tool_name=tool_name)
            self._check_rate_limit(agent_id=manager_agent_id, session_id=session_id, purpose=f"handoff:{specialist_agent_id}")
            self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_args)
            response = await self._client_call(
                self.client.a2a_authorize_tool,
                text=self._bounded_text(text or f"[OpenAI Agents] {manager_agent_id} delegates {tool_name} to {specialist_agent_id}", limit=self.config.max_input_chars, label="OPENAI AGENTS HANDOFF"),
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
                    session_id=session_id,
                    request_purpose="openai_agents_delegated_task",
                    policy_context=policy_context,
                    extra={
                        "source_agent_id": manager_agent_id,
                        "delegation_chain": [manager_agent_id, specialist_agent_id],
                        "tool_platform": effective_tool_platform,
                    },
                ),
            )
            envelope = self._extract_result(response)
            if self._verdict(envelope) != "ALLOWED":
                reason = self._reason(envelope)
                await self._report_incident_best_effort(agent_id=manager_agent_id, incident_type="blocked_delegation", details=reason)
                raise OpenAIAgentsFirewallDenied(f"AgenticDome blocked OpenAI Agents handoff: {reason}", decision=envelope)
            decision_token = self._safe_str(envelope.get("decision_token") or envelope.get("token"))
            if decision_token:
                self.token_store.put(
                    session_id=session_id,
                    target_agent_id=specialist_agent_id,
                    tool_name=tool_name,
                    tool_args=clean_args,
                    record=DecisionTokenRecord(decision_token=decision_token, source_agent_id=manager_agent_id, created_at=time.time(), token_hmac=self._token_hmac(decision_token)),
                    ttl_s=self.config.handoff_token_ttl_s,
                )
            self._audit("openai_agents_handoff_allowed", agent_id=manager_agent_id, session_id=session_id, details={"target_agent_id": specialist_agent_id, "tool_name": tool_name})
            return envelope
        except Exception as exc:
            await self._handle_failure("handoff authorization", exc)
            return {}

    async def verify_specialist_execution(
        self,
        *,
        session_id: str,
        specialist_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        decision_token: Optional[str] = None,
        source_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_args = self._strip_private_args(tool_args)
        token = decision_token
        source = source_agent_id
        if not token:
            pending = self.token_store.consume(
                session_id=session_id,
                target_agent_id=specialist_agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
            )
            if pending:
                if not self._verify_record_hmac(pending):
                    raise OpenAIAgentsFirewallDenied("Invalid AgenticDome decision token HMAC for OpenAI Agents delegated execution.")
                token = pending.decision_token
                source = pending.source_agent_id
        if not token or not source:
            await self._report_incident_best_effort(
                agent_id=specialist_agent_id,
                incident_type="missing_delegation_token",
                details=f"tool={tool_name}",
                severity="high",
            )
            raise OpenAIAgentsFirewallDenied("Missing AgenticDome decision token or source_agent_id for delegated execution.")
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
            result = self._extract_result(response)
            if not bool(result.get("valid") or result.get("allowed")):
                await self._report_incident_best_effort(
                    agent_id=specialist_agent_id,
                    incident_type="invalid_delegation_token",
                    details=self._safe_str(result),
                    severity="high",
                )
                raise OpenAIAgentsFirewallDenied(f"AgenticDome blocked delegated execution: {result.get('reason') or result}", decision=result)
            self.token_store.delete(
                session_id=session_id,
                target_agent_id=specialist_agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
            )
            self._audit("openai_agents_delegated_execution_allowed", agent_id=specialist_agent_id, session_id=session_id, details={"tool_name": tool_name})
            return result
        except Exception as exc:
            await self._handle_failure("token verification", exc)
            return {}

    async def sanitize_output(self, *, session_id: str, agent_id: str, text: str, policy_context: Optional[Dict[str, Any]] = None) -> str:
        try:
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="output")
            response = await self._client_call(
                self.client.mesh_validate,
                text=self._bounded_text(text, limit=self.config.max_output_chars, label="OPENAI AGENTS OUTPUT"),
                agent_id=agent_id,
                direction="output",
                session_id=session_id,
                platform=self.config.platform,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._policy_context(
                    session_id=session_id,
                    request_purpose="openai_agents_output_review",
                    policy_context=policy_context,
                    extra={
                        "redact_pii": self.config.redact_pii,
                        "redact_secrets": self.config.redact_secrets,
                        "block_on_sensitive_output": self.config.block_on_sensitive_output,
                    },
                ),
            )
            envelope = self._extract_result(response)
            sanitized_text = (
                envelope.get("text")
                or envelope.get("sanitized_text")
                or envelope.get("output")
                or (response.get("text") if isinstance(response, dict) else None)
                or (response.get("sanitized_text") if isinstance(response, dict) else None)
            )
            if self._verdict(envelope) == "BLOCKED":
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_output", details=self._reason(envelope))
                return "[OUTPUT BLOCKED BY AgenticDome]"
            return self._safe_str(sanitized_text) if sanitized_text is not None else text
        except Exception as exc:
            await self._handle_failure("output sanitization", exc)
            return text

    async def _sanitize_result(
        self,
        *,
        raw_result: Any,
        session_id: str,
        agent_id: str,
        policy_context: Dict[str, Any],
        preserve_structured_output: bool,
    ) -> Any:
        result_text = self._serialize_for_review(raw_result)
        sanitized = await self.sanitize_output(
            session_id=session_id,
            agent_id=agent_id,
            text=result_text,
            policy_context=policy_context,
        )
        if preserve_structured_output and isinstance(raw_result, (dict, list, tuple)):
            if sanitized == result_text:
                return raw_result
            try:
                return json.loads(sanitized)
            except Exception:
                pass
        return sanitized

    def wrap_tool_handler(
        self,
        *,
        tool_name: str,
        handler: Callable[..., Any],
        text_builder: Optional[Callable[[Any, Dict[str, Any]], str]] = None,
        policy_context_builder: Optional[Callable[[Any, Dict[str, Any]], Dict[str, Any]]] = None,
        tool_platform: Optional[str] = None,
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
        tool_schema: Optional[Any] = None,
    ) -> Callable[..., Awaitable[Any]]:
        async def secured(ctx: Any, args_json_or_dict: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args_json_or_dict)
            agent_id = self._ctx_agent_id(ctx)
            session_id = self._ctx_session_id(ctx)
            source_agent_id = self._ctx_source_agent_id(ctx)
            text = text_builder(ctx, tool_args) if text_builder else f"[OpenAI Agents] {agent_id} intends to call {tool_name}"
            policy_context = policy_context_builder(ctx, tool_args) if policy_context_builder else {"sdk": "openai_agents", "agent_name": agent_id}
            decision = await self.authorize_direct_tool_call(
                session_id=session_id,
                agent_id=agent_id,
                source_agent_id=source_agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
                text=text,
                tool_platform=tool_platform,
                policy_context=policy_context,
                tool_schema=tool_schema,
            )
            sanitized_args = self._sanitized_args(decision)
            clean_args = self._mutate_args(args_json_or_dict, sanitized_args) if sanitized_args is not None else self._strip_private_args(tool_args)
            if inspect.iscoroutinefunction(handler):
                raw_result = await handler(ctx, clean_args, *a, **kw)
            else:
                raw_result = await asyncio.to_thread(handler, ctx, clean_args, *a, **kw)
            if not sanitize_output:
                return raw_result
            return await self._sanitize_result(
                raw_result=raw_result,
                session_id=session_id,
                agent_id=agent_id,
                preserve_structured_output=preserve_structured_output,
                policy_context={**policy_context, "request_purpose": "openai_agents_tool_output_review", "tool_name": tool_name},
            )
        return secured

    def wrap_delegated_tool_handler(
        self,
        *,
        tool_name: str,
        handler: Callable[..., Any],
        source_agent_id_getter: Optional[Callable[[Any, Dict[str, Any]], Optional[str]]] = None,
        decision_token_getter: Optional[Callable[[Any, Dict[str, Any]], Optional[str]]] = None,
        text_builder: Optional[Callable[[Any, Dict[str, Any]], str]] = None,
        policy_context_builder: Optional[Callable[[Any, Dict[str, Any]], Dict[str, Any]]] = None,
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
    ) -> Callable[..., Awaitable[Any]]:
        async def secured(ctx: Any, args_json_or_dict: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args_json_or_dict)
            clean_args = self._strip_private_args(tool_args)
            agent_id = self._ctx_agent_id(ctx)
            session_id = self._ctx_session_id(ctx)
            decision_token = decision_token_getter(ctx, clean_args) if decision_token_getter else None
            if not decision_token:
                decision_token = self._safe_str(tool_args.get("_AgenticDome_decision_token") or tool_args.get("_decision_token") or self._ctx_attr(ctx, "decision_token")) or None
            source_agent_id = source_agent_id_getter(ctx, clean_args) if source_agent_id_getter else None
            if not source_agent_id:
                source_agent_id = self._safe_str(tool_args.get("_AgenticDome_source_agent_id") or tool_args.get("_source_agent_id") or self._ctx_attr(ctx, "source_agent_id")) or None
            await self.verify_specialist_execution(
                session_id=session_id,
                specialist_agent_id=agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
                decision_token=decision_token,
                source_agent_id=source_agent_id,
            )
            if inspect.iscoroutinefunction(handler):
                raw_result = await handler(ctx, clean_args, *a, **kw)
            else:
                raw_result = await asyncio.to_thread(handler, ctx, clean_args, *a, **kw)
            if not sanitize_output:
                return raw_result
            policy_context = policy_context_builder(ctx, clean_args) if policy_context_builder else {"sdk": "openai_agents", "agent_name": agent_id}
            return await self._sanitize_result(
                raw_result=raw_result,
                session_id=session_id,
                agent_id=agent_id,
                preserve_structured_output=preserve_structured_output,
                policy_context={
                    **policy_context,
                    "request_purpose": "openai_agents_delegated_tool_output_review",
                    "tool_name": tool_name,
                    "execution_text": text_builder(ctx, clean_args) if text_builder else f"[OpenAI Agents] Specialist {agent_id} executes approved {tool_name}",
                },
            )
        return secured

    def secure_tool(
        self,
        *,
        tool_name: Optional[str] = None,
        tool_platform: Optional[str] = None,
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
        tool_schema: Optional[Any] = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_handler(
                tool_name=tool_name or getattr(handler, "__name__", "openai_agents_tool"),
                handler=handler,
                tool_platform=tool_platform,
                sanitize_output=sanitize_output,
                preserve_structured_output=preserve_structured_output,
                tool_schema=tool_schema,
            )
        return decorator

    def _extract_runner_result_text(self, result: Any) -> str:
        for attr in ("final_output", "output", "text", "content"):
            value = getattr(result, attr, None)
            if value is not None:
                return self._serialize_for_review(value)
        return self._serialize_for_review(result)


    async def sanitize_streaming_response(
        self,
        chunks: AsyncIterator[Any],
        *,
        session_id: str,
        agent_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[str]:
        tail = ""
        async for chunk in chunks:
            text = self._safe_str(chunk)
            review_text = (tail + text)[-max(1, self.config.streaming_buffer_chars):]
            sanitized = await self.sanitize_output(
                session_id=session_id,
                agent_id=agent_id,
                text=review_text,
                policy_context={**(policy_context or {}), "request_purpose": "openai_agents_streaming_output_review"},
            )
            if sanitized == "[OUTPUT BLOCKED BY AgenticDome]":
                yield sanitized
                return
            if len(sanitized) >= len(text) and sanitized.endswith(text):
                yield text
            else:
                yield await self.sanitize_output(
                    session_id=session_id,
                    agent_id=agent_id,
                    text=text,
                    policy_context={**(policy_context or {}), "request_purpose": "openai_agents_streaming_output_review"},
                )
            tail = review_text

    def create_input_guardrail(self) -> Callable[..., Awaitable[Any]]:
        async def guardrail(ctx: Any, agent: Any, input: Any, *args: Any, **kwargs: Any) -> Any:
            agent_id = self._safe_str(getattr(agent, "name", None) or getattr(agent, "agent_id", None)) or self._ctx_agent_id(ctx)
            session_id = self._ctx_session_id(ctx)
            await self.screen_input(session_id=session_id, agent_id=agent_id, text=self._serialize_for_review(input), policy_context={"guardrail": "agenticdome_input"})
            return None
        return guardrail

    def create_output_guardrail(self) -> Callable[..., Awaitable[Any]]:
        async def guardrail(ctx: Any, agent: Any, output: Any, *args: Any, **kwargs: Any) -> Any:
            agent_id = self._safe_str(getattr(agent, "name", None) or getattr(agent, "agent_id", None)) or self._ctx_agent_id(ctx)
            session_id = self._ctx_session_id(ctx)
            sanitized = await self.sanitize_output(session_id=session_id, agent_id=agent_id, text=self._serialize_for_review(output), policy_context={"guardrail": "agenticdome_output"})
            return sanitized
        return guardrail

    async def run_agent_stream_securely(
        self,
        *,
        runner: Any,
        agent: Any,
        input_text: str,
        session_id: str,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        **runner_kwargs: Any,
    ) -> AsyncIterator[str]:
        effective_agent_id = agent_id or self._safe_str(getattr(agent, "name", None)) or "openai_agent"
        await self.screen_input(session_id=session_id, agent_id=effective_agent_id, text=input_text, policy_context=policy_context)
        if hasattr(runner, "run_streamed") and callable(runner.run_streamed):
            maybe_stream = runner.run_streamed(agent, input=input_text, session_id=session_id, **runner_kwargs)
        elif hasattr(runner, "stream") and callable(runner.stream):
            maybe_stream = runner.stream(agent, input=input_text, session_id=session_id, **runner_kwargs)
        elif callable(runner):
            maybe_stream = runner(agent, input=input_text, session_id=session_id, **runner_kwargs)
        else:
            raise ValueError("runner must expose run_streamed(...), stream(...), or be callable.")
        stream = await maybe_stream if inspect.isawaitable(maybe_stream) else maybe_stream
        source = getattr(stream, "stream_events", None) or getattr(stream, "events", None) or stream
        async for chunk in self.sanitize_streaming_response(self._aiter_text(source), session_id=session_id, agent_id=effective_agent_id, policy_context=policy_context):
            yield chunk

    async def _aiter_text(self, stream: Any) -> AsyncIterator[str]:
        if hasattr(stream, "__aiter__"):
            async for item in stream:
                yield self._extract_runner_result_text(item)
            return
        for item in stream or []:
            yield self._extract_runner_result_text(item)

    async def run_agent_securely(
        self,
        *,
        runner: Any,
        agent: Any,
        input_text: str,
        session_id: str,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        **runner_kwargs: Any,
    ) -> Any:
        effective_agent_id = agent_id or self._safe_str(getattr(agent, "name", None)) or "openai_agent"
        await self.screen_input(
            session_id=session_id,
            agent_id=effective_agent_id,
            text=input_text,
            policy_context=policy_context,
        )
        if hasattr(runner, "run") and callable(runner.run):
            maybe_result = runner.run(agent, input=input_text, session_id=session_id, **runner_kwargs)
        elif callable(runner):
            maybe_result = runner(agent, input=input_text, session_id=session_id, **runner_kwargs)
        else:
            raise ValueError("runner must be a Runner instance with .run(...) or a callable.")
        result = await maybe_result if inspect.isawaitable(maybe_result) else maybe_result
        sanitized = await self.sanitize_output(
            session_id=session_id,
            agent_id=effective_agent_id,
            text=self._extract_runner_result_text(result),
            policy_context={**(policy_context or {}), "request_purpose": "openai_agents_final_user_output"},
        )
        for attr in ("final_output", "output", "text", "content"):
            try:
                if hasattr(result, attr):
                    setattr(result, attr, sanitized)
                    return result
            except Exception:
                pass
        return sanitized


__all__ = [
    "FirewallConfig",
    "load_config",
    "OpenAIAgentsFirewallError",
    "OpenAIAgentsFirewallDenied",
    "OpenAIAgentsFirewallConfigurationError",
    "ToolBlocked",
    "FirewallMisconfigured",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "AgenticDomeOpenAIAgentsFirewall",
]
