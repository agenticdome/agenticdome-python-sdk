from __future__ import annotations

import asyncio
import functools
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
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, AsyncIterator, Callable, Deque, Dict, Iterable, Optional, Tuple, TypeVar, Union

import anyio

try:
    from pydantic_ai import Agent, RunContext
    from pydantic_ai.models import ModelResponse
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "AgenticDome PydanticAI integration requires pydantic-ai. "
        "Install with: pip install 'agenticdome-python-sdk[pydanticai]'"
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


logger = logging.getLogger("agenticdome.pydanticai")
logger.setLevel(logging.INFO)

DepsT = TypeVar("DepsT")


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

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
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class FirewallConfig:
    api_base: str = field(
        default_factory=lambda: os.getenv(
            "AGENTICDOME_API_BASE",
            "",
        ).rstrip("/")
    )
    api_key: str = field(default_factory=lambda: os.getenv("AGENTICDOME_API_KEY", ""))
    tenant_id: str = field(default_factory=lambda: os.getenv("AGENTICDOME_TENANT_ID", ""))

    platform: str = field(default_factory=lambda: os.getenv("AGENTICDOME_PLATFORM", "pydanticai"))
    timeout_s: int = field(default_factory=lambda: _env_int("AGENTICDOME_TIMEOUT_S", 20))
    fail_closed: bool = field(default_factory=lambda: _env_bool("AGENTICDOME_FAIL_CLOSED", True))
    production_mode: bool = field(default_factory=lambda: _env_bool("AGENTICDOME_PRODUCTION_MODE", False))
    require_stable_session_id_in_prod: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_REQUIRE_STABLE_SESSION_ID_IN_PROD", True)
    )

    require_explicit_session_id: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False)
    )
    default_tool_platform: str = field(
        default_factory=lambda: os.getenv("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "python")
    )

    redact_pii: bool = field(default_factory=lambda: _env_bool("AGENTICDOME_REDACT_PII", True))
    redact_secrets: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_REDACT_SECRETS", True)
    )
    block_on_sensitive_output: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False)
    )

    enable_a2a_for_delegation: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_ENABLE_A2A_FOR_DELEGATION", True)
    )
    handoff_token_ttl_s: int = field(
        default_factory=lambda: _env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900)
    )

    redis_url: str = field(default_factory=lambda: os.getenv("AGENTICDOME_REDIS_URL", "").strip())
    redis_key_prefix: str = field(
        default_factory=lambda: os.getenv(
            "AGENTICDOME_REDIS_KEY_PREFIX",
            "AgenticDome:pydanticai:handoff",
        )
    )

    report_incidents: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_REPORT_INCIDENTS", True)
    )
    blocked_incident_severity: str = field(
        default_factory=lambda: os.getenv("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium")
    )

    max_input_chars: int = field(default_factory=lambda: _env_int("AGENTICDOME_PYDANTICAI_MAX_INPUT_CHARS", 50_000))
    max_output_chars: int = field(default_factory=lambda: _env_int("AGENTICDOME_PYDANTICAI_MAX_OUTPUT_CHARS", 100_000))
    max_tool_arg_chars: int = field(default_factory=lambda: _env_int("AGENTICDOME_PYDANTICAI_MAX_TOOL_ARG_CHARS", 20_000))
    rate_limit_per_minute: int = field(default_factory=lambda: _env_int("AGENTICDOME_PYDANTICAI_RATE_LIMIT_PER_MINUTE", 0))
    retry_attempts: int = field(default_factory=lambda: _env_int("AGENTICDOME_PYDANTICAI_RETRY_ATTEMPTS", 2))
    retry_backoff_s: float = field(default_factory=lambda: float(os.getenv("AGENTICDOME_PYDANTICAI_RETRY_BACKOFF_S", "0.25") or "0.25"))
    circuit_breaker_failures: int = field(default_factory=lambda: _env_int("AGENTICDOME_PYDANTICAI_CIRCUIT_BREAKER_FAILURES", 5))
    circuit_breaker_reset_s: int = field(default_factory=lambda: _env_int("AGENTICDOME_PYDANTICAI_CIRCUIT_BREAKER_RESET_S", 60))
    audit_logging: bool = field(default_factory=lambda: _env_bool("AGENTICDOME_PYDANTICAI_AUDIT_LOGGING", True))
    otel_enabled: bool = field(default_factory=lambda: _env_bool("AGENTICDOME_PYDANTICAI_OTEL_ENABLED", True))
    emergency_block_tools: str = field(default_factory=lambda: os.getenv("AGENTICDOME_PYDANTICAI_EMERGENCY_BLOCK_TOOLS", ""))
    emergency_block_agents: str = field(default_factory=lambda: os.getenv("AGENTICDOME_PYDANTICAI_EMERGENCY_BLOCK_AGENTS", ""))
    token_hmac_secret: str = field(default_factory=lambda: os.getenv("AGENTICDOME_TOKEN_HMAC_SECRET", ""))


class PydanticAIFirewallError(RuntimeError):
    """Base exception for AgenticDome PydanticAI firewall errors."""


class PydanticAIFirewallDenied(PydanticAIFirewallError):
    """Raised when AgenticDome explicitly blocks execution."""


class PydanticAIFirewallConfigurationError(PydanticAIFirewallError):
    """Raised when required PydanticAI firewall configuration is missing."""


@dataclass(frozen=True)
class DecisionTokenRecord:
    decision_token: str
    source_agent_id: str
    created_at: float
    token_hmac: str = ""


# ------------------------------------------------------------------
# Token Store
# ------------------------------------------------------------------

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
        if record is not None:
            self.delete(
                session_id=session_id,
                target_agent_id=target_agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
            )
        return record


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _tool_fingerprint(tool_name: str, tool_args: Dict[str, Any]) -> str:
    payload = {
        "tool_name": tool_name or "",
        "tool_args": tool_args or {},
    }
    return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()


class InMemoryDecisionTokenStore(DecisionTokenStore):
    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id
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
        return f"{self._tenant_id}:{session_id}:{target_agent_id}:{fp}"

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
    def __init__(self, url: str, prefix: str, tenant_id: str) -> None:
        import redis

        self.r = redis.Redis.from_url(url, decode_responses=True)
        self.prefix = f"{prefix}:{tenant_id}"

    def _key(
        self,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        fp = _tool_fingerprint(tool_name, tool_args)
        return f"{self.prefix}:{session_id}:{target_agent_id}:{fp}"

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


def _build_token_store(config: FirewallConfig) -> DecisionTokenStore:
    if config.redis_url:
        try:
            return RedisDecisionTokenStore(
                config.redis_url,
                config.redis_key_prefix,
                config.tenant_id,
            )
        except ImportError:
            logger.warning(
                "Redis package missing. Install with: "
                "pip install 'agenticdome-python-sdk[redis]'. "
                "Using in-memory token cache."
            )
        except Exception as exc:
            logger.warning(
                "Redis token store unavailable: %s. Using in-memory token cache.",
                exc,
            )

    return InMemoryDecisionTokenStore(config.tenant_id)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _safe_setattr(obj: Any, name: str, value: Any) -> None:
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


def _is_handoff_tool(tool_name: str) -> bool:
    lower = tool_name.lower()
    return any(marker in lower for marker in ("delegate", "handoff", "route", "transfer"))


def _target_agent_id(kwargs: Dict[str, Any]) -> str:
    return str(
        kwargs.get("target_agent_id")
        or kwargs.get("coworker")
        or kwargs.get("agent")
        or kwargs.get("specialist_agent_id")
        or "specialist"
    )


def _target_tool_name(current_tool_name: str, kwargs: Dict[str, Any]) -> str:
    return str(
        kwargs.get("target_tool_name")
        or kwargs.get("tool_name")
        or kwargs.get("skill_name")
        or current_tool_name
    )


def _target_tool_args(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    raw = (
        kwargs.get("target_tool_args")
        or kwargs.get("skill_args")
        or kwargs.get("arguments")
        or {}
    )

    if isinstance(raw, dict):
        return dict(raw)

    return {"_raw_input": str(raw)}


def _strip_private_args(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in kwargs.items()
        if not str(key).startswith("_AgenticDome_")
        and not str(key).startswith("_decision_")
        and str(key) not in {"decision_token", "source_agent_id"}
    }


def _csv_set(value: str) -> set:
    return {item.strip() for item in (value or "").split(",") if item.strip()}


def _structured_text(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return str(value)


def _extract_identity(ctx: Any) -> Dict[str, Any]:
    deps = _safe_getattr(ctx, "deps")
    identity = _safe_getattr(ctx, "identity") or _safe_getattr(deps, "identity")
    out: Dict[str, Any] = {}
    for key in (
        "tenant_id", "user_id", "principal_id", "caller_id", "entra_tenant_id",
        "oid", "object_id", "appid", "app_id", "client_id", "upn", "username",
        "email", "roles", "scp", "azp", "data_classification", "sensitivity_label",
    ):
        value = _safe_getattr(ctx, key, None) or _safe_getattr(deps, key, None)
        if value is None and identity is not None:
            value = _safe_getattr(identity, key, None)
        if value is not None:
            out[key] = value
    return out


def _run_async_from_sync(async_fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    async def _call() -> Any:
        return await async_fn(*args, **kwargs)

    try:
        return anyio.from_thread.run(_call)
    except RuntimeError:
        return anyio.run(_call)


# ------------------------------------------------------------------
# PydanticAI Firewall
# ------------------------------------------------------------------

class CyberSecFirewall:
    """
    AgenticDome Security Firewall for PydanticAI.

    Provides:
    - Prompt ingress screening where supported by the PydanticAI runtime
    - Tool execution authorization
    - Manager-to-specialist delegation token generation
    - Specialist decision-token verification
    - Output DLP sanitization
    """

    def __init__(self, config: Optional[FirewallConfig] = None, client: Optional[AgentGuardClient] = None) -> None:
        self.config = config or FirewallConfig()

        configured = bool(self.config.api_base and self.config.api_key and self.config.tenant_id)
        if not configured:
            raise PydanticAIFirewallConfigurationError(
                "AgenticDome PydanticAI firewall requires AGENTICDOME_API_BASE, "
                "AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
            )

        if client is not None:
            self.client = client
        else:
            self.client = AgentGuardClient(
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

    async def _to_thread(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))

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

    def _client_call(self, method_names: Tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
        if self.client is None:
            return None
        if not self._circuit_allows_call():
            raise PydanticAIFirewallDenied("AgenticDome PydanticAI circuit breaker is open.")

        last_error: Optional[Exception] = None
        for attempt in range(max(1, self.config.retry_attempts)):
            last_type_error: Optional[TypeError] = None
            try:
                for method_name in method_names:
                    method = getattr(self.client, method_name, None)
                    if method is None:
                        continue
                    try:
                        result = method(*args, **kwargs)
                        if inspect.isawaitable(result):
                            raise TypeError("async client methods must be called from async wrapper")
                        self._record_client_success()
                        return result
                    except TypeError as exc:
                        last_type_error = exc
                        continue
                if last_type_error:
                    raise last_type_error
                raise AttributeError(f"AgenticDome client does not implement any of: {', '.join(method_names)}")
            except Exception as exc:
                last_error = exc
                self._record_client_failure()
                if attempt + 1 >= max(1, self.config.retry_attempts):
                    break
                time.sleep(max(0.0, self.config.retry_backoff_s) * (2 ** attempt))
        assert last_error is not None
        raise last_error

    def _extract_payload(self, response: Any) -> Dict[str, Any]:
        if isinstance(response, dict):
            result = response.get("result")
            if isinstance(result, dict):
                return result
            return response
        return {}

    def _extract_verdict(self, response: Any) -> str:
        payload = self._extract_payload(response)
        return str(payload.get("verdict") or payload.get("decision") or "ALLOWED").upper()

    def _reason(self, response: Any) -> str:
        payload = self._extract_payload(response)
        return str(payload.get("reason") or payload.get("message") or response)

    def _decision_token(self, response: Any) -> Optional[str]:
        payload = self._extract_payload(response)
        token = payload.get("decision_token") or payload.get("token")
        return str(token) if token else None

    def _sanitized_tool_args(self, response: Any) -> Optional[Dict[str, Any]]:
        payload = self._extract_payload(response)
        for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
            value = payload.get(key)
            if isinstance(value, dict):
                return _strip_private_args(value)
        return None

    def _token_hmac(self, token: str) -> str:
        if not self.config.token_hmac_secret or not token:
            return ""
        digest = hmac.new(self.config.token_hmac_secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _verify_record_hmac(self, record: DecisionTokenRecord) -> bool:
        if not self.config.token_hmac_secret:
            return True
        return bool(record.token_hmac) and hmac.compare_digest(record.token_hmac, self._token_hmac(record.decision_token))

    def _bounded_text(self, text: str, *, limit: int, label: str) -> str:
        if limit > 0 and len(text) > limit:
            return text[:limit] + f"\n[TRUNCATED BY AgenticDome {label}]"
        return text

    def _enforce_tool_arg_size(self, *, tool_name: str, tool_args: Dict[str, Any]) -> None:
        if self.config.max_tool_arg_chars <= 0:
            return
        if len(_structured_text(tool_args or {})) > self.config.max_tool_arg_chars:
            raise PydanticAIFirewallDenied(f"PydanticAI tool arguments exceed max size for {tool_name}.")

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
                raise PydanticAIFirewallDenied(f"PydanticAI rate limit exceeded for {purpose}.")
            events.append(now)

    def _emergency_policy_check(self, *, agent_id: str, tool_name: Optional[str] = None) -> None:
        if agent_id in _csv_set(self.config.emergency_block_agents):
            raise PydanticAIFirewallDenied(f"Emergency local policy blocked PydanticAI agent: {agent_id}")
        if tool_name and tool_name in _csv_set(self.config.emergency_block_tools):
            raise PydanticAIFirewallDenied(f"Emergency local policy blocked PydanticAI tool: {tool_name}")

    def _policy_context(self, ctx: Any, *, agent_id: str, session_id: str, purpose: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        policy = {
            "request_id": str(uuid.uuid4()),
            "request_ts_ms": int(time.time() * 1000),
            "source_agent_id": agent_id,
            "session_id": session_id,
            "request_purpose": purpose,
            "platform": self.config.platform,
        }
        policy.update(_extract_identity(ctx))
        if extra:
            policy.update(extra)
        return policy

    def _audit(self, event: str, *, agent_id: str, session_id: str, details: Optional[Dict[str, Any]] = None) -> None:
        if not self.config.audit_logging:
            return
        payload = {"event": event, "agent_id": agent_id, "session_id": session_id, "platform": self.config.platform}
        if details:
            payload.update(details)
        logger.info("AgenticDome PydanticAI audit: %s", json.dumps(payload, sort_keys=True, default=str))

    def _otel_event(self, name: str, attributes: Dict[str, Any]) -> None:
        if not self.config.otel_enabled:
            return
        try:
            from opentelemetry import trace
            span = trace.get_current_span()
            if span and span.is_recording():
                span.add_event(name, attributes={k: str(v) for k, v in attributes.items()})
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
                raise PydanticAIFirewallDenied(f"PydanticAI tool {tool_name} missing required args: {', '.join(missing)}")
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
                    raise PydanticAIFirewallDenied(f"PydanticAI tool {tool_name} arg {key} failed schema validation.")

    def _agent_name(self, ctx: RunContext[Any], fallback: str = "unnamed_agent") -> str:
        agent = _safe_getattr(ctx, "agent")
        value = (
            _safe_getattr(agent, "name")
            or _safe_getattr(ctx, "agent_name")
            or _safe_getattr(_safe_getattr(ctx, "deps"), "agent_id")
        )
        return str(value) if value else fallback

    def _session_id(self, ctx: RunContext[Any]) -> str:
        deps = _safe_getattr(ctx, "deps")

        for attr in ("run_id", "trace_id", "session_id", "task_id"):
            value = _safe_getattr(ctx, attr) or _safe_getattr(deps, attr)
            if value:
                return str(value)

        if self.config.require_explicit_session_id or (
            self.config.production_mode and self.config.require_stable_session_id_in_prod
        ):
            raise PydanticAIFirewallDenied(
                "Strict mode error: missing stable session_id, run_id, trace_id, or task_id."
            )

        return f"pydanticai-session-{id(ctx)}"

    def _report_incident(
        self,
        *,
        agent_id: str,
        incident_type: str,
        severity: Optional[str] = None,
        details: str = "",
    ) -> None:
        if self.client is None or not self.config.report_incidents:
            return

        try:
            self._client_call(
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
            logger.debug("AgenticDome incident reporting failed: %s", exc)

    def _handle_error(self, stage: str, exc: Exception, agent_id: str = "unknown") -> None:
        logger.error("AgenticDome PydanticAI %s error: %s", stage, exc)

        self._report_incident(
            agent_id=agent_id,
            incident_type=f"pydanticai_{stage}_error",
            severity=self.config.blocked_incident_severity,
            details=str(exc),
        )

        if self.config.fail_closed:
            if isinstance(exc, PydanticAIFirewallDenied):
                raise exc
            raise PydanticAIFirewallDenied(f"AgenticDome security check failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Agent lifecycle hooks
    # ------------------------------------------------------------------

    def attach_to_agent(self, agent: Agent[DepsT, Any]) -> None:
        """
        Attach prompt ingress and response egress hooks to a PydanticAI Agent
        when the installed PydanticAI runtime exposes compatible hook decorators.

        PydanticAI hook APIs may vary by version. If lifecycle decorators are not
        available, use secure_tool() around tools for tool perimeter security.
        """

        before_runner_init = getattr(agent, "before_runner_init", None)
        after_runner_end = getattr(agent, "after_runner_end", None)

        if callable(before_runner_init):
            @before_runner_init
            def _ingress_prompt_shield(ctx: RunContext[DepsT], prompt: str) -> str:
                if self.client is None or not str(prompt or "").strip():
                    return prompt

                agent_id = getattr(agent, "name", None) or self._agent_name(ctx)

                try:
                    response = self._client_call(
                        ("guardrail_validate", "guardrailValidate"),
                        text=self._bounded_text(str(prompt), limit=self.config.max_input_chars, label="PYDANTICAI INPUT"),
                        agent_id=agent_id,
                        platform=self.config.platform,
                        source_platform=self.config.platform,
                        direction="input",
                        session_id=self._session_id(ctx),
                        policy_context=self._policy_context(
                            ctx,
                            agent_id=agent_id,
                            session_id=self._session_id(ctx),
                            purpose="pydanticai_prompt_input",
                        ),
                    )

                    if self._extract_verdict(response) == "BLOCKED":
                        raise PydanticAIFirewallDenied(
                            f"AgenticDome prompt shield blocked input: {self._reason(response)}"
                        )
                except Exception as exc:
                    self._handle_error("before_runner_init", exc, agent_id)

                return prompt

        else:
            logger.info(
                "PydanticAI agent does not expose before_runner_init. "
                "Prompt lifecycle hook not attached."
            )

        if callable(after_runner_end):
            @after_runner_end
            def _egress_dlp_shield(
                ctx: RunContext[DepsT],
                response: ModelResponse,
            ) -> ModelResponse:
                if self.client is None:
                    return response

                agent_id = getattr(agent, "name", None) or self._agent_name(ctx)

                try:
                    messages = getattr(response, "messages", None)
                    if not messages:
                        return response

                    last_msg = messages[-1]
                    parts = getattr(last_msg, "parts", None)
                    if not parts:
                        return response

                    for part in parts:
                        content = getattr(part, "content", None)
                        if not isinstance(content, str):
                            continue

                        scan = self._client_call(
                            ("mesh_validate", "meshValidate"),
                            text=self._bounded_text(content, limit=self.config.max_output_chars, label="PYDANTICAI OUTPUT"),
                            agent_id=agent_id,
                            direction="output",
                            session_id=self._session_id(ctx),
                            platform=self.config.platform,
                            redact_pii=self.config.redact_pii,
                            redact_secrets=self.config.redact_secrets,
                            block_on_sensitive_output=self.config.block_on_sensitive_output,
                            policy_context=self._policy_context(
                                ctx,
                                agent_id=agent_id,
                                session_id=self._session_id(ctx),
                                purpose="pydanticai_output_review",
                                extra={
                                    "redact_pii": self.config.redact_pii,
                                    "redact_secrets": self.config.redact_secrets,
                                    "block_on_sensitive_output": self.config.block_on_sensitive_output,
                                },
                            ),
                        )

                        payload = self._extract_payload(scan)
                        verdict = self._extract_verdict(scan)

                        if verdict == "BLOCKED":
                            part.content = (
                                "[EGRESS PAYLOAD TERMINATED BY AGENTICDOME DLP SECURITY MESH]"
                            )
                            continue

                        sanitized = (
                            payload.get("sanitized_text")
                            or payload.get("text")
                            or payload.get("output")
                        )

                        if sanitized is not None:
                            part.content = str(sanitized)

                except Exception as exc:
                    logger.error("AgenticDome PydanticAI after_runner_end error: %s", exc)
                    if self.config.fail_closed:
                        try:
                            messages = getattr(response, "messages", None)
                            if messages and getattr(messages[-1], "parts", None):
                                for part in messages[-1].parts:
                                    if hasattr(part, "content"):
                                        part.content = (
                                            "[FATAL ERROR: AGENTICDOME SECURITY CHECK FAULTED]"
                                        )
                        except Exception:
                            pass

                return response

        else:
            logger.info(
                "PydanticAI agent does not expose after_runner_end. "
                "Output lifecycle hook not attached."
            )

    # ------------------------------------------------------------------
    # Tool perimeter
    # ------------------------------------------------------------------

    def secure_tool(
        self,
        tool_func: Optional[Callable[..., Any]] = None,
        *,
        tool_name: Optional[str] = None,
        tool_platform: Optional[str] = None,
        tool_schema: Optional[Any] = None,
        sanitize_output: bool = True,
    ) -> Callable[..., Any]:
        """
        Decorator that protects a PydanticAI tool.

        Supports both `@firewall.secure_tool` and
        `@firewall.secure_tool(tool_name=..., tool_schema=...)`.
        """

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            effective_name = tool_name or getattr(fn, "__name__", "pydanticai_tool")

            if asyncio.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def _async_wrapper(ctx: RunContext[Any], *args: Any, **kwargs: Any) -> Any:
                    clean_kwargs, _ = await self._pre_execute_tool_check(
                        ctx,
                        effective_name,
                        dict(kwargs),
                        tool_platform=tool_platform,
                        tool_schema=tool_schema,
                    )
                    result = await fn(ctx, *args, **clean_kwargs)
                    if not sanitize_output:
                        return result
                    return await self._post_execute_tool_sanitize(ctx, result)

                return _async_wrapper

            @functools.wraps(fn)
            def _sync_wrapper(ctx: RunContext[Any], *args: Any, **kwargs: Any) -> Any:
                clean_kwargs, _ = _run_async_from_sync(
                    self._pre_execute_tool_check,
                    ctx,
                    effective_name,
                    dict(kwargs),
                    tool_platform=tool_platform,
                    tool_schema=tool_schema,
                )
                result = fn(ctx, *args, **clean_kwargs)
                if not sanitize_output:
                    return result
                return _run_async_from_sync(self._post_execute_tool_sanitize, ctx, result)

            return _sync_wrapper

        if tool_func is None:
            return decorate
        return decorate(tool_func)

    async def _pre_execute_tool_check(
        self,
        ctx: RunContext[Any],
        name: str,
        kwargs: Dict[str, Any],
        *,
        tool_platform: Optional[str] = None,
        tool_schema: Optional[Any] = None,
    ) -> Tuple[Dict[str, Any], bool]:
        session_id = self._session_id(ctx)
        agent_id = self._agent_name(ctx)
        self._emergency_policy_check(agent_id=agent_id, tool_name=name)

        if self.client is None:
            clean = _strip_private_args(kwargs)
            self._enforce_tool_arg_size(tool_name=name, tool_args=clean)
            self._validate_tool_schema(tool_name=name, tool_args=clean, schema=tool_schema)
            return clean, False

        token = kwargs.pop("_AgenticDome_decision_token", None) or kwargs.pop("_decision_token", None)
        source_agent_id = kwargs.pop("_AgenticDome_source_agent_id", None) or kwargs.pop(
            "_source_agent_id",
            None,
        )

        clean_kwargs = _strip_private_args(kwargs)
        self._enforce_tool_arg_size(tool_name=name, tool_args=clean_kwargs)
        self._validate_tool_schema(tool_name=name, tool_args=clean_kwargs, schema=tool_schema)
        self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose=f"tool:{name}")

        # Case A: Specialist execution verifies delegated decision token.
        stored_record: Optional[DecisionTokenRecord] = None
        if not token:
            stored_record = self.token_store.consume(
                session_id=session_id,
                target_agent_id=agent_id,
                tool_name=name,
                tool_args=clean_kwargs,
            )
            if stored_record:
                if not self._verify_record_hmac(stored_record):
                    raise PydanticAIFirewallDenied("Stored AgenticDome PydanticAI decision token failed local HMAC verification.")
                token = stored_record.decision_token
                source_agent_id = stored_record.source_agent_id

        if token and source_agent_id:
            response = await self._to_thread(
                self._client_call,
                ("a2a_verify_decision_token_rpc", "a2aVerifyDecisionTokenRpc", "a2a_verify_decision_token"),
                str(token),
                tool_name=name,
                tool_args=clean_kwargs,
                agent_id=agent_id,
                source_agent_id=str(source_agent_id),
                platform=self.config.platform,
                require_allowed=True,
            )

            payload = self._extract_payload(response)

            if payload and payload.get("valid") is False:
                raise PydanticAIFirewallDenied(
                    f"AgenticDome rejected handoff token: {self._reason(response)}"
                )
            self._audit("pydanticai_delegation_verified", agent_id=agent_id, session_id=session_id, details={"tool_name": name, "source_agent_id": source_agent_id})
            return clean_kwargs, True

        # Case B: Manager handoff tool authorizes delegation and injects token.
        if self.config.enable_a2a_for_delegation and _is_handoff_tool(name):
            target_agent_id = _target_agent_id(clean_kwargs)
            target_tool_name = _target_tool_name(name, clean_kwargs)
            target_args = _strip_private_args(_target_tool_args(clean_kwargs))
            stored_target_args = dict(target_args)

            response = await self._to_thread(
                self._client_call,
                ("a2a_authorize_tool", "a2aAuthorizeTool"),
                text=f"PydanticAI manager {agent_id} delegating {target_tool_name} to {target_agent_id}",
                agent_id=target_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform=str(tool_platform or clean_kwargs.get("tool_platform") or self.config.default_tool_platform),
                tool_name=target_tool_name,
                tool_args=dict(target_args),
                session_id=session_id,
                direction="outbound",
                source_agent_id=agent_id,
                policy_context=self._policy_context(
                    ctx,
                    agent_id=agent_id,
                    session_id=session_id,
                    purpose="pydanticai_delegated_task",
                    extra={"delegation_chain": [agent_id, target_agent_id], "target_agent_id": target_agent_id},
                ),
            )

            if self._extract_verdict(response) == "BLOCKED":
                raise PydanticAIFirewallDenied(
                    f"AgenticDome blocked PydanticAI delegation: {self._reason(response)}"
                )

            decision_token = self._decision_token(response)

            if decision_token:
                clean_kwargs["_AgenticDome_decision_token"] = decision_token
                clean_kwargs["_AgenticDome_source_agent_id"] = agent_id

                target_args["_AgenticDome_decision_token"] = decision_token
                target_args["_AgenticDome_source_agent_id"] = agent_id

                if "target_tool_args" in clean_kwargs or "skill_args" not in clean_kwargs:
                    clean_kwargs["target_tool_args"] = target_args
                else:
                    clean_kwargs["skill_args"] = target_args

                self.token_store.put(
                    session_id=session_id,
                    target_agent_id=target_agent_id,
                    tool_name=target_tool_name,
                    tool_args=stored_target_args,
                    record=DecisionTokenRecord(
                        decision_token=decision_token,
                        source_agent_id=agent_id,
                        created_at=time.time(),
                        token_hmac=self._token_hmac(decision_token),
                    ),
                    ttl_s=self.config.handoff_token_ttl_s,
                )

            return clean_kwargs, False

        # Case C: Direct tool authorization.
        response = await self._to_thread(
            self._client_call,
            ("guardrail_validate", "guardrailValidate"),
            text=f"PydanticAI tool execution: {name}",
            agent_id=agent_id,
            platform=self.config.platform,
            source_platform=self.config.platform,
            tool_platform=str(tool_platform or clean_kwargs.get("tool_platform") or self.config.default_tool_platform),
            tool_name=name,
            tool_args=clean_kwargs,
            direction="outbound",
            session_id=session_id,
            policy_context=self._policy_context(
                ctx,
                agent_id=agent_id,
                session_id=session_id,
                purpose="pydanticai_tool_execution",
                extra={"tool_name": name},
            ),
        )

        if self._extract_verdict(response) == "BLOCKED":
            raise PydanticAIFirewallDenied(
                f"AgenticDome blocked tool execution '{name}': {self._reason(response)}"
            )

        execution_kwargs = self._sanitized_tool_args(response) or clean_kwargs
        self._validate_tool_schema(tool_name=name, tool_args=execution_kwargs, schema=tool_schema)
        self._audit("pydanticai_tool_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": name})
        self._otel_event("agenticdome.pydanticai.tool_allowed", {"agent_id": agent_id, "session_id": session_id, "tool_name": name})
        return execution_kwargs, False

    async def sanitize_text(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        ctx: Optional[Any] = None,
        purpose: str = "pydanticai_output_review",
    ) -> str:
        if self.client is None:
            return text
        self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="output")
        bounded_text = self._bounded_text(text, limit=self.config.max_output_chars, label="PYDANTICAI OUTPUT")
        response = await self._to_thread(
            self._client_call,
            ("mesh_validate", "meshValidate"),
            text=bounded_text,
            agent_id=agent_id,
            direction="output",
            session_id=session_id,
            platform=self.config.platform,
            redact_pii=self.config.redact_pii,
            redact_secrets=self.config.redact_secrets,
            block_on_sensitive_output=self.config.block_on_sensitive_output,
            policy_context=self._policy_context(
                ctx,
                agent_id=agent_id,
                session_id=session_id,
                purpose=purpose,
                extra={
                    "redact_pii": self.config.redact_pii,
                    "redact_secrets": self.config.redact_secrets,
                    "block_on_sensitive_output": self.config.block_on_sensitive_output,
                },
            ) if ctx is not None else {
                "source_agent_id": agent_id,
                "session_id": session_id,
                "request_purpose": purpose,
                "platform": self.config.platform,
            },
        )
        payload = self._extract_payload(response)
        verdict = self._extract_verdict(response)
        if verdict == "BLOCKED":
            return "[BLOCKED BY AGENTICDOME ACTION LAYER DLP]"
        sanitized = payload.get("sanitized_text") or payload.get("text") or payload.get("output")
        return str(sanitized) if sanitized is not None else bounded_text

    def _preserve_structured_output(self, original: Any, sanitized: str, original_text: str) -> Any:
        if sanitized == original_text:
            return original
        if isinstance(original, (dict, list, tuple)):
            try:
                parsed = json.loads(sanitized)
                if isinstance(parsed, (dict, list)):
                    return parsed
            except Exception:
                pass
        return sanitized

    async def _post_execute_tool_sanitize(self, ctx: RunContext[Any], result: Any) -> Any:
        if self.client is None:
            return result

        agent_id = self._agent_name(ctx)
        session_id = self._session_id(ctx)
        raw_text = _structured_text(result)
        sanitized = await self.sanitize_text(
            text=raw_text,
            agent_id=agent_id,
            session_id=session_id,
            ctx=ctx,
            purpose="pydanticai_tool_output_review",
        )
        if sanitized == "[BLOCKED BY AGENTICDOME ACTION LAYER DLP]":
            return sanitized
        if isinstance(result, str):
            return sanitized
        return self._preserve_structured_output(result, sanitized, raw_text)

    async def sanitize_streaming_response(
        self,
        *,
        chunks: Any,
        agent_id: str,
        session_id: str,
        ctx: Optional[Any] = None,
    ) -> AsyncIterator[Any]:
        if hasattr(chunks, "__aiter__"):
            async for chunk in chunks:
                yield await self._sanitize_stream_chunk(chunk, agent_id=agent_id, session_id=session_id, ctx=ctx)
            return
        if isinstance(chunks, Iterable) and not isinstance(chunks, (str, bytes, dict)):
            for chunk in chunks:
                yield await self._sanitize_stream_chunk(chunk, agent_id=agent_id, session_id=session_id, ctx=ctx)
            return
        yield await self._sanitize_stream_chunk(chunks, agent_id=agent_id, session_id=session_id, ctx=ctx)

    async def _sanitize_stream_chunk(self, chunk: Any, *, agent_id: str, session_id: str, ctx: Optional[Any] = None) -> Any:
        if isinstance(chunk, str):
            return await self.sanitize_text(text=chunk, agent_id=agent_id, session_id=session_id, ctx=ctx, purpose="pydanticai_stream_output_review")
        if isinstance(chunk, dict):
            raw = _structured_text(chunk)
            sanitized = await self.sanitize_text(text=raw, agent_id=agent_id, session_id=session_id, ctx=ctx, purpose="pydanticai_stream_output_review")
            return self._preserve_structured_output(chunk, sanitized, raw)
        text = str(chunk)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, ctx=ctx, purpose="pydanticai_stream_output_review")
        for attr in ("text", "content", "output", "message"):
            if hasattr(chunk, attr):
                try:
                    setattr(chunk, attr, sanitized)
                    return chunk
                except Exception:
                    pass
        return sanitized

    def create_hooks(self) -> Any:
        """Create a native PydanticAI Hooks capability when pydantic_ai supports it."""
        try:
            from pydantic_ai.capabilities import Hooks
        except Exception as exc:
            raise PydanticAIFirewallError("Installed pydantic_ai does not expose capabilities.Hooks") from exc

        hooks = Hooks(id="agenticdome-security", description="AgenticDome security lifecycle enforcement")

        @hooks.on.before_run
        async def _before_run(ctx: Any) -> Any:
            agent_id = self._agent_name(ctx)
            session_id = self._session_id(ctx)
            self._emergency_policy_check(agent_id=agent_id)
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="run")
            self._audit("pydanticai_run_started", agent_id=agent_id, session_id=session_id)
            return ctx

        @hooks.on.before_tool_execute
        async def _before_tool_execute(ctx: Any, *, call: Any, tool_def: Any, args: Dict[str, Any]) -> Dict[str, Any]:
            tool_name = str(getattr(call, "tool_name", None) or getattr(tool_def, "name", None) or "pydanticai_tool")
            clean_args, _ = await self._pre_execute_tool_check(ctx, tool_name, dict(args or {}))
            return clean_args

        @hooks.on.after_tool_execute
        async def _after_tool_execute(ctx: Any, *, call: Any, tool_def: Any, args: Dict[str, Any], result: Any) -> Any:
            return await self._post_execute_tool_sanitize(ctx, result)

        @hooks.on.after_output_process
        async def _after_output_process(ctx: Any, output: Any, **_: Any) -> Any:
            return await self._post_execute_tool_sanitize(ctx, output)

        @hooks.on.event
        async def _event(ctx: Any, event: Any) -> Any:
            agent_id = self._agent_name(ctx)
            session_id = self._session_id(ctx)
            for attr in ("text", "content", "output"):
                value = getattr(event, attr, None)
                if isinstance(value, str):
                    setattr(event, attr, await self.sanitize_text(text=value, agent_id=agent_id, session_id=session_id, ctx=ctx, purpose="pydanticai_event_output_review"))
            return event

        return hooks

    def install_native_hooks(self, agent: Any) -> Any:
        hooks = self.create_hooks()
        capabilities = getattr(agent, "capabilities", None)
        if isinstance(capabilities, list):
            capabilities.append(hooks)
            return agent
        existing = getattr(agent, "_capabilities", None)
        if isinstance(existing, list):
            existing.append(hooks)
            return agent
        setattr(agent, "agenticdome_hooks", hooks)
        logger.info("Attached AgenticDome hooks to agenticdome_hooks; pass this Hooks object in Agent(..., capabilities=[...]) if your Agent is immutable.")
        return agent


__all__ = [
    "FirewallConfig",
    "PydanticAIFirewallError",
    "PydanticAIFirewallDenied",
    "PydanticAIFirewallConfigurationError",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "CyberSecFirewall",
]
