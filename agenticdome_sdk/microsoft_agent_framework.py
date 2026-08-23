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


logger = logging.getLogger("agenticdome.microsoft_agent_framework")
logger.setLevel(logging.INFO)

AsyncHandler = Callable[..., Awaitable[Any]]
SyncHandler = Callable[..., Any]


# ============================================================================
# AgenticDome x Microsoft Agent Framework
#
# Runtime firewall for:
#   - inbound prompt screening
#   - direct tool authorization
#   - manager -> specialist delegation authorization
#   - specialist-side decision token verification
#   - tool / final output sanitization via Mesh
#   - optional Microsoft Copilot / AI Foundry threat helper calls
# ============================================================================


def _env(name: str, default: str = "") -> str:
    """
    Supports both modern AGENTICDOME_* env vars and legacy agenticdome_* vars.
    """
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

    platform: str = "microsoft_agent_framework_v1"
    default_tool_platform: str = "microsoft_agent_framework_v1"

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
    redis_key_prefix: str = "AgenticDome:microsoft_agent_framework:handoff"

    report_incidents: bool = True
    blocked_incident_severity: str = "medium"

    enable_copilot_threat_api: bool = False
    copilot_api_version: str = "2025-09-01"
    enforce_copilot_threat_api: bool = False

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
    token_hmac_secret: str = ""


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE", "").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        platform=_env("AGENTICDOME_PLATFORM", "microsoft_agent_framework_v1"),
        default_tool_platform=_env(
            "AGENTICDOME_DEFAULT_TOOL_PLATFORM",
            "microsoft_agent_framework_v1",
        ),
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
        redis_key_prefix=_env(
            "AGENTICDOME_REDIS_KEY_PREFIX",
            "AgenticDome:microsoft_agent_framework:handoff",
        ),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env(
            "AGENTICDOME_BLOCKED_INCIDENT_SEVERITY",
            "medium",
        ),
        enable_copilot_threat_api=_env_bool("AGENTICDOME_ENABLE_COPILOT_THREAT_API", False),
        copilot_api_version=_env("AGENTICDOME_COPILOT_API_VERSION", "2025-09-01"),
        enforce_copilot_threat_api=_env_bool("AGENTICDOME_ENFORCE_COPILOT_THREAT_API", False),
        max_input_chars=_env_int("AGENTICDOME_MSAF_MAX_INPUT_CHARS", 50_000),
        max_output_chars=_env_int("AGENTICDOME_MSAF_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_MSAF_MAX_TOOL_ARG_CHARS", 20_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_MSAF_RATE_LIMIT_PER_MINUTE", 0),
        retry_attempts=_env_int("AGENTICDOME_MSAF_RETRY_ATTEMPTS", 2),
        retry_backoff_s=float(_env("AGENTICDOME_MSAF_RETRY_BACKOFF_S", "0.25") or "0.25"),
        circuit_breaker_failures=_env_int("AGENTICDOME_MSAF_CIRCUIT_BREAKER_FAILURES", 5),
        circuit_breaker_reset_s=_env_int("AGENTICDOME_MSAF_CIRCUIT_BREAKER_RESET_S", 60),
        audit_logging=_env_bool("AGENTICDOME_MSAF_AUDIT_LOGGING", True),
        otel_enabled=_env_bool("AGENTICDOME_MSAF_OTEL_ENABLED", True),
        emergency_block_tools=_env("AGENTICDOME_MSAF_EMERGENCY_BLOCK_TOOLS", ""),
        emergency_block_agents=_env("AGENTICDOME_MSAF_EMERGENCY_BLOCK_AGENTS", ""),
        token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET", ""),
    )


class MicrosoftAgentFirewallError(RuntimeError):
    """Base Microsoft Agent Framework firewall exception."""


class MicrosoftAgentFirewallDenied(MicrosoftAgentFirewallError):
    """Raised when AgenticDome blocks or fail-closes execution."""


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
        if record is not None:
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
        key = self._key(
            session_id=session_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        raw = None
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
                created_at=float(payload["created_at"]),
                token_hmac=str(payload.get("token_hmac", "")),
            )
        except Exception:
            return None

def _build_token_store(config: FirewallConfig) -> DecisionTokenStore:
    if config.redis_url:
        try:
            logger.info("AgenticDome Microsoft Agent Framework firewall using Redis token store.")
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id)
        except Exception as exc:
            logger.warning("Redis token store unavailable; falling back to memory. reason=%s", exc)

    return InMemoryDecisionTokenStore(config.tenant_id)


class AgenticDomeMicrosoftAgentFirewall:
    """
    Production-grade AgenticDome firewall for Microsoft Agent Framework.

    Use it at these boundaries:
      1. before agent run -> screen_input(...)
      2. before direct tool execution -> wrap_tool_handler(...) or authorize_direct_tool_call(...)
      3. manager handoff -> authorize_manager_handoff(...)
      4. specialist execution -> verify_specialist_execution(...) or wrap_delegated_tool_handler(...)
      5. output review -> sanitize_text(...)
    """

    def __init__(self, *, config: Optional[FirewallConfig] = None):
        self.config = config or load_config()

        if not credentials_or_local_sim(self.config.api_base, self.config.api_key, self.config.tenant_id):
            raise ValueError(
                "AgenticDome firewall misconfigured. "
                "Set AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
            )

        try:
            self.client = AgenticDomeClient(
                api_base=self.config.api_base,
                api_key=self.config.api_key,
                tenant_id=self.config.tenant_id,
                timeout=self.config.timeout_s,
            )
        except TypeError:
            self.client = AgenticDomeClient(  # type: ignore
                self.config.api_base,
                {
                    "api_key": self.config.api_key,
                    "tenant_id": self.config.tenant_id,
                    "timeout": self.config.timeout_s,
                },
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
            if (
                self.config.circuit_breaker_failures > 0
                and self._circuit_failures >= self.config.circuit_breaker_failures
            ):
                self._circuit_open_until = time.time() + max(1, self.config.circuit_breaker_reset_s)

    async def _client_call(self, method_names: Tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
        if not self._circuit_allows_call():
            raise MicrosoftAgentFirewallDenied("AgenticDome circuit breaker is open for Microsoft Agent Framework firewall calls.")

        last_type_error: Optional[TypeError] = None
        last_error: Optional[Exception] = None
        attempts = max(1, self.config.retry_attempts)

        for method_name in method_names:
            method = getattr(self.client, method_name, None)
            if method is None:
                continue

            for attempt in range(attempts):
                try:
                    result = await self._to_thread(method, *args, **kwargs)
                    self._record_client_success()
                    return result
                except TypeError as exc:
                    last_type_error = exc
                    break
                except Exception as exc:
                    last_error = exc
                    self._record_client_failure()
                    if attempt + 1 >= attempts:
                        break
                    await asyncio.sleep(max(0.0, self.config.retry_backoff_s) * (2 ** attempt))

        if last_type_error and last_error is None:
            raise last_type_error
        if last_error:
            raise last_error

        raise AttributeError(
            f"AgenticDome client does not implement any of: {', '.join(method_names)}"
        )

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
        return {"_raw": str(raw)}

    @staticmethod
    def _strip_internal_tool_args(args: Dict[str, Any]) -> Dict[str, Any]:
        internal_keys = {
            "_decision_token",
            "_source_agent_id",
            "_agenticdome_decision_token",
            "_agenticdome_source_agent_id",
        }
        return {
            key: value
            for key, value in (args or {}).items()
            if key not in internal_keys
            and not str(key).startswith("_agenticdome_")
            and not str(key).startswith("_decision_")
        }

    def _csv_set(self, value: str) -> set:
        return {item.strip() for item in (value or "").split(",") if item.strip()}

    def _token_hmac(self, token: str) -> str:
        if not self.config.token_hmac_secret or not token:
            return ""
        digest = hmac.new(
            self.config.token_hmac_secret.encode("utf-8"),
            token.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _verify_record_hmac(self, record: DecisionTokenRecord) -> bool:
        if not self.config.token_hmac_secret:
            return True
        expected = self._token_hmac(record.decision_token)
        return bool(record.token_hmac) and hmac.compare_digest(record.token_hmac, expected)

    def _bounded_text(self, text: str, *, limit: int, label: str) -> str:
        if limit > 0 and len(text) > limit:
            return text[:limit] + f"\n[TRUNCATED BY AgenticDome {label}]"
        return text

    def _enforce_tool_arg_size(self, *, tool_name: str, tool_args: Dict[str, Any]) -> None:
        if self.config.max_tool_arg_chars <= 0:
            return
        serialized = json.dumps(tool_args or {}, sort_keys=True, default=str)
        if len(serialized) > self.config.max_tool_arg_chars:
            raise MicrosoftAgentFirewallDenied(f"Microsoft Agent Framework tool arguments exceed max size for {tool_name}.")

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
                raise MicrosoftAgentFirewallDenied(f"Microsoft Agent Framework rate limit exceeded for {purpose}.")
            events.append(now)

    def _emergency_policy_check(self, *, agent_id: str, tool_name: Optional[str] = None) -> None:
        if agent_id in self._csv_set(self.config.emergency_block_agents):
            raise MicrosoftAgentFirewallDenied(f"Emergency local policy blocked agent: {agent_id}")
        if tool_name and tool_name in self._csv_set(self.config.emergency_block_tools):
            raise MicrosoftAgentFirewallDenied(f"Emergency local policy blocked tool: {tool_name}")

    def _audit(self, event: str, *, agent_id: str, session_id: str, details: Optional[Dict[str, Any]] = None) -> None:
        if not self.config.audit_logging:
            return
        payload = {
            "event": event,
            "agent_id": agent_id,
            "session_id": session_id,
            "platform": self.config.platform,
        }
        if details:
            payload.update(details)
        logger.info("AgenticDome Microsoft Agent Framework audit: %s", json.dumps(payload, sort_keys=True, default=str))

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

    def _identity_context(self, ctx: Any, policy_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        source = dict(policy_context or {})
        identity = self._ctx_get(ctx, "identity", "entra_identity", "user", "principal", default=None)
        for key in (
            "tenant_id",
            "entra_tenant_id",
            "oid",
            "object_id",
            "appid",
            "app_id",
            "client_id",
            "upn",
            "username",
            "email",
            "user_id",
            "principal_id",
            "caller_id",
            "roles",
            "scp",
            "azp",
        ):
            value = self._ctx_get(ctx, key, default=None)
            if value is None and identity is not None:
                value = self._ctx_get(identity, key, default=None)
            if value is not None and key not in source:
                source[key] = value
        return source

    def _sanitized_args(self, payload: Any) -> Optional[Dict[str, Any]]:
        env = self._extract_result(payload)
        for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
            value = env.get(key)
            if isinstance(value, dict):
                return self._strip_internal_tool_args(value)
        return None

    @staticmethod
    def _extract_result(payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        result = payload.get("result")
        return result if isinstance(result, dict) else payload

    def _verdict(self, payload: Any) -> str:
        env = self._extract_result(payload)
        return self._safe_str(env.get("verdict") or env.get("decision")).upper()

    def _reason(self, payload: Any) -> str:
        env = self._extract_result(payload)
        return self._safe_str(env.get("reason") or env.get("message") or payload)

    def _ctx_get(self, ctx: Any, *names: str, default: Any = None) -> Any:
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

    def _session_id(self, ctx: Any) -> str:
        for key in ("session_id", "run_id", "trace_id", "conversation_id", "request_id", "task_id"):
            value = self._ctx_get(ctx, key)
            if value:
                return self._safe_str(value)

        if self.config.require_explicit_session_id or (
            self.config.production_mode and self.config.require_stable_session_id_in_prod
        ):
            raise MicrosoftAgentFirewallDenied(
                "Missing stable session_id/run_id/trace_id in Microsoft Agent Framework context."
            )

        return f"msaf-{uuid.uuid4().hex}"

    def _agent_id(self, ctx: Any, default: str = "microsoft_agent") -> str:
        agent = self._ctx_get(ctx, "agent", default=None)

        value = (
            self._safe_str(getattr(agent, "name", None))
            or self._safe_str(getattr(agent, "agent_id", None))
            or self._safe_str(getattr(agent, "id", None))
            or self._safe_str(self._ctx_get(ctx, "agent_name", "agent_id", "name"))
        )

        return value or default

    def _source_agent_id(self, ctx: Any) -> Optional[str]:
        value = self._ctx_get(ctx, "source_agent_id")
        text = self._safe_str(value)
        return text or None

    def _decision_token(self, ctx: Any) -> Optional[str]:
        value = self._ctx_get(ctx, "decision_token")
        text = self._safe_str(value)
        return text or None

    def _tool_platform(self, tool_platform: Optional[str], tool_args: Dict[str, Any]) -> str:
        return (
            self._safe_str(tool_platform)
            or self._safe_str(tool_args.get("tool_platform"))
            or self._safe_str(tool_args.get("platform"))
            or self.config.default_tool_platform
        )

    def _policy_context(
        self,
        *,
        session_id: str,
        agent_id: str,
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

    async def _report_incident_best_effort(
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

    async def _handle_error(self, exc: Exception, context: str) -> None:
        if isinstance(exc, MicrosoftAgentFirewallDenied):
            raise exc

        if self.config.fail_closed:
            raise MicrosoftAgentFirewallDenied(f"AgenticDome fail-closed: {context}: {exc}") from exc

        logger.warning("AgenticDome fail-open: %s: %s", context, exc)

    # ------------------------------------------------------------------
    # Core controls
    # ------------------------------------------------------------------

    async def screen_input(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            self._emergency_policy_check(agent_id=agent_id)
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="input")
            bounded_text = self._bounded_text(text, limit=self.config.max_input_chars, label="MSAF INPUT")
            if self.config.enforce_copilot_threat_api:
                await self._enforce_copilot_threat(
                    payload={"text": bounded_text, "agent_id": agent_id, "session_id": session_id, "stage": "input"},
                    agent_id=agent_id,
                    session_id=session_id,
                    stage="input",
                )
            response = await self._client_call(
                ("guardrail_validate", "guardrailValidate"),
                text=bounded_text,
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="input",
                session_id=session_id,
                policy_context=self._policy_context(
                    session_id=session_id,
                    agent_id=agent_id,
                    request_purpose="microsoft_agent.prompt_input",
                    policy_context=policy_context,
                ),
            )

            if self._verdict(response) == "BLOCKED":
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type="blocked_prompt_input",
                    details=self._reason(response),
                )
                raise MicrosoftAgentFirewallDenied(
                    f"AgenticDome blocked prompt: {self._reason(response)}"
                )

            self._audit("msaf_input_allowed", agent_id=agent_id, session_id=session_id)
            self._otel_event("agenticdome.msaf.input_allowed", {"agent_id": agent_id, "session_id": session_id})
            return self._extract_result(response) or response

        except Exception as exc:
            await self._handle_error(exc, "screen_input")
            return {}

    async def authorize_direct_tool_call(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_platform: Optional[str] = None,
        source_agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_tool_args = self._strip_internal_tool_args(tool_args)
        effective_tool_platform = self._tool_platform(tool_platform, clean_tool_args)

        try:
            self._emergency_policy_check(agent_id=agent_id, tool_name=tool_name)
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose=f"tool:{tool_name}")
            self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_tool_args)
            bounded_text = self._bounded_text(text or f"[Microsoft Agent Framework] Agent {agent_id} executing tool {tool_name}", limit=self.config.max_input_chars, label="MSAF TOOL AUTH")
            if self.config.enforce_copilot_threat_api:
                await self._enforce_copilot_threat(
                    payload={"text": bounded_text, "agent_id": agent_id, "session_id": session_id, "tool_name": tool_name, "tool_args": clean_tool_args, "stage": "tool"},
                    agent_id=agent_id,
                    session_id=session_id,
                    stage="tool",
                )
            response = await self._client_call(
                ("guardrail_validate", "guardrailValidate"),
                text=bounded_text,
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="outbound",
                session_id=session_id,
                tool_platform=effective_tool_platform,
                tool_name=tool_name,
                tool_args=clean_tool_args,
                policy_context=self._policy_context(
                    session_id=session_id,
                    agent_id=agent_id,
                    request_purpose="microsoft_agent.tool_authorization",
                    policy_context=policy_context,
                    extra={
                        "source_agent_id": source_agent_id or agent_id,
                        "tool_platform": effective_tool_platform,
                    },
                ),
                source_agent_id=source_agent_id,
            )

            if self._verdict(response) == "BLOCKED":
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type="blocked_tool_execution",
                    details=self._reason(response),
                )
                raise MicrosoftAgentFirewallDenied(
                    f"AgenticDome blocked tool: {self._reason(response)}"
                )

            result = self._extract_result(response) or response
            self._audit("msaf_tool_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": tool_name})
            self._otel_event("agenticdome.msaf.tool_allowed", {"agent_id": agent_id, "session_id": session_id, "tool_name": tool_name})
            return result

        except Exception as exc:
            await self._handle_error(exc, "authorize_direct_tool_call")
            return {}

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
        clean_tool_args = self._strip_internal_tool_args(tool_args)
        effective_tool_platform = self._tool_platform(tool_platform, clean_tool_args)

        try:
            self._emergency_policy_check(agent_id=manager_agent_id, tool_name=tool_name)
            self._check_rate_limit(agent_id=manager_agent_id, session_id=session_id, purpose=f"handoff:{tool_name}")
            self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_tool_args)
            bounded_text = self._bounded_text(
                text or f"[Microsoft Agent Framework] Manager {manager_agent_id} delegates {tool_name} to {specialist_agent_id}",
                limit=self.config.max_input_chars,
                label="MSAF HANDOFF",
            )
            response = await self._client_call(
                ("a2a_authorize_tool", "a2aAuthorizeTool"),
                text=bounded_text,
                agent_id=specialist_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform=effective_tool_platform,
                tool_name=tool_name,
                tool_args=clean_tool_args,
                session_id=session_id,
                direction="outbound",
                source_agent_id=manager_agent_id,
                policy_context=self._policy_context(
                    session_id=session_id,
                    agent_id=manager_agent_id,
                    request_purpose="delegated_task_execution",
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
                await self._report_incident_best_effort(
                    agent_id=manager_agent_id,
                    incident_type="blocked_delegation",
                    details=self._reason(envelope),
                )
                raise MicrosoftAgentFirewallDenied(
                    f"AgenticDome blocked delegation: {self._reason(envelope)}"
                )

            decision_token = self._safe_str(
                envelope.get("decision_token") or envelope.get("token")
            )

            if decision_token:
                self.token_store.put(
                    session_id=session_id,
                    target_agent_id=specialist_agent_id,
                    tool_name=tool_name,
                    tool_args=clean_tool_args,
                    record=DecisionTokenRecord(
                        decision_token=decision_token,
                        source_agent_id=manager_agent_id,
                        created_at=time.time(),
                        token_hmac=self._token_hmac(decision_token),
                    ),
                    ttl_s=self.config.handoff_token_ttl_s,
                )

            self._audit("msaf_handoff_authorized", agent_id=manager_agent_id, session_id=session_id, details={"specialist_agent_id": specialist_agent_id, "tool_name": tool_name})
            return envelope

        except Exception as exc:
            await self._handle_error(exc, "authorize_manager_handoff")
            return {}

    async def verify_specialist_execution(
        self,
        *,
        specialist_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_id: str,
        decision_token: Optional[str] = None,
        source_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_tool_args = self._strip_internal_tool_args(tool_args)
        token = decision_token
        source = source_agent_id

        if not token:
            pending = self.token_store.consume(
                session_id=session_id,
                target_agent_id=specialist_agent_id,
                tool_name=tool_name,
                tool_args=clean_tool_args,
            )
            if pending:
                if not self._verify_record_hmac(pending):
                    raise MicrosoftAgentFirewallDenied("Stored AgenticDome decision token failed local HMAC verification.")
                token = pending.decision_token
                source = pending.source_agent_id

        if not token or not source:
            await self._report_incident_best_effort(
                agent_id=specialist_agent_id,
                incident_type="missing_delegation_token",
                details=f"tool={tool_name}",
                severity="high",
            )
            raise MicrosoftAgentFirewallDenied(
                "Missing AgenticDome decision token or source_agent_id for delegated specialist execution."
            )

        try:
            response = await self._client_call(
                ("a2a_verify_decision_token_rpc", "a2aVerifyDecisionTokenRpc", "a2a_verify_decision_token"),
                token,
                tool_name=tool_name,
                tool_args=clean_tool_args,
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
                raise MicrosoftAgentFirewallDenied(
                    f"AgenticDome blocked delegated execution: {result.get('reason') or result}"
                )

            self._audit("msaf_delegation_verified", agent_id=specialist_agent_id, session_id=session_id, details={"tool_name": tool_name, "source_agent_id": source})
            return result

        except Exception as exc:
            await self._handle_error(exc, "verify_specialist_execution")
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
            bounded_text = self._bounded_text(text, limit=self.config.max_output_chars, label="MSAF OUTPUT")
            response = await self._client_call(
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
                    session_id=session_id,
                    agent_id=agent_id,
                    request_purpose="microsoft_agent.output_review",
                    policy_context=policy_context,
                    extra={
                        "redact_pii": self.config.redact_pii,
                        "redact_secrets": self.config.redact_secrets,
                        "block_on_sensitive_output": self.config.block_on_sensitive_output,
                    },
                ),
            )

            envelope = self._extract_result(response)
            verdict = self._verdict(envelope)

            sanitized_text = (
                envelope.get("text")
                or envelope.get("sanitized_text")
                or envelope.get("output")
                or (response.get("text") if isinstance(response, dict) else None)
                or (response.get("sanitized_text") if isinstance(response, dict) else None)
            )

            if verdict == "BLOCKED":
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type="blocked_output",
                    details=self._reason(envelope),
                )
                return "[OUTPUT BLOCKED BY AgenticDome]"

            if sanitized_text is not None:
                return self._safe_str(sanitized_text)

            return bounded_text

        except Exception as exc:
            await self._handle_error(exc, "sanitize_text")
            return text

    # ------------------------------------------------------------------
    # Optional Microsoft-specific threat helpers
    # ------------------------------------------------------------------

    async def copilot_validate_optional(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.config.enable_copilot_threat_api:
            return {
                "enabled": False,
                "reason": "AGENTICDOME_ENABLE_COPILOT_THREAT_API is false",
            }

        return await self._client_call(
            ("copilot_validate", "copilotValidate"),
            payload,
            api_version=self.config.copilot_api_version,
        )

    async def copilot_analyze_tool_execution_optional(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.config.enable_copilot_threat_api:
            return {
                "enabled": False,
                "reason": "AGENTICDOME_ENABLE_COPILOT_THREAT_API is false",
            }

        return await self._client_call(
            ("copilot_analyze_tool_execution", "copilotAnalyzeToolExecution"),
            payload,
            api_version=self.config.copilot_api_version,
        )

    async def _enforce_copilot_threat(
        self,
        *,
        payload: Dict[str, Any],
        agent_id: str,
        session_id: str,
        stage: str,
    ) -> Dict[str, Any]:
        if not self.config.enable_copilot_threat_api:
            return {"enabled": False}
        try:
            response = await self.copilot_validate_optional(payload)
            envelope = self._extract_result(response)
            verdict = self._verdict(envelope)
            blocked = verdict in {"BLOCKED", "DENY", "DENIED", "REJECTED"} or bool(envelope.get("blocked"))
            if blocked:
                reason = self._reason(envelope)
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type=f"copilot_threat_blocked_{stage}",
                    details=reason,
                    severity="high",
                )
                raise MicrosoftAgentFirewallDenied(f"Copilot threat helper blocked {stage}: {reason}")
            return envelope or response
        except MicrosoftAgentFirewallDenied:
            raise
        except Exception as exc:
            if self.config.enforce_copilot_threat_api:
                raise MicrosoftAgentFirewallDenied(f"Copilot threat helper failed during {stage}: {exc}") from exc
            logger.warning("Copilot threat helper failed open during %s: %s", stage, exc)
            return {}

    async def copilot_analyze_tool_execution_enforced(
        self,
        *,
        payload: Dict[str, Any],
        agent_id: str,
        session_id: str,
        tool_name: str,
    ) -> Dict[str, Any]:
        if not self.config.enable_copilot_threat_api:
            return {"enabled": False}
        try:
            response = await self.copilot_analyze_tool_execution_optional(payload)
            envelope = self._extract_result(response)
            verdict = self._verdict(envelope)
            blocked = verdict in {"BLOCKED", "DENY", "DENIED", "REJECTED"} or bool(envelope.get("blocked"))
            if blocked:
                reason = self._reason(envelope)
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type="copilot_threat_blocked_tool_execution",
                    details=f"tool={tool_name} reason={reason}",
                    severity="high",
                )
                raise MicrosoftAgentFirewallDenied(f"Copilot threat helper blocked tool execution: {reason}")
            return envelope or response
        except MicrosoftAgentFirewallDenied:
            raise
        except Exception as exc:
            if self.config.enforce_copilot_threat_api:
                raise MicrosoftAgentFirewallDenied(f"Copilot threat helper failed during tool execution: {exc}") from exc
            logger.warning("Copilot threat helper failed open during tool execution: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Wrappers
    # ------------------------------------------------------------------


    @staticmethod
    def _serialize_result_for_review(value: Any) -> str:
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return AgenticDomeMicrosoftAgentFirewall._safe_str(value)

    async def _sanitize_handler_result(
        self,
        *,
        raw_result: Any,
        agent_id: str,
        session_id: str,
        policy_context: Dict[str, Any],
        preserve_structured_output: bool,
    ) -> Any:
        result_text = self._serialize_result_for_review(raw_result)
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
    ) -> Callable[..., Awaitable[Any]]:
        async def secured(ctx: Any, args: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args)
            clean_args = self._strip_internal_tool_args(tool_args)
            agent_id = self._agent_id(ctx, default="microsoft_agent")
            session_id = self._session_id(ctx)
            source_agent_id = self._source_agent_id(ctx)

            text = (
                text_builder(ctx, clean_args)
                if text_builder
                else f"[Microsoft Agent Framework] {agent_id} intends to execute {tool_name}"
            )

            policy_context = self._identity_context(
                ctx,
                policy_context_builder(ctx, clean_args)
                if policy_context_builder
                else {"sdk": "microsoft_agent_framework", "agent_name": agent_id},
            )

            decision = await self.authorize_direct_tool_call(
                text=text,
                agent_id=agent_id,
                session_id=session_id,
                tool_name=tool_name,
                tool_args=clean_args,
                tool_platform=tool_platform,
                source_agent_id=source_agent_id,
                policy_context=policy_context,
            )
            execution_args = self._sanitized_args(decision) or clean_args

            if self.config.enable_copilot_threat_api:
                await self.copilot_analyze_tool_execution_enforced(
                    payload={"tool_name": tool_name, "tool_args": execution_args, "agent_id": agent_id, "session_id": session_id},
                    agent_id=agent_id,
                    session_id=session_id,
                    tool_name=tool_name,
                )

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
                    "request_purpose": "tool_output_review",
                    "tool_name": tool_name,
                },
            )

        return secured

    def wrap_delegated_tool_handler(
        self,
        *,
        tool_name: str,
        handler: Callable[..., Any],
        decision_token_getter: Optional[Callable[[Any, Dict[str, Any]], Optional[str]]] = None,
        source_agent_id_getter: Optional[Callable[[Any, Dict[str, Any]], Optional[str]]] = None,
        text_builder: Optional[Callable[[Any, Dict[str, Any]], str]] = None,
        policy_context_builder: Optional[Callable[[Any, Dict[str, Any]], Dict[str, Any]]] = None,
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
    ) -> Callable[..., Awaitable[Any]]:
        async def secured(ctx: Any, args: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args)
            clean_args = self._strip_internal_tool_args(tool_args)

            agent_id = self._agent_id(ctx, default="microsoft_specialist_agent")
            session_id = self._session_id(ctx)

            decision_token = decision_token_getter(ctx, clean_args) if decision_token_getter else None
            if not decision_token:
                decision_token = (
                    self._safe_str(tool_args.get("_agenticdome_decision_token"))
                    or self._safe_str(tool_args.get("_decision_token"))
                    or self._decision_token(ctx)
                    or None
                )

            source_agent_id = source_agent_id_getter(ctx, clean_args) if source_agent_id_getter else None
            if not source_agent_id:
                source_agent_id = (
                    self._safe_str(tool_args.get("_agenticdome_source_agent_id"))
                    or self._safe_str(tool_args.get("_source_agent_id"))
                    or self._source_agent_id(ctx)
                    or None
                )

            await self.verify_specialist_execution(
                specialist_agent_id=agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
                session_id=session_id,
                decision_token=decision_token,
                source_agent_id=source_agent_id,
            )

            if asyncio.iscoroutinefunction(handler):
                raw_result = await handler(ctx, clean_args, *a, **kw)
            else:
                raw_result = await asyncio.to_thread(handler, ctx, clean_args, *a, **kw)

            if not sanitize_output:
                return raw_result

            policy_context = self._identity_context(
                ctx,
                policy_context_builder(ctx, clean_args)
                if policy_context_builder
                else {"sdk": "microsoft_agent_framework", "agent_name": agent_id},
            )

            return await self._sanitize_handler_result(
                raw_result=raw_result,
                agent_id=agent_id,
                session_id=session_id,
                preserve_structured_output=preserve_structured_output,
                policy_context={
                    **policy_context,
                    "request_purpose": "delegated_tool_output_review",
                    "tool_name": tool_name,
                    "execution_text": (
                        text_builder(ctx, clean_args)
                        if text_builder
                        else f"[Microsoft Agent Framework] Specialist {agent_id} executes approved {tool_name}"
                    ),
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
    ) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_handler(
                tool_name=tool_name or getattr(handler, "__name__", "microsoft_tool"),
                handler=handler,
                tool_platform=tool_platform,
                sanitize_output=sanitize_output,
                preserve_structured_output=preserve_structured_output,
            )

        return decorator

    def secure_delegated_tool(
        self,
        *,
        tool_name: Optional[str] = None,
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
    ) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_delegated_tool_handler(
                tool_name=tool_name or getattr(handler, "__name__", "microsoft_delegated_tool"),
                handler=handler,
                sanitize_output=sanitize_output,
                preserve_structured_output=preserve_structured_output,
            )

        return decorator

    async def run_agent_securely(
        self,
        *,
        run_callable: Callable[..., Any],
        input_text: str,
        session_id: str,
        agent_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
        output_extractor: Optional[Callable[[Any], str]] = None,
        preserve_response_object: bool = False,
        response_mutator: Optional[Callable[[Any, str], Any]] = None,
        **kwargs: Any,
    ) -> Any:
        await self.screen_input(
            text=input_text,
            agent_id=agent_id,
            session_id=session_id,
            policy_context=policy_context,
        )

        bounded_input = self._bounded_text(input_text, limit=self.config.max_input_chars, label="MSAF RUN")
        if asyncio.iscoroutinefunction(run_callable):
            result = await run_callable(
                input_text=bounded_input,
                session_id=session_id,
                **kwargs,
            )
        else:
            result = await asyncio.to_thread(
                run_callable,
                input_text=bounded_input,
                session_id=session_id,
                **kwargs,
            )

        output_text = output_extractor(result) if output_extractor else self._safe_str(result)
        sanitized = await self.sanitize_text(
            text=output_text,
            agent_id=agent_id,
            session_id=session_id,
            policy_context={
                **(policy_context or {}),
                "request_purpose": "final_user_output",
            },
        )
        if preserve_response_object:
            if response_mutator:
                return response_mutator(result, sanitized)
            for attr in ("text", "content", "message", "output"):
                if hasattr(result, attr):
                    try:
                        setattr(result, attr, sanitized)
                        return result
                    except Exception:
                        pass
        return sanitized

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
                yield await self._sanitize_stream_chunk(
                    chunk=chunk,
                    agent_id=agent_id,
                    session_id=session_id,
                    policy_context=policy_context,
                )
            return
        if isinstance(chunks, Iterable) and not isinstance(chunks, (str, bytes, dict)):
            for chunk in chunks:
                yield await self._sanitize_stream_chunk(
                    chunk=chunk,
                    agent_id=agent_id,
                    session_id=session_id,
                    policy_context=policy_context,
                )
            return
        yield await self._sanitize_stream_chunk(
            chunk=chunks,
            agent_id=agent_id,
            session_id=session_id,
            policy_context=policy_context,
        )

    async def _sanitize_stream_chunk(
        self,
        *,
        chunk: Any,
        agent_id: str,
        session_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        if isinstance(chunk, str):
            return await self.sanitize_text(text=chunk, agent_id=agent_id, session_id=session_id, policy_context=policy_context)
        if isinstance(chunk, dict):
            return await self._sanitize_handler_result(
                raw_result=chunk,
                agent_id=agent_id,
                session_id=session_id,
                policy_context=policy_context or {},
                preserve_structured_output=True,
            )
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

    async def before_agent_run(self, ctx: Any, input_text: str, policy_context: Optional[Dict[str, Any]] = None) -> None:
        agent_id = self._agent_id(ctx, default="microsoft_agent")
        session_id = self._session_id(ctx)
        await self.screen_input(
            text=input_text,
            agent_id=agent_id,
            session_id=session_id,
            policy_context=self._identity_context(ctx, policy_context),
        )

    async def after_agent_run(self, ctx: Any, output: Any, policy_context: Optional[Dict[str, Any]] = None) -> Any:
        agent_id = self._agent_id(ctx, default="microsoft_agent")
        session_id = self._session_id(ctx)
        text = self._safe_str(output)
        return await self.sanitize_text(
            text=text,
            agent_id=agent_id,
            session_id=session_id,
            policy_context=self._identity_context(ctx, policy_context),
        )

    async def before_tool_call(
        self,
        ctx: Any,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        agent_id = self._agent_id(ctx, default="microsoft_agent")
        session_id = self._session_id(ctx)
        decision = await self.authorize_direct_tool_call(
            text=f"[Microsoft Agent Framework] {agent_id} intends to execute {tool_name}",
            agent_id=agent_id,
            session_id=session_id,
            tool_name=tool_name,
            tool_args=tool_args,
            tool_platform=tool_platform,
            source_agent_id=self._source_agent_id(ctx),
            policy_context=self._identity_context(ctx, policy_context),
        )
        return self._sanitized_args(decision) or self._strip_internal_tool_args(tool_args)

    async def after_tool_call(
        self,
        ctx: Any,
        *,
        tool_name: str,
        result: Any,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        agent_id = self._agent_id(ctx, default="microsoft_agent")
        session_id = self._session_id(ctx)
        return await self._sanitize_handler_result(
            raw_result=result,
            agent_id=agent_id,
            session_id=session_id,
            preserve_structured_output=True,
            policy_context={**self._identity_context(ctx, policy_context), "tool_name": tool_name},
        )

    def create_middleware(self) -> Any:
        firewall = self

        class AgenticDomeMicrosoftAgentMiddleware:
            async def before_agent_run(self, ctx: Any, input_text: str, **kwargs: Any) -> None:
                await firewall.before_agent_run(ctx, input_text, policy_context=kwargs.get("policy_context"))

            async def after_agent_run(self, ctx: Any, output: Any, **kwargs: Any) -> Any:
                return await firewall.after_agent_run(ctx, output, policy_context=kwargs.get("policy_context"))

            async def before_tool_call(self, ctx: Any, tool_name: str, tool_args: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
                return await firewall.before_tool_call(
                    ctx,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    tool_platform=kwargs.get("tool_platform"),
                    policy_context=kwargs.get("policy_context"),
                )

            async def after_tool_call(self, ctx: Any, tool_name: str, result: Any, **kwargs: Any) -> Any:
                return await firewall.after_tool_call(
                    ctx,
                    tool_name=tool_name,
                    result=result,
                    policy_context=kwargs.get("policy_context"),
                )

        return AgenticDomeMicrosoftAgentMiddleware()

    def install_on_agent(self, agent: Any, *, attr_name: str = "agenticdome_middleware") -> Any:
        middleware = self.create_middleware()
        try:
            existing = getattr(agent, attr_name, None)
            if isinstance(existing, list):
                existing.append(middleware)
            elif existing is None:
                setattr(agent, attr_name, [middleware])
            else:
                setattr(agent, attr_name, [existing, middleware])
        except Exception:
            setattr(agent, attr_name, [middleware])
        return agent

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


__all__ = [
    "FirewallConfig",
    "load_config",
    "MicrosoftAgentFirewallError",
    "MicrosoftAgentFirewallDenied",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "AgenticDomeMicrosoftAgentFirewall",
]
