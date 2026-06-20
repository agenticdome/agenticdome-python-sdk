from __future__ import annotations

import asyncio
import base64
import copy
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
from typing import Any, AsyncIterator, Awaitable, Callable, Deque, Dict, Iterable, List, Optional, Tuple

from agenticdome_sdk.client import AgentGuardClient

try:
    from agenticdome_sdk.exceptions import AgentGuardHTTPError
except Exception:  # pragma: no cover - compatibility with older package layouts
    try:
        from agenticdome_sdk.client import AgentGuardHTTPError  # type: ignore
    except Exception:  # pragma: no cover
        class AgentGuardHTTPError(Exception):  # type: ignore
            pass


logger = logging.getLogger("agenticdome.aws_bedrock")
logger.setLevel(logging.INFO)


# ============================================================================
# AgenticDome x AWS Bedrock
#
# This module protects local Python boundaries around Bedrock Runtime, Bedrock
# Agents action groups, knowledge-base retrieval, and local tool execution.
# ============================================================================


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

    platform: str = "aws_bedrock"
    default_tool_platform: str = "aws_bedrock"
    default_agent_id: str = "aws_bedrock_agent"
    default_model_id: str = ""

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

    aws_account_id: str = ""
    aws_region: str = ""
    aws_role_arn: str = ""
    aws_principal_arn: str = ""

    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:aws_bedrock:handoff"
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
        api_base=_env("AGENTICDOME_API_BASE", "https://au.agenticdome.io").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        platform=_env("AGENTICDOME_PLATFORM", "aws_bedrock"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "aws_bedrock"),
        default_agent_id=_env("AGENTICDOME_BEDROCK_AGENT_ID", "aws_bedrock_agent"),
        default_model_id=_env("AGENTICDOME_BEDROCK_MODEL_ID", ""),
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
        aws_account_id=_env("AGENTICDOME_AWS_ACCOUNT_ID", ""),
        aws_region=_env("AGENTICDOME_AWS_REGION", _env("AWS_REGION", _env("AWS_DEFAULT_REGION", ""))),
        aws_role_arn=_env("AGENTICDOME_AWS_ROLE_ARN", ""),
        aws_principal_arn=_env("AGENTICDOME_AWS_PRINCIPAL_ARN", ""),
        handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
        redis_url=_env("AGENTICDOME_REDIS_URL", "").strip(),
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:aws_bedrock:handoff"),
        token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET", ""),
        max_input_chars=_env_int("AGENTICDOME_BEDROCK_MAX_INPUT_CHARS", 50_000),
        max_output_chars=_env_int("AGENTICDOME_BEDROCK_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_BEDROCK_MAX_TOOL_ARG_CHARS", 20_000),
        streaming_buffer_chars=_env_int("AGENTICDOME_BEDROCK_STREAMING_BUFFER_CHARS", 4_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_BEDROCK_RATE_LIMIT_PER_MINUTE", 0),
        retry_attempts=_env_int("AGENTICDOME_BEDROCK_RETRY_ATTEMPTS", 2),
        retry_backoff_s=float(_env("AGENTICDOME_BEDROCK_RETRY_BACKOFF_S", "0.25") or "0.25"),
        circuit_breaker_failures=_env_int("AGENTICDOME_BEDROCK_CIRCUIT_BREAKER_FAILURES", 5),
        circuit_breaker_reset_s=_env_int("AGENTICDOME_BEDROCK_CIRCUIT_BREAKER_RESET_S", 60),
        audit_logging=_env_bool("AGENTICDOME_BEDROCK_AUDIT_LOGGING", True),
        otel_enabled=_env_bool("AGENTICDOME_BEDROCK_OTEL_ENABLED", True),
        emergency_block_tools=_env("AGENTICDOME_BEDROCK_EMERGENCY_BLOCK_TOOLS", ""),
        emergency_block_agents=_env("AGENTICDOME_BEDROCK_EMERGENCY_BLOCK_AGENTS", ""),
    )


class AWSBedrockFirewallError(RuntimeError):
    """Base AWS Bedrock firewall exception."""


class AWSBedrockConfigurationError(AWSBedrockFirewallError):
    """Raised when required AgenticDome configuration is missing."""


class AWSBedrockDenied(AWSBedrockFirewallError):
    """Raised when AgenticDome blocks or fail-closes a Bedrock operation."""


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
    payload = {"tool_name": tool_name or "", "tool_args": tool_args or {}}
    return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()


class InMemoryDecisionTokenStore(DecisionTokenStore):
    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id or "aws_bedrock"
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
        self._prefix = f"{key_prefix.rstrip(':')}:{tenant_id or 'aws_bedrock'}"

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
            logger.warning("Redis token store unavailable; using in-memory AWS Bedrock token store. reason=%s", exc)
    return InMemoryDecisionTokenStore(config.tenant_id)


class AgenticDomeAWSBedrockFirewall:
    """Firewall for local AWS Bedrock Runtime, Bedrock Agents, and retrieval boundaries."""

    def __init__(self, *, config: Optional[FirewallConfig] = None, client: Optional[AgentGuardClient] = None) -> None:
        self.config = config or load_config()
        if client is None and not (self.config.api_base and self.config.api_key and self.config.tenant_id):
            raise AWSBedrockConfigurationError(
                "AgenticDome AWS Bedrock firewall misconfigured. "
                "Set AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
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
            raise AWSBedrockDenied("AgenticDome AWS Bedrock circuit breaker is open.")
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
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        try:
            return str(value)
        except Exception:
            return repr(value)

    @staticmethod
    def _serialize_for_review(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if isinstance(value, (dict, list, tuple)):
            return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return AgenticDomeAWSBedrockFirewall._safe_str(value)

    @staticmethod
    def _json_loads_maybe(value: Any) -> Any:
        if isinstance(value, (dict, list)):
            return value
        if hasattr(value, "read"):
            value = value.read()
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return value
        return value

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
        return {"_raw": AgenticDomeAWSBedrockFirewall._safe_str(raw)}

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
        state = None
        try:
            state = ctx.get("state") if isinstance(ctx, dict) else getattr(ctx, "state")
        except Exception:
            state = None
        if isinstance(state, dict):
            for name in names:
                if state.get(name) is not None:
                    return state.get(name)
        return default

    def _agent_id(self, ctx: Any = None, explicit: Optional[str] = None) -> str:
        value = explicit
        if value is None and ctx is not None:
            value = self._ctx_attr(ctx, "agent_id", "agent_name", "name", "bedrock_agent_id", "agentId")
        return self._safe_str(value) or self.config.default_agent_id

    def _session_id(self, ctx: Any = None, explicit: Optional[str] = None) -> str:
        if explicit:
            return self._safe_str(explicit)
        if ctx is not None:
            for key in ("session_id", "sessionId", "run_id", "trace_id", "conversation_id", "request_id", "invocation_id", "invocationId"):
                value = self._ctx_attr(ctx, key)
                if value:
                    return self._safe_str(value)
        if self.config.require_explicit_session_id or (self.config.production_mode and self.config.require_stable_session_id_in_prod):
            raise AWSBedrockDenied("Missing stable session_id/run_id/trace_id in AWS Bedrock context.")
        return f"bedrock-{uuid.uuid4().hex}"

    def _user_id(self, ctx: Any = None) -> Optional[str]:
        value = self._ctx_attr(ctx, "user_id", "principal_id", "caller_id", "userId") if ctx is not None else None
        text = self._safe_str(value)
        return text or None

    def _identity_context(self, source: Any = None) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        defaults = {
            "aws_account_id": self.config.aws_account_id,
            "aws_region": self.config.aws_region,
            "aws_role_arn": self.config.aws_role_arn,
            "aws_principal_arn": self.config.aws_principal_arn,
        }
        for key, value in defaults.items():
            if value:
                out[key] = value
        for key in (
            "aws_account_id", "account_id", "accountId", "aws_region", "region", "aws_role_arn", "role_arn",
            "aws_principal_arn", "principal_arn", "caller_arn", "iam_role", "service_role", "bedrock_agent_id",
            "bedrock_agent_alias_id", "knowledge_base_id", "data_classification", "sensitivity_label",
        ):
            value = self._ctx_attr(source, key, default=None) if source is not None else None
            if value is not None:
                normalized = {
                    "account_id": "aws_account_id",
                    "accountId": "aws_account_id",
                    "region": "aws_region",
                    "role_arn": "aws_role_arn",
                    "principal_arn": "aws_principal_arn",
                    "caller_arn": "aws_principal_arn",
                }.get(key, key)
                out[normalized] = value
        return out

    def _policy_context(
        self,
        *,
        agent_id: str,
        session_id: str,
        request_purpose: str,
        model_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        source: Any = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ctx = dict(policy_context or {})
        ctx.setdefault("request_id", str(uuid.uuid4()))
        ctx.setdefault("request_ts_ms", int(time.time() * 1000))
        ctx["request_purpose"] = request_purpose
        ctx.setdefault("session_id", session_id)
        ctx.setdefault("source_agent_id", agent_id)
        ctx.setdefault("platform", self.config.platform)
        ctx.update({k: v for k, v in self._identity_context(source).items() if v is not None and v != ""})
        if model_id:
            ctx.setdefault("model_id", model_id)
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
            and str(key) not in {"decision_token", "source_agent_id", "delegation_token", "handoff_token"}
        }

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
                raise AWSBedrockDenied(f"AWS Bedrock rate limit exceeded for {purpose}.")
            events.append(now)

    def _enforce_tool_arg_size(self, *, tool_name: str, tool_args: Dict[str, Any]) -> None:
        if self.config.max_tool_arg_chars > 0 and len(self._serialize_for_review(tool_args or {})) > self.config.max_tool_arg_chars:
            raise AWSBedrockDenied(f"AWS Bedrock tool arguments exceed max size for {tool_name}.")

    def _enforce_input_size(self, *, text: str, label: str) -> None:
        if self.config.max_input_chars > 0 and len(text) > self.config.max_input_chars * 4:
            raise AWSBedrockDenied(f"AWS Bedrock {label} exceeds maximum accepted input size.")

    def _emergency_policy_check(self, *, agent_id: str, tool_name: Optional[str] = None) -> None:
        agents = {item.strip() for item in (self.config.emergency_block_agents or "").split(",") if item.strip()}
        tools = {item.strip() for item in (self.config.emergency_block_tools or "").split(",") if item.strip()}
        if agent_id in agents:
            raise AWSBedrockDenied(f"Emergency local policy blocked AWS Bedrock agent: {agent_id}")
        if tool_name and tool_name in tools:
            raise AWSBedrockDenied(f"Emergency local policy blocked AWS Bedrock tool: {tool_name}")

    def _audit(self, event: str, *, agent_id: str, session_id: str, details: Optional[Dict[str, Any]] = None) -> None:
        if not self.config.audit_logging:
            return
        payload = {"event": event, "agent_id": agent_id, "session_id": session_id, "platform": self.config.platform}
        if details:
            payload.update(details)
        logger.info("AgenticDome AWS Bedrock audit: %s", json.dumps(payload, sort_keys=True, default=str))

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
                raise AWSBedrockDenied(f"AWS Bedrock tool {tool_name} missing required args: {', '.join(missing)}")
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
                    raise AWSBedrockDenied(f"AWS Bedrock tool {tool_name} arg {key} failed schema validation.")

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
        for key in ("blocked", "is_blocked"):
            if key in view:
                return bool(view[key])
        for key in ("allowed", "allow"):
            if key in view:
                return not bool(view[key])
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

    def _sanitized_args(self, response: Any) -> Optional[Dict[str, Any]]:
        view = self._extract_decision_view(response)
        for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
            value = view.get(key) if isinstance(view, dict) else None
            if isinstance(value, dict):
                return self._strip_internal_args(value)
        return None

    def _decision_token(self, payload: Any) -> str:
        view = self._extract_decision_view(payload)
        for source in (view, payload if isinstance(payload, dict) else {}):
            if not isinstance(source, dict):
                continue
            for key in ("decision_token", "delegation_token", "handoff_token", "token"):
                value = source.get(key)
                if value:
                    return self._safe_str(value)
        return ""

    def _token_from_args(self, tool_args: Dict[str, Any]) -> str:
        for key in ("_AgenticDome_decision_token", "decision_token", "delegation_token", "handoff_token"):
            value = tool_args.get(key)
            if value:
                return self._safe_str(value)
        return ""

    def _token_hmac(self, token: str) -> str:
        if not self.config.token_hmac_secret or not token:
            return ""
        digest = hmac.new(self.config.token_hmac_secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _verify_record_hmac(self, record: DecisionTokenRecord) -> bool:
        if not self.config.token_hmac_secret:
            return True
        return bool(record.token_hmac) and hmac.compare_digest(record.token_hmac, self._token_hmac(record.decision_token))

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
        if isinstance(exc, AWSBedrockDenied):
            raise exc
        if self.config.fail_closed:
            raise AWSBedrockDenied(f"AgenticDome fail-closed: {context}: {exc}") from exc
        logger.warning("AgenticDome fail-open: %s: %s", context, exc)

    # ------------------------------------------------------------------
    # Bedrock payload extraction helpers
    # ------------------------------------------------------------------

    def extract_text_from_converse_messages(self, messages: Any, system: Any = None) -> str:
        parts: List[str] = []

        def walk(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, str):
                parts.append(value)
                return
            if isinstance(value, bytes):
                parts.append(value.decode("utf-8", errors="replace"))
                return
            if isinstance(value, dict):
                for key in ("text", "inputText", "prompt", "content", "toolUse", "toolResult", "json", "document", "image", "video"):
                    if key in value:
                        walk(value[key])
                return
            if isinstance(value, (list, tuple)):
                for item in value:
                    walk(item)

        walk(system)
        walk(messages)
        return "\n".join(part for part in parts if part).strip()

    def extract_text_from_invoke_body(self, body: Any) -> str:
        payload = self._json_loads_maybe(body)
        if isinstance(payload, str):
            return payload
        if not isinstance(payload, dict):
            return self._serialize_for_review(payload)

        direct_keys = (
            "prompt", "inputText", "input_text", "text", "query", "instruction", "system", "system_prompt",
            "input", "inputs", "question", "user_prompt",
        )
        parts: List[str] = []
        for key in direct_keys:
            if payload.get(key):
                parts.append(self._serialize_for_review(payload[key]))
        if payload.get("messages"):
            parts.append(self.extract_text_from_converse_messages(payload.get("messages"), payload.get("system")))
        if payload.get("contents"):
            parts.append(self.extract_text_from_converse_messages(payload.get("contents"), payload.get("system")))
        if payload.get("anthropic_version") and payload.get("messages"):
            parts.append(self.extract_text_from_converse_messages(payload.get("messages"), payload.get("system")))
        return "\n".join(part for part in parts if part).strip() or self._serialize_for_review(payload)

    def _apply_sanitized_text_to_converse_response(self, response: Any, sanitized_text: str) -> Any:
        out = copy.deepcopy(response)
        try:
            content = out.get("output", {}).get("message", {}).get("content")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and isinstance(item.get("text"), str):
                        item["text"] = sanitized_text
                        return out
            if isinstance(out.get("outputText"), str):
                out["outputText"] = sanitized_text
                return out
        except Exception:
            pass
        return sanitized_text

    def extract_text_from_bedrock_response(self, response: Any) -> str:
        payload = self._json_loads_maybe(response)
        if isinstance(payload, str):
            return payload
        if not isinstance(payload, dict):
            return self._serialize_for_review(payload)

        parts: List[str] = []
        output_message = payload.get("output", {}).get("message") if isinstance(payload.get("output"), dict) else None
        if output_message:
            parts.append(self.extract_text_from_converse_messages([output_message]))
        for key in ("outputText", "completion", "generation", "answer", "text", "generated_text", "output", "results"):
            value = payload.get(key)
            if value:
                parts.append(self._serialize_for_review(value))
        if isinstance(payload.get("content"), list):
            parts.append(self.extract_text_from_converse_messages(payload["content"]))
        if isinstance(payload.get("outputs"), list):
            parts.append(self.extract_text_from_converse_messages(payload["outputs"]))
        return "\n".join(part for part in parts if part).strip() or self._serialize_for_review(payload)

    def _apply_sanitized_text_to_provider_payload(self, parsed: Any, sanitized: str) -> Any:
        if not isinstance(parsed, dict):
            return sanitized
        out = copy.deepcopy(parsed)
        for key in ("outputText", "completion", "generation", "answer", "text", "generated_text"):
            if isinstance(out.get(key), str):
                out[key] = sanitized
                return out
        if isinstance(out.get("content"), list):
            for item in out["content"]:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    item["text"] = sanitized
                    return out
        if isinstance(out.get("outputs"), list):
            for item in out["outputs"]:
                if isinstance(item, dict):
                    for key in ("text", "outputText", "generation"):
                        if isinstance(item.get(key), str):
                            item[key] = sanitized
                            return out
        return sanitized

    def _extract_stream_event_text(self, event: Any) -> str:
        payload = self._json_loads_maybe(event)
        if isinstance(payload, dict):
            if isinstance(payload.get("chunk"), dict):
                chunk = payload["chunk"]
                if chunk.get("bytes") is not None:
                    return self.extract_text_from_bedrock_response(chunk.get("bytes"))
            for key in ("bytes", "text", "delta", "contentBlockDelta", "trace"):
                if key in payload:
                    return self.extract_text_from_bedrock_response(payload[key])
        return self._safe_str(event)

    def _apply_stream_event_text(self, event: Any, sanitized: str) -> Any:
        out = copy.deepcopy(event)
        if isinstance(out, dict):
            if isinstance(out.get("chunk"), dict) and out["chunk"].get("bytes") is not None:
                parsed = self._json_loads_maybe(out["chunk"].get("bytes"))
                updated = self._apply_sanitized_text_to_provider_payload(parsed, sanitized)
                out["chunk"]["bytes"] = json.dumps(updated).encode("utf-8") if isinstance(updated, (dict, list)) else self._safe_str(updated).encode("utf-8")
                return out
            for key in ("bytes", "text"):
                if key in out:
                    out[key] = sanitized.encode("utf-8") if isinstance(out[key], bytes) else sanitized
                    return out
        return sanitized

    # ------------------------------------------------------------------
    # Core AgenticDome controls
    # ------------------------------------------------------------------

    async def screen_prompt(self, *, text: str, agent_id: str, session_id: str, model_id: Optional[str] = None, user_id: Optional[str] = None, policy_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            self._emergency_policy_check(agent_id=agent_id)
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="prompt")
            self._enforce_input_size(text=text, label="prompt")
            response = await self._client_call(
                self.client.guardrail_validate,
                text=self._bounded_text(text, limit=self.config.max_input_chars, label="AWS BEDROCK INPUT"),
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="input",
                session_id=session_id,
                user_id=user_id,
                policy_context=self._policy_context(agent_id=agent_id, session_id=session_id, model_id=model_id, request_purpose="aws_bedrock.prompt_input", policy_context=policy_context),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_prompt_input", details=reason)
                raise AWSBedrockDenied(f"AgenticDome blocked Bedrock prompt: {reason}")
            self._audit("aws_bedrock_prompt_allowed", agent_id=agent_id, session_id=session_id, details={"model_id": model_id})
            self._otel_event("agenticdome.aws_bedrock.prompt_allowed", {"agent_id": agent_id, "session_id": session_id, "model_id": model_id or ""})
            return response
        except Exception as exc:
            await self._handle_error(exc, "screen_prompt")
            return {}

    async def authorize_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        agent_id: str,
        session_id: str,
        text: str,
        model_id: Optional[str] = None,
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        tool_schema: Optional[Any] = None,
    ) -> Dict[str, Any]:
        clean_args = self._strip_internal_args(tool_args)
        effective_tool_platform = tool_platform or clean_args.get("tool_platform") or clean_args.get("platform") or self.config.default_tool_platform
        try:
            self._emergency_policy_check(agent_id=agent_id, tool_name=tool_name)
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose=f"tool:{tool_name}")
            self._enforce_tool_arg_size(tool_name=tool_name, tool_args=clean_args)
            self._validate_tool_schema(tool_name=tool_name, tool_args=clean_args, schema=tool_schema)
            response = await self._client_call(
                self.client.guardrail_validate,
                text=self._bounded_text(text, limit=self.config.max_input_chars, label="AWS BEDROCK TOOL"),
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
                    model_id=model_id,
                    request_purpose="aws_bedrock.tool_execution",
                    policy_context=policy_context,
                    extra={"tool_name": tool_name, "tool_platform": effective_tool_platform},
                ),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_tool_execution", details=reason)
                raise AWSBedrockDenied(f"AgenticDome blocked Bedrock tool execution: {reason}")
            sanitized = self._sanitized_args(response)
            if sanitized is not None:
                self._validate_tool_schema(tool_name=tool_name, tool_args=sanitized, schema=tool_schema)
                response = dict(response or {})
                response["sanitized_tool_args"] = sanitized
            self._audit("aws_bedrock_tool_allowed", agent_id=agent_id, session_id=session_id, details={"tool_name": tool_name})
            self._otel_event("agenticdome.aws_bedrock.tool_allowed", {"agent_id": agent_id, "session_id": session_id, "tool_name": tool_name})
            return response
        except Exception as exc:
            await self._handle_error(exc, "authorize_tool_call")
            return {}

    async def sanitize_text(self, *, text: str, agent_id: str, session_id: str, model_id: Optional[str] = None, policy_context: Optional[Dict[str, Any]] = None) -> str:
        try:
            self._check_rate_limit(agent_id=agent_id, session_id=session_id, purpose="output")
            response = await self._client_call(
                self.client.mesh_validate,
                text=self._bounded_text(text, limit=self.config.max_output_chars, label="AWS BEDROCK OUTPUT"),
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
                    model_id=model_id,
                    request_purpose=(policy_context or {}).get("request_purpose", "aws_bedrock.output_review"),
                    policy_context=policy_context,
                    extra={"redact_pii": self.config.redact_pii, "redact_secrets": self.config.redact_secrets, "block_on_sensitive_output": self.config.block_on_sensitive_output},
                ),
            )
            if self._is_blocked(response):
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_output", details=self._reason(response))
                return "[OUTPUT BLOCKED BY AgenticDome]"
            sanitized = self._sanitized_text(response)
            return sanitized if sanitized is not None else text
        except Exception as exc:
            await self._handle_error(exc, "sanitize_text")
            return text

    # ------------------------------------------------------------------
    # AWS Bedrock Runtime wrappers
    # ------------------------------------------------------------------

    async def converse_securely(self, *, bedrock_runtime_client: Any, model_id: str, messages: List[Dict[str, Any]], agent_id: Optional[str] = None, session_id: Optional[str] = None, system: Optional[Any] = None, policy_context: Optional[Dict[str, Any]] = None, sanitize_output: Optional[bool] = None, **converse_kwargs: Any) -> Any:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(explicit=session_id)
        prompt_text = self.extract_text_from_converse_messages(messages, system)
        await self.screen_prompt(text=prompt_text or self._serialize_for_review(messages), agent_id=effective_agent_id, session_id=effective_session_id, model_id=model_id, policy_context=policy_context)
        call_kwargs = dict(converse_kwargs)
        call_kwargs.update({"modelId": model_id, "messages": copy.deepcopy(messages)})
        if system is not None:
            call_kwargs["system"] = copy.deepcopy(system)
        response = bedrock_runtime_client.converse(**call_kwargs)
        if isawaitable(response):
            response = await response
        should_sanitize = self.config.sanitize_model_output if sanitize_output is None else sanitize_output
        if not should_sanitize:
            return response
        response_text = self.extract_text_from_bedrock_response(response)
        sanitized = await self.sanitize_text(text=response_text, agent_id=effective_agent_id, session_id=effective_session_id, model_id=model_id, policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.converse_output"})
        return self._apply_sanitized_text_to_converse_response(response, sanitized)

    async def converse_stream_securely(self, *, bedrock_runtime_client: Any, model_id: str, messages: List[Dict[str, Any]], agent_id: Optional[str] = None, session_id: Optional[str] = None, system: Optional[Any] = None, policy_context: Optional[Dict[str, Any]] = None, sanitize_output: Optional[bool] = None, **converse_kwargs: Any) -> AsyncIterator[Any]:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(explicit=session_id)
        prompt_text = self.extract_text_from_converse_messages(messages, system)
        await self.screen_prompt(text=prompt_text or self._serialize_for_review(messages), agent_id=effective_agent_id, session_id=effective_session_id, model_id=model_id, policy_context=policy_context)
        call_kwargs = dict(converse_kwargs)
        call_kwargs.update({"modelId": model_id, "messages": copy.deepcopy(messages)})
        if system is not None:
            call_kwargs["system"] = copy.deepcopy(system)
        response = bedrock_runtime_client.converse_stream(**call_kwargs)
        if isawaitable(response):
            response = await response
        stream = response.get("stream") if isinstance(response, dict) else response
        should_sanitize = self.config.sanitize_model_output if sanitize_output is None else sanitize_output
        async for event in self._aiter(stream):
            if not should_sanitize:
                yield event
                continue
            text = self._extract_stream_event_text(event)
            if not text:
                yield event
                continue
            sanitized = await self.sanitize_text(text=text, agent_id=effective_agent_id, session_id=effective_session_id, model_id=model_id, policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.converse_stream_output"})
            yield self._apply_stream_event_text(event, sanitized)

    async def invoke_model_securely(self, *, bedrock_runtime_client: Any, model_id: str, body: Any, agent_id: Optional[str] = None, session_id: Optional[str] = None, policy_context: Optional[Dict[str, Any]] = None, sanitize_output: Optional[bool] = None, **invoke_kwargs: Any) -> Any:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(explicit=session_id)
        prompt_text = self.extract_text_from_invoke_body(body)
        await self.screen_prompt(text=prompt_text, agent_id=effective_agent_id, session_id=effective_session_id, model_id=model_id, policy_context=policy_context)
        call_kwargs = dict(invoke_kwargs)
        call_kwargs.update({"modelId": model_id, "body": body})
        response = bedrock_runtime_client.invoke_model(**call_kwargs)
        if isawaitable(response):
            response = await response
        should_sanitize = self.config.sanitize_model_output if sanitize_output is None else sanitize_output
        if not should_sanitize:
            return response
        return await self.sanitize_invoke_model_response(response=response, agent_id=effective_agent_id, session_id=effective_session_id, model_id=model_id, policy_context=policy_context)

    async def invoke_model_with_response_stream_securely(self, *, bedrock_runtime_client: Any, model_id: str, body: Any, agent_id: Optional[str] = None, session_id: Optional[str] = None, policy_context: Optional[Dict[str, Any]] = None, sanitize_output: Optional[bool] = None, **invoke_kwargs: Any) -> AsyncIterator[Any]:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(explicit=session_id)
        prompt_text = self.extract_text_from_invoke_body(body)
        await self.screen_prompt(text=prompt_text, agent_id=effective_agent_id, session_id=effective_session_id, model_id=model_id, policy_context=policy_context)
        call_kwargs = dict(invoke_kwargs)
        call_kwargs.update({"modelId": model_id, "body": body})
        response = bedrock_runtime_client.invoke_model_with_response_stream(**call_kwargs)
        if isawaitable(response):
            response = await response
        stream = response.get("body") if isinstance(response, dict) else response
        should_sanitize = self.config.sanitize_model_output if sanitize_output is None else sanitize_output
        async for event in self._aiter(stream):
            if not should_sanitize:
                yield event
                continue
            text = self._extract_stream_event_text(event)
            if not text:
                yield event
                continue
            sanitized = await self.sanitize_text(text=text, agent_id=effective_agent_id, session_id=effective_session_id, model_id=model_id, policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.invoke_model_stream_output"})
            yield self._apply_stream_event_text(event, sanitized)

    async def sanitize_invoke_model_response(self, *, response: Any, agent_id: str, session_id: str, model_id: Optional[str] = None, policy_context: Optional[Dict[str, Any]] = None) -> Any:
        if not isinstance(response, dict) or "body" not in response:
            text = self.extract_text_from_bedrock_response(response)
            return await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, model_id=model_id, policy_context=policy_context)
        out = dict(response)
        body = out.get("body")
        parsed = self._json_loads_maybe(body)
        text = self.extract_text_from_bedrock_response(parsed)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, model_id=model_id, policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.invoke_model_output"})
        updated = self._apply_sanitized_text_to_provider_payload(parsed, sanitized)
        out["body"] = json.dumps(updated).encode("utf-8") if isinstance(updated, (dict, list)) else self._safe_str(updated).encode("utf-8")
        return out

    async def invoke_agent_securely(self, *, bedrock_agent_runtime_client: Any, agent_id: str, agent_alias_id: str, session_id: str, input_text: str, source_agent_id: Optional[str] = None, policy_context: Optional[Dict[str, Any]] = None, sanitize_output: Optional[bool] = None, **invoke_kwargs: Any) -> Any:
        effective_agent_id = source_agent_id or self.config.default_agent_id
        await self.screen_prompt(text=input_text, agent_id=effective_agent_id, session_id=session_id, model_id=self.config.default_model_id or None, policy_context={**(policy_context or {}), "bedrock_agent_id": agent_id, "bedrock_agent_alias_id": agent_alias_id})
        call_kwargs = dict(invoke_kwargs)
        call_kwargs.update({"agentId": agent_id, "agentAliasId": agent_alias_id, "sessionId": session_id, "inputText": input_text})
        response = bedrock_agent_runtime_client.invoke_agent(**call_kwargs)
        if isawaitable(response):
            response = await response
        should_sanitize = self.config.sanitize_model_output if sanitize_output is None else sanitize_output
        if not should_sanitize:
            return response
        if isinstance(response, dict) and "completion" in response:
            out = dict(response)
            chunks = []
            async for event in self._aiter(out["completion"]):
                text = self._extract_stream_event_text(event)
                if text:
                    sanitized = await self.sanitize_text(text=text, agent_id=effective_agent_id, session_id=session_id, model_id=self.config.default_model_id or None, policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.invoke_agent_output"})
                    chunks.append(self._apply_stream_event_text(event, sanitized))
                else:
                    chunks.append(event)
            out["completion"] = chunks
            return out
        text = self.extract_text_from_bedrock_response(response)
        sanitized = await self.sanitize_text(text=text, agent_id=effective_agent_id, session_id=session_id, model_id=self.config.default_model_id or None, policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.invoke_agent_output"})
        return sanitized if sanitized != text else response

    async def _aiter(self, stream: Any) -> AsyncIterator[Any]:
        if hasattr(stream, "__aiter__"):
            async for item in stream:
                yield item
            return
        if stream is None:
            return
        for item in stream:
            yield item

    # ------------------------------------------------------------------
    # Tool, action-group, retrieval, and delegation helpers
    # ------------------------------------------------------------------

    def _mutate_args(self, original: Any, replacement: Dict[str, Any]) -> Dict[str, Any]:
        clean = self._strip_internal_args(replacement)
        if isinstance(original, dict):
            original.clear()
            original.update(clean)
            return original
        return clean

    async def authorize_manager_handoff(self, *, source_agent_id: str, target_agent_id: str, target_tool_name: str, target_tool_args: Dict[str, Any], session_id: str, model_id: Optional[str] = None, handoff_reason: Optional[str] = None, policy_context: Optional[Dict[str, Any]] = None) -> DecisionTokenRecord:
        clean_args = self._strip_internal_args(target_tool_args)
        try:
            self._emergency_policy_check(agent_id=source_agent_id, tool_name=target_tool_name)
            self._emergency_policy_check(agent_id=target_agent_id, tool_name=target_tool_name)
            self._check_rate_limit(agent_id=source_agent_id, session_id=session_id, purpose=f"handoff:{target_agent_id}")
            self._enforce_tool_arg_size(tool_name=target_tool_name, tool_args=clean_args)
            response = await self._client_call(
                self.client.guardrail_validate,
                text=self._bounded_text(handoff_reason or f"[AWS Bedrock] {source_agent_id} delegates {target_tool_name} to {target_agent_id}", limit=self.config.max_input_chars, label="AWS BEDROCK HANDOFF"),
                agent_id=source_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="handoff",
                session_id=session_id,
                tool_platform=self.config.default_tool_platform,
                tool_name=target_tool_name,
                tool_args=clean_args,
                policy_context=self._policy_context(agent_id=source_agent_id, session_id=session_id, model_id=model_id, request_purpose="aws_bedrock.manager_handoff", policy_context=policy_context, extra={"target_agent_id": target_agent_id, "target_tool_name": target_tool_name}),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=source_agent_id, incident_type="blocked_agent_handoff", details=reason)
                raise AWSBedrockDenied(f"AgenticDome blocked Bedrock handoff: {reason}")
            token = self._decision_token(response) or f"bedrock-{uuid.uuid4().hex}"
            record = DecisionTokenRecord(decision_token=token, source_agent_id=source_agent_id, created_at=time.time(), token_hmac=self._token_hmac(token))
            self.token_store.put(session_id=session_id, target_agent_id=target_agent_id, tool_name=target_tool_name, tool_args=clean_args, record=record, ttl_s=self.config.handoff_token_ttl_s)
            self._audit("aws_bedrock_handoff_allowed", agent_id=source_agent_id, session_id=session_id, details={"target_agent_id": target_agent_id, "target_tool_name": target_tool_name})
            return record
        except Exception as exc:
            await self._handle_error(exc, "authorize_manager_handoff")
            return DecisionTokenRecord("", source_agent_id, time.time())

    async def verify_delegated_execution(self, *, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any], session_id: str, source_agent_id: Optional[str] = None, decision_token: Optional[str] = None, model_id: Optional[str] = None, policy_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        clean_args = self._strip_internal_args(tool_args)
        record = None
        token = self._safe_str(decision_token or self._token_from_args(tool_args))
        if not token:
            record = self.token_store.consume(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=clean_args)
            if record:
                token = record.decision_token
                source_agent_id = source_agent_id or record.source_agent_id
        if not token:
            raise AWSBedrockDenied("Missing AWS Bedrock delegated execution decision token.")
        if record and not self._verify_record_hmac(record):
            raise AWSBedrockDenied("Invalid AWS Bedrock delegated execution decision token HMAC.")
        try:
            response = await self._client_call(
                self.client.guardrail_validate,
                text=f"[AWS Bedrock] Verify delegated execution of {tool_name} by {target_agent_id}",
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
                policy_context=self._policy_context(agent_id=target_agent_id, session_id=session_id, model_id=model_id, request_purpose="aws_bedrock.delegated_execution", policy_context=policy_context, extra={"source_agent_id": source_agent_id or (record.source_agent_id if record else "")}),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=target_agent_id, incident_type="blocked_delegated_execution", details=reason)
                raise AWSBedrockDenied(f"AgenticDome blocked Bedrock delegated execution: {reason}")
            self._audit("aws_bedrock_delegated_execution_allowed", agent_id=target_agent_id, session_id=session_id, details={"tool_name": tool_name})
            return response
        except Exception as exc:
            await self._handle_error(exc, "verify_delegated_execution")
            return {}

    def wrap_tool_handler(self, *, tool_name: str, handler: Callable[..., Any], tool_platform: Optional[str] = None, text_builder: Optional[Callable[[Any, Dict[str, Any]], str]] = None, policy_context_builder: Optional[Callable[[Any, Dict[str, Any]], Dict[str, Any]]] = None, sanitize_output: Optional[bool] = None, preserve_structured_output: bool = True, tool_schema: Optional[Any] = None) -> Callable[..., Awaitable[Any]]:
        async def secured(ctx: Any, args: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args)
            agent_id = self._agent_id(ctx)
            session_id = self._session_id(ctx)
            model_id = self._safe_str(self._ctx_attr(ctx, "model_id", "modelId", default=self.config.default_model_id)) or None
            policy_context = policy_context_builder(ctx, tool_args) if policy_context_builder else {"framework": "aws_bedrock", "agent_name": agent_id}
            stored_record = self.token_store.get(session_id=session_id, target_agent_id=agent_id, tool_name=tool_name, tool_args=self._strip_internal_args(tool_args))
            if self._token_from_args(tool_args) or stored_record is not None:
                await self.verify_delegated_execution(target_agent_id=agent_id, tool_name=tool_name, tool_args=tool_args, session_id=session_id, model_id=model_id, policy_context=policy_context)
                tool_args = self._strip_internal_args(tool_args)
            else:
                text = text_builder(ctx, tool_args) if text_builder else f"[AWS Bedrock] {agent_id} intends to execute {tool_name}"
                response = await self.authorize_tool_call(tool_name=tool_name, tool_args=tool_args, agent_id=agent_id, session_id=session_id, text=text, model_id=model_id, tool_platform=tool_platform, policy_context=policy_context, tool_schema=tool_schema)
                sanitized = self._sanitized_args(response)
                if sanitized is not None:
                    tool_args = self._mutate_args(args, sanitized)
            raw_result = handler(ctx, tool_args, *a, **kw)
            if isawaitable(raw_result):
                raw_result = await raw_result
            should_sanitize = self.config.sanitize_tool_output if sanitize_output is None else sanitize_output
            if not should_sanitize:
                return raw_result
            result_text = self._serialize_for_review(raw_result)
            sanitized = await self.sanitize_text(text=result_text, agent_id=agent_id, session_id=session_id, model_id=model_id, policy_context={**policy_context, "request_purpose": "aws_bedrock.tool_output_review", "tool_name": tool_name})
            if preserve_structured_output and isinstance(raw_result, (dict, list, tuple)):
                if sanitized == result_text:
                    return raw_result
                try:
                    return json.loads(sanitized)
                except Exception:
                    pass
            return sanitized
        return secured

    def secure_tool(self, *, tool_name: str, tool_platform: Optional[str] = None, **options: Any) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_handler(tool_name=tool_name, handler=handler, tool_platform=tool_platform, **options)
        return decorator

    def wrap_action_group_lambda(self, *, handler: Callable[..., Any], tool_platform: Optional[str] = "aws_bedrock_action_group", sanitize_output: Optional[bool] = None, tool_schema: Optional[Any] = None) -> Callable[..., Awaitable[Any]]:
        async def secured(event: Dict[str, Any], context: Any = None) -> Any:
            tool_name = self._safe_str(event.get("function") or event.get("actionGroup") or event.get("apiPath") or "bedrock.action_group")
            params = event.get("parameters") or event.get("requestBody") or event.get("input") or {}
            args = self._normalize_args(params)
            ctx = {
                "agent_id": event.get("agent", {}).get("id") if isinstance(event.get("agent"), dict) else event.get("agent_id"),
                "session_id": event.get("sessionId") or event.get("session_id") or getattr(context, "aws_request_id", None),
                "model_id": event.get("modelId") or self.config.default_model_id,
                "aws_account_id": getattr(context, "invoked_function_arn", "").split(":")[4] if getattr(context, "invoked_function_arn", "") else self.config.aws_account_id,
            }
            secured_tool = self.wrap_tool_handler(tool_name=tool_name, handler=lambda _ctx, _args: handler(event, context), tool_platform=tool_platform, sanitize_output=sanitize_output, tool_schema=tool_schema)
            return await secured_tool(ctx, args)
        return secured

    async def sanitize_retrieval_result(self, *, retrieval_result: Any, agent_id: str, session_id: str, model_id: Optional[str] = None, policy_context: Optional[Dict[str, Any]] = None) -> Any:
        async def sanitize_node(node: Any, index: int = 0) -> Any:
            if not isinstance(node, dict):
                return node
            out = copy.deepcopy(node)
            content = out.get("content")
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                content["text"] = await self.sanitize_text(text=content["text"], agent_id=agent_id, session_id=session_id, model_id=model_id, policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.retrieval_node_review", "retrieval_index": index})
                return out
            if isinstance(out.get("text"), str):
                out["text"] = await self.sanitize_text(text=out["text"], agent_id=agent_id, session_id=session_id, model_id=model_id, policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.retrieval_node_review", "retrieval_index": index})
            return out

        if isinstance(retrieval_result, dict) and isinstance(retrieval_result.get("retrievalResults"), list):
            out = copy.deepcopy(retrieval_result)
            out["retrievalResults"] = [await sanitize_node(node, idx) for idx, node in enumerate(out["retrievalResults"])]
            return out
        if isinstance(retrieval_result, list):
            return [await sanitize_node(node, idx) for idx, node in enumerate(retrieval_result)]
        text = self._serialize_for_review(retrieval_result)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, model_id=model_id, policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.retrieval_result_review"})
        if isinstance(retrieval_result, (dict, list, tuple)) and sanitized == text:
            return retrieval_result
        try:
            return json.loads(sanitized)
        except Exception:
            return sanitized


__all__ = [
    "AgenticDomeAWSBedrockFirewall",
    "AWSBedrockConfigurationError",
    "AWSBedrockDenied",
    "AWSBedrockFirewallError",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "FirewallConfig",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "load_config",
]
