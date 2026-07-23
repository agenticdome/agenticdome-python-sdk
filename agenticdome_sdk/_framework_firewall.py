from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import hmac
import inspect
import json
import logging
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock, Thread
from typing import Any, Awaitable, Callable, Deque, Dict, Optional, Tuple, Type

from .client import AgentGuardClient


@dataclass(frozen=True)
class FrameworkFirewallConfig:
    api_base: str
    api_key: str
    tenant_id: str
    platform: str
    agent_id: str
    default_tool_platform: str = "python"
    timeout_s: int = 20
    fail_closed: bool = True
    production_mode: bool = False
    require_explicit_session_id: bool = False
    require_stable_session_id_in_prod: bool = True
    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False
    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:framework:handoff"
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
    strict_delegated_execution: bool = True
    scan_code_expressions: bool = True
    report_incidents: bool = True
    blocked_incident_severity: str = "medium"


@dataclass(frozen=True)
class DecisionTokenRecord:
    decision_token: str
    source_agent_id: str
    created_at: float
    token_hmac: str = ""


def _stable_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        return json.dumps(str(value))


def _fingerprint(tool_name: str, tool_args: Dict[str, Any]) -> str:
    return hashlib.sha256(_stable_json({"tool_name": tool_name, "tool_args": tool_args}).encode()).hexdigest()


class DecisionTokenStore:
    def put(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any], record: DecisionTokenRecord, ttl_s: int) -> None:
        raise NotImplementedError

    def consume(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        raise NotImplementedError

    def delete(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> None:
        raise NotImplementedError


class InMemoryDecisionTokenStore(DecisionTokenStore):
    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self._lock = Lock()
        self._data: Dict[str, Tuple[float, DecisionTokenRecord]] = {}

    def _key(self, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
        return f"{self.tenant_id}:{session_id}:{target_agent_id}:{_fingerprint(tool_name, tool_args)}"

    def put(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any], record: DecisionTokenRecord, ttl_s: int) -> None:
        with self._lock:
            self._data[self._key(session_id, target_agent_id, tool_name, tool_args)] = (time.time() + max(1, ttl_s), record)

    def consume(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        with self._lock:
            entry = self._data.pop(self._key(session_id, target_agent_id, tool_name, tool_args), None)
        return entry[1] if entry and entry[0] > time.time() else None

    def delete(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> None:
        with self._lock:
            self._data.pop(self._key(session_id, target_agent_id, tool_name, tool_args), None)


class RedisDecisionTokenStore(DecisionTokenStore):
    def __init__(self, redis_url: str, key_prefix: str, tenant_id: str) -> None:
        import redis

        self.client = redis.Redis.from_url(redis_url, decode_responses=True)
        self.prefix = key_prefix.rstrip(":")
        self.tenant_id = tenant_id

    def _key(self, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> str:
        return f"{self.prefix}:{self.tenant_id}:{session_id}:{target_agent_id}:{_fingerprint(tool_name, tool_args)}"

    def put(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any], record: DecisionTokenRecord, ttl_s: int) -> None:
        self.client.setex(
            self._key(session_id, target_agent_id, tool_name, tool_args),
            max(1, ttl_s),
            _stable_json(record.__dict__),
        )

    def consume(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        pipe = self.client.pipeline()
        pipe.get(key)
        pipe.delete(key)
        raw, _ = pipe.execute()
        if not raw:
            return None
        value = json.loads(raw)
        return DecisionTokenRecord(**value)

    def delete(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> None:
        self.client.delete(self._key(session_id, target_agent_id, tool_name, tool_args))


def build_token_store(config: FrameworkFirewallConfig, logger: logging.Logger) -> DecisionTokenStore:
    if config.redis_url:
        try:
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id)
        except Exception as exc:
            logger.warning("Redis token store unavailable; using process-local storage: %s", exc)
    return InMemoryDecisionTokenStore(config.tenant_id)


def run_coro_sync(coro: Awaitable[Any]) -> Any:
    """Run a coroutine from sync code, including when the caller already owns an event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    outcome: Dict[str, Any] = {}

    def runner() -> None:
        try:
            outcome["value"] = asyncio.run(coro)
        except BaseException as exc:  # propagate on the calling thread
            outcome["error"] = exc

    thread = Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


class FrameworkFirewallBase:
    """Shared, dependency-free enforcement used by native framework adapters."""

    def __init__(
        self,
        config: FrameworkFirewallConfig,
        *,
        client: Optional[AgentGuardClient],
        token_store: Optional[DecisionTokenStore],
        denied_error: Type[Exception],
        configuration_error: Type[Exception],
        label: str,
        logger: logging.Logger,
    ) -> None:
        if not (config.api_base and config.api_key and config.tenant_id):
            raise configuration_error("Missing AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, or AGENTICDOME_TENANT_ID.")
        self.config = config
        self.client = client or AgentGuardClient(
            api_base=config.api_base,
            api_key=config.api_key,
            tenant_id=config.tenant_id,
            timeout=config.timeout_s,
        )
        self.token_store = token_store or build_token_store(config, logger)
        self.denied_error = denied_error
        self.label = label
        self.logger = logger
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

    @staticmethod
    def serialize(value: Any) -> str:
        return value if isinstance(value, str) else _stable_json(value)

    @staticmethod
    def normalize_args(value: Any) -> Dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, dict) else {"_raw": parsed}
            except Exception:
                return {"_raw": value}
        return {"_raw": str(value)}

    @staticmethod
    def strip_private_args(value: Dict[str, Any]) -> Dict[str, Any]:
        private = {"_decision_token", "decision_token", "_source_agent_id", "source_agent_id"}
        return {k: v for k, v in value.items() if not str(k).startswith("_AgenticDome_") and k not in private}

    @staticmethod
    def envelope(payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        result = payload.get("result")
        return result if isinstance(result, dict) else payload

    @classmethod
    def verdict(cls, payload: Any) -> str:
        env = cls.envelope(payload)
        return str(env.get("verdict") or env.get("decision") or "").upper()

    @classmethod
    def reason(cls, payload: Any) -> str:
        env = cls.envelope(payload)
        return str(env.get("reason") or env.get("message") or payload)

    def session_id(self, explicit: Optional[str], source: Any = None) -> str:
        if explicit:
            return str(explicit)
        for name in ("session_id", "run_id", "trace_id", "conversation_id", "request_id", "thread_id"):
            value = source.get(name) if isinstance(source, dict) else getattr(source, name, None)
            if value:
                return str(value)
        if self.config.require_explicit_session_id or (self.config.production_mode and self.config.require_stable_session_id_in_prod):
            raise self.denied_error(f"Missing stable session identifier for {self.label} execution.")
        return f"{self.config.platform}-{uuid.uuid4().hex}"

    def _policy_context(self, session_id: str, purpose: str, policy_context: Optional[Dict[str, Any]], **extra: Any) -> Dict[str, Any]:
        context = dict(policy_context or {})
        context.setdefault("request_id", uuid.uuid4().hex)
        context.setdefault("request_ts_ms", int(time.time() * 1000))
        context.setdefault("session_id", session_id)
        context.setdefault("platform", self.config.platform)
        context["request_purpose"] = purpose
        context.update({k: v for k, v in extra.items() if v is not None})
        return context

    def _local_checks(self, agent_id: str, session_id: str, purpose: str, tool_name: Optional[str] = None) -> None:
        blocked_agents = {v.strip() for v in self.config.emergency_block_agents.split(",") if v.strip()}
        blocked_tools = {v.strip() for v in self.config.emergency_block_tools.split(",") if v.strip()}
        if agent_id in blocked_agents or (tool_name and tool_name in blocked_tools):
            raise self.denied_error(f"AgenticDome emergency policy blocked {tool_name or agent_id}.")
        limit = self.config.rate_limit_per_minute
        if limit <= 0:
            return
        key = f"{agent_id}:{session_id}:{purpose}"
        now = time.time()
        with self._rate_lock:
            events = self._rate_events[key]
            while events and events[0] < now - 60:
                events.popleft()
            if len(events) >= limit:
                raise self.denied_error(f"AgenticDome {self.label} rate limit exceeded for {purpose}.")
            events.append(now)

    def _bounded(self, text: str, limit: int, label: str) -> str:
        if limit > 0 and len(text) > limit:
            return text[:limit] + f"\n[TRUNCATED BY AgenticDome {label}]"
        return text

    def _client_call_sync(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        with self._circuit_lock:
            if time.time() < self._circuit_open_until:
                raise self.denied_error(f"AgenticDome {self.label} circuit breaker is open.")
        last_error: Optional[Exception] = None
        for attempt in range(max(1, self.config.retry_attempts)):
            try:
                result = fn(*args, **kwargs)
                if inspect.isawaitable(result):
                    result = run_coro_sync(result)
                with self._circuit_lock:
                    self._circuit_failures = 0
                    self._circuit_open_until = 0.0
                return result
            except Exception as exc:
                last_error = exc
                with self._circuit_lock:
                    self._circuit_failures += 1
                    if self.config.circuit_breaker_failures > 0 and self._circuit_failures >= self.config.circuit_breaker_failures:
                        self._circuit_open_until = time.time() + max(1, self.config.circuit_breaker_reset_s)
                if attempt + 1 < max(1, self.config.retry_attempts):
                    time.sleep(max(0.0, self.config.retry_backoff_s) * (2**attempt))
        assert last_error is not None
        raise last_error

    def _failure(self, context: str, exc: Exception, fallback: Any) -> Any:
        if isinstance(exc, self.denied_error):
            raise exc
        if self.config.fail_closed:
            raise self.denied_error(f"AgenticDome fail-closed during {self.label} {context}: {exc}") from exc
        self.logger.warning("AgenticDome fail-open during %s %s: %s", self.label, context, exc)
        return fallback

    def _audit(self, event: str, **details: Any) -> None:
        if self.config.audit_logging:
            self.logger.info("AgenticDome %s audit: %s", self.label, _stable_json({"event": event, **details}))

    def _token_hmac(self, token: str) -> str:
        if not self.config.token_hmac_secret:
            return ""
        digest = hmac.new(self.config.token_hmac_secret.encode(), token.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    def screen_input(self, *, session_id: str, agent_id: str, text: str, policy_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            self._local_checks(agent_id, session_id, "input")
            response = self._client_call_sync(
                self.client.guardrail_validate,
                text=self._bounded(text, self.config.max_input_chars, "INPUT"),
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="input",
                session_id=session_id,
                policy_context=self._policy_context(session_id, f"{self.config.platform}_prompt_input", policy_context),
            )
            if self.verdict(response) == "BLOCKED":
                raise self.denied_error(f"AgenticDome blocked {self.label} prompt: {self.reason(response)}")
            self._audit("input_allowed", agent_id=agent_id, session_id=session_id)
            return self.envelope(response) or response
        except Exception as exc:
            return self._failure("input screening", exc, {"verdict": "ALLOWED", "reason": "fail-open"})

    async def ascreen_input(self, **kwargs: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self.screen_input, **kwargs)

    def authorize_tool_call(
        self,
        *,
        session_id: str,
        agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        text: str = "",
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        source_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_args = self.strip_private_args(tool_args)
        try:
            self._local_checks(agent_id, session_id, f"tool:{tool_name}", tool_name)
            if self.config.max_tool_arg_chars > 0 and len(self.serialize(clean_args)) > self.config.max_tool_arg_chars:
                raise self.denied_error(f"AgenticDome {self.label} tool arguments exceed the configured maximum.")
            response = self._client_call_sync(
                self.client.guardrail_validate,
                text=self._bounded(text or f"[{self.label}] {agent_id} calls {tool_name}", self.config.max_input_chars, "TOOL"),
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                source_agent_id=source_agent_id,
                direction="outbound",
                session_id=session_id,
                tool_platform=tool_platform or self.config.default_tool_platform,
                tool_name=tool_name,
                tool_args=clean_args,
                policy_context=self._policy_context(session_id, f"{self.config.platform}_tool_call", policy_context, tool_name=tool_name),
            )
            if self.verdict(response) == "BLOCKED":
                raise self.denied_error(f"AgenticDome blocked {self.label} tool {tool_name}: {self.reason(response)}")
            self._audit("tool_allowed", agent_id=agent_id, session_id=session_id, tool_name=tool_name)
            return self.envelope(response) or response
        except Exception as exc:
            return self._failure("tool authorization", exc, {"verdict": "ALLOWED", "reason": "fail-open"})

    async def aauthorize_tool_call(self, **kwargs: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self.authorize_tool_call, **kwargs)

    def sanitized_args(self, decision: Dict[str, Any], original: Dict[str, Any]) -> Dict[str, Any]:
        env = self.envelope(decision)
        for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
            if isinstance(env.get(key), dict):
                return self.strip_private_args(env[key])
        return self.strip_private_args(original)

    def authorize_manager_handoff(
        self,
        *,
        session_id: str,
        manager_agent_id: str,
        specialist_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        text: str = "",
        tool_platform: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_args = self.strip_private_args(tool_args)
        try:
            response = self._client_call_sync(
                self.client.a2a_authorize_tool,
                text=text or f"[{self.label}] {manager_agent_id} delegates {tool_name} to {specialist_agent_id}",
                agent_id=specialist_agent_id,
                platform=self.config.platform,
                source_agent_id=manager_agent_id,
                source_platform=self.config.platform,
                tool_platform=tool_platform or self.config.default_tool_platform,
                tool_name=tool_name,
                tool_args=clean_args,
                session_id=session_id,
                direction="outbound",
                policy_context=self._policy_context(
                    session_id,
                    f"{self.config.platform}_delegated_task",
                    policy_context,
                    delegation_chain=[manager_agent_id, specialist_agent_id],
                ),
            )
            env = self.envelope(response)
            if self.verdict(env) != "ALLOWED":
                raise self.denied_error(f"AgenticDome blocked {self.label} handoff: {self.reason(env)}")
            token = str(env.get("decision_token") or env.get("token") or "")
            if self.config.strict_delegated_execution and not token:
                raise self.denied_error("AgenticDome allowed the handoff but did not issue a decision token.")
            if token:
                self.token_store.put(
                    session_id=session_id,
                    target_agent_id=specialist_agent_id,
                    tool_name=tool_name,
                    tool_args=clean_args,
                    record=DecisionTokenRecord(token, manager_agent_id, time.time(), self._token_hmac(token)),
                    ttl_s=self.config.handoff_token_ttl_s,
                )
            return env
        except Exception as exc:
            return self._failure("handoff authorization", exc, {"verdict": "ALLOWED", "reason": "fail-open"})

    async def aauthorize_manager_handoff(self, **kwargs: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self.authorize_manager_handoff, **kwargs)

    def verify_specialist_execution(
        self,
        *,
        session_id: str,
        specialist_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        decision_token: Optional[str] = None,
        source_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_args = self.strip_private_args(tool_args)
        record = None
        if not decision_token:
            record = self.token_store.consume(
                session_id=session_id,
                target_agent_id=specialist_agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
            )
            if record:
                decision_token = record.decision_token
                source_agent_id = source_agent_id or record.source_agent_id
        if record and self.config.token_hmac_secret:
            expected = self._token_hmac(record.decision_token)
            if not record.token_hmac or not hmac.compare_digest(record.token_hmac, expected):
                raise self.denied_error("AgenticDome delegated decision-token HMAC is invalid.")
        if not decision_token or not source_agent_id:
            raise self.denied_error("Missing AgenticDome decision token or source agent for delegated execution.")
        try:
            response = self._client_call_sync(
                self.client.a2a_verify_decision_token_rpc,
                decision_token,
                tool_name=tool_name,
                tool_args=clean_args,
                agent_id=specialist_agent_id,
                source_agent_id=source_agent_id,
                platform=self.config.platform,
                session_id=session_id,
                require_allowed=True,
                consume=True,
            )
            env = self.envelope(response)
            if not bool(env.get("valid") or env.get("allowed")):
                raise self.denied_error(f"AgenticDome blocked delegated execution: {self.reason(env)}")
            return env
        except Exception as exc:
            return self._failure("delegation verification", exc, {"valid": True, "reason": "fail-open"})

    async def averify_specialist_execution(self, **kwargs: Any) -> Dict[str, Any]:
        return await asyncio.to_thread(self.verify_specialist_execution, **kwargs)

    def sanitize_output(self, *, session_id: str, agent_id: str, text: str, policy_context: Optional[Dict[str, Any]] = None) -> str:
        try:
            self._local_checks(agent_id, session_id, "output")
            response = self._client_call_sync(
                self.client.mesh_validate,
                text=self._bounded(text, self.config.max_output_chars, "OUTPUT"),
                agent_id=agent_id,
                platform=self.config.platform,
                direction="output",
                session_id=session_id,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._policy_context(session_id, f"{self.config.platform}_output_review", policy_context),
            )
            env = self.envelope(response)
            if self.verdict(env) == "BLOCKED":
                return "[OUTPUT BLOCKED BY AgenticDome]"
            value = env.get("text") or env.get("sanitized_text") or env.get("output")
            return str(value) if value is not None else text
        except Exception as exc:
            return self._failure("output sanitization", exc, text)

    async def asanitize_output(self, **kwargs: Any) -> str:
        return await asyncio.to_thread(self.sanitize_output, **kwargs)

    def review_value(self, value: Any, *, session_id: str, agent_id: str, policy_context: Optional[Dict[str, Any]] = None) -> Any:
        original = self.serialize(value)
        reviewed = self.sanitize_output(session_id=session_id, agent_id=agent_id, text=original, policy_context=policy_context)
        if isinstance(value, (dict, list)) and reviewed != "[OUTPUT BLOCKED BY AgenticDome]":
            if reviewed == original:
                return value
            try:
                return json.loads(reviewed)
            except Exception:
                pass
        return reviewed

    async def areview_value(self, value: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(self.review_value, value, **kwargs)

    def wrap_tool_handler(
        self,
        *,
        tool_name: str,
        handler: Callable[..., Any],
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_platform: Optional[str] = None,
        sanitize_output: bool = True,
    ) -> Callable[..., Any]:
        is_async = inspect.iscoroutinefunction(handler)

        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            call_args = self.normalize_args(kwargs if kwargs else (args[0] if len(args) == 1 and isinstance(args[0], dict) else {}))
            sid = self.session_id(session_id)
            aid = agent_id or self.config.agent_id
            decision = await self.aauthorize_tool_call(
                session_id=sid, agent_id=aid, tool_name=tool_name, tool_args=call_args,
                tool_platform=tool_platform, text=f"[{self.label}] {aid} calls {tool_name}",
            )
            clean = self.sanitized_args(decision, call_args)
            if kwargs:
                raw = await handler(*args, **clean)
            elif len(args) == 1 and isinstance(args[0], dict):
                raw = await handler(clean)
            else:
                raw = await handler(*args, **kwargs)
            return await self.areview_value(raw, session_id=sid, agent_id=aid, policy_context={"tool_name": tool_name}) if sanitize_output else raw

        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            call_args = self.normalize_args(kwargs if kwargs else (args[0] if len(args) == 1 and isinstance(args[0], dict) else {}))
            sid = self.session_id(session_id)
            aid = agent_id or self.config.agent_id
            decision = self.authorize_tool_call(
                session_id=sid, agent_id=aid, tool_name=tool_name, tool_args=call_args,
                tool_platform=tool_platform, text=f"[{self.label}] {aid} calls {tool_name}",
            )
            clean = self.sanitized_args(decision, call_args)
            if kwargs:
                raw = handler(*args, **clean)
            elif len(args) == 1 and isinstance(args[0], dict):
                raw = handler(clean)
            else:
                raw = handler(*args, **kwargs)
            return self.review_value(raw, session_id=sid, agent_id=aid, policy_context={"tool_name": tool_name}) if sanitize_output else raw

        wrapper = async_wrapper if is_async else sync_wrapper
        return functools.wraps(handler)(wrapper)

    def secure_tool(self, *, tool_name: Optional[str] = None, **options: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            return self.wrap_tool_handler(tool_name=tool_name or fn.__name__, handler=fn, **options)
        return decorator

