from __future__ import annotations

import asyncio
import functools
import hashlib
import inspect
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from threading import Lock
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from agenticdome_sdk.client import AgentGuardClient

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

    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:openai_agents:handoff"

    report_incidents: bool = True
    blocked_incident_severity: str = "medium"


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE", "https://au.agenticdome.io").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        platform=_env("AGENTICDOME_PLATFORM", "openai_agents_sdk"),
        default_tool_platform=_env("AGENTICDOME_TOOL_PLATFORM", _env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "openai_agents_sdk")),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
        redis_url=_env("AGENTICDOME_REDIS_URL", "").strip(),
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:openai_agents:handoff"),
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
        if not (self.config.api_base and self.config.api_key and self.config.tenant_id):
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

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass

    async def _call_sync(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(fn, *args, **kwargs)

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
        if self.config.require_explicit_session_id:
            raise OpenAIAgentsFirewallDenied("Missing session_id/run_id/trace_id in OpenAI Agents context.")
        return f"openai-agents-{uuid.uuid4().hex}"

    def _ctx_source_agent_id(self, ctx: Any) -> Optional[str]:
        value = self._ctx_attr(ctx, "source_agent_id") or self._ctx_attr(self._ctx_attr(ctx, "context", default=None), "source_agent_id")
        text = self._safe_str(value)
        return text or None

    def _policy_context(
        self,
        *,
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
        ctx.setdefault("platform", self.config.platform)
        if extra:
            ctx.update(extra)
        return ctx

    async def _report_incident_best_effort(self, *, agent_id: str, incident_type: str, details: str, severity: Optional[str] = None) -> None:
        if not self.config.report_incidents:
            return
        try:
            await self._call_sync(
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
            response = await self._call_sync(
                self.client.guardrail_validate,
                text=text,
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
    ) -> Dict[str, Any]:
        clean_args = self._strip_private_args(tool_args)
        effective_tool_platform = self._tool_platform(tool_platform, clean_args)
        try:
            response = await self._call_sync(
                self.client.guardrail_validate,
                text=text,
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
            return self._extract_result(response) or response
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
            response = await self._call_sync(
                self.client.a2a_authorize_tool,
                text=text or f"[OpenAI Agents] {manager_agent_id} delegates {tool_name} to {specialist_agent_id}",
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
                    record=DecisionTokenRecord(decision_token=decision_token, source_agent_id=manager_agent_id, created_at=time.time()),
                    ttl_s=self.config.handoff_token_ttl_s,
                )
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
            pending = self.token_store.get(
                session_id=session_id,
                target_agent_id=specialist_agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
            )
            if pending:
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
            response = await self._call_sync(
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
            return result
        except Exception as exc:
            await self._handle_failure("token verification", exc)
            return {}

    async def sanitize_output(self, *, session_id: str, agent_id: str, text: str, policy_context: Optional[Dict[str, Any]] = None) -> str:
        try:
            response = await self._call_sync(
                self.client.mesh_validate,
                text=text,
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
        if preserve_structured_output and isinstance(raw_result, (dict, list, tuple)) and sanitized == result_text:
            return raw_result
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
        async def secured(ctx: Any, args_json_or_dict: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args_json_or_dict)
            agent_id = self._ctx_agent_id(ctx)
            session_id = self._ctx_session_id(ctx)
            source_agent_id = self._ctx_source_agent_id(ctx)
            text = text_builder(ctx, tool_args) if text_builder else f"[OpenAI Agents] {agent_id} intends to call {tool_name}"
            policy_context = policy_context_builder(ctx, tool_args) if policy_context_builder else {"sdk": "openai_agents", "agent_name": agent_id}
            await self.authorize_direct_tool_call(
                session_id=session_id,
                agent_id=agent_id,
                source_agent_id=source_agent_id,
                tool_name=tool_name,
                tool_args=tool_args,
                text=text,
                tool_platform=tool_platform,
                policy_context=policy_context,
            )
            if inspect.iscoroutinefunction(handler):
                raw_result = await handler(ctx, self._strip_private_args(tool_args), *a, **kw)
            else:
                raw_result = await asyncio.to_thread(handler, ctx, self._strip_private_args(tool_args), *a, **kw)
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
    ) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_handler(
                tool_name=tool_name or getattr(handler, "__name__", "openai_agents_tool"),
                handler=handler,
                tool_platform=tool_platform,
                sanitize_output=sanitize_output,
                preserve_structured_output=preserve_structured_output,
            )
        return decorator

    def _extract_runner_result_text(self, result: Any) -> str:
        for attr in ("final_output", "output", "text", "content"):
            value = getattr(result, attr, None)
            if value is not None:
                return self._serialize_for_review(value)
        return self._serialize_for_review(result)

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
