
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from inspect import isawaitable
from threading import Lock
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

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


logger = logging.getLogger("agenticdome.llamaindex")
logger.setLevel(logging.INFO)


@dataclass(frozen=True)
class FirewallConfig:
    api_base: str
    api_key: str
    tenant_id: str
    platform: str = "llamaindex"
    default_tool_platform: str = "llamaindex"
    default_agent_id: str = "llamaindex_agent"
    timeout_s: int = 20
    fail_closed: bool = True
    require_explicit_session_id: bool = False
    sanitize_query_output: bool = True
    sanitize_tool_output: bool = True
    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False
    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:llamaindex:handoff"
    report_incidents: bool = True
    blocked_incident_severity: str = "medium"


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE", "https://au.agenticdome.io").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        platform=_env("AGENTICDOME_PLATFORM", "llamaindex"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "llamaindex"),
        default_agent_id=_env("AGENTICDOME_LLAMAINDEX_AGENT_ID", "llamaindex_agent"),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        sanitize_query_output=_env_bool("AGENTICDOME_SANITIZE_QUERY_OUTPUT", True),
        sanitize_tool_output=_env_bool("AGENTICDOME_SANITIZE_TOOL_OUTPUT", True),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
        redis_url=_env("AGENTICDOME_REDIS_URL", "").strip(),
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:llamaindex:handoff"),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
    )


class LlamaIndexFirewallError(RuntimeError):
    """Base LlamaIndex firewall exception."""


class LlamaIndexConfigurationError(LlamaIndexFirewallError):
    """Raised when required AgenticDome configuration is missing."""


class LlamaIndexDenied(LlamaIndexFirewallError):
    """Raised when AgenticDome blocks or fail-closes a LlamaIndex operation."""


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

    def get(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        with self._lock:
            self._cleanup()
            entry = self._data.get(key)
            return entry[1] if entry else None

    def delete(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> None:
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
        payload = {
            "decision_token": record.decision_token,
            "source_agent_id": record.source_agent_id,
            "created_at": record.created_at,
        }
        self._client.setex(key, ttl_s, _canonical_json(payload))

    def get(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> Optional[DecisionTokenRecord]:
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

    def delete(self, *, session_id: str, target_agent_id: str, tool_name: str, tool_args: Dict[str, Any]) -> None:
        key = self._key(session_id=session_id, target_agent_id=target_agent_id, tool_name=tool_name, tool_args=tool_args)
        self._client.delete(key)


def _build_token_store(config: FirewallConfig) -> DecisionTokenStore:
    if config.redis_url:
        try:
            logger.info("AgenticDome LlamaIndex firewall using Redis token store.")
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id)
        except Exception as exc:
            logger.warning("Redis token store unavailable; falling back to memory. reason=%s", exc)
    return InMemoryDecisionTokenStore(config.tenant_id)


class AgenticDomeLlamaIndexFirewall:
    """AgenticDome firewall for LlamaIndex tools, query engines, retrievers, callbacks, and handoffs."""

    def __init__(
        self,
        *,
        config: Optional[FirewallConfig] = None,
        client: Optional[AgentGuardClient] = None,
        token_store: Optional[DecisionTokenStore] = None,
    ) -> None:
        self.config = config or load_config()
        if client is None and not (self.config.api_base and self.config.api_key and self.config.tenant_id):
            raise LlamaIndexConfigurationError(
                "AgenticDome LlamaIndex firewall misconfigured. Set AGENTICDOME_API_BASE, "
                "AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
            )
        self.client = client or AgentGuardClient(
            api_base=self.config.api_base,
            api_key=self.config.api_key,
            tenant_id=self.config.tenant_id,
            timeout=self.config.timeout_s,
        )
        self.token_store = token_store or _build_token_store(self.config)

    async def _to_thread(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
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
            return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        return AgenticDomeLlamaIndexFirewall._safe_str(value)

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
        return {"_raw": AgenticDomeLlamaIndexFirewall._safe_str(raw)}

    @staticmethod
    def _strip_private_args(args: Dict[str, Any]) -> Dict[str, Any]:
        private_keys = {
            "decision_token",
            "AgenticDome_decision_token",
            "_AgenticDome_decision_token",
            "_decision_token",
            "source_agent_id",
            "AgenticDome_source_agent_id",
            "_AgenticDome_source_agent_id",
            "_source_agent_id",
        }
        return {key: value for key, value in (args or {}).items() if key not in private_keys}

    @staticmethod
    def _node_text(node: Any) -> str:
        for method_name in ("get_content", "get_text"):
            method = getattr(node, method_name, None)
            if callable(method):
                try:
                    return AgenticDomeLlamaIndexFirewall._safe_str(method())
                except Exception:
                    pass
        inner = getattr(node, "node", None)
        if inner is not None:
            text = AgenticDomeLlamaIndexFirewall._node_text(inner)
            if text:
                return text
        for attr in ("text", "content"):
            value = getattr(node, attr, None)
            if value is not None:
                return AgenticDomeLlamaIndexFirewall._safe_str(value)
        return AgenticDomeLlamaIndexFirewall._safe_str(node)

    @staticmethod
    def _set_node_text(node: Any, text: str) -> Any:
        for target in (node, getattr(node, "node", None)):
            if target is None:
                continue
            setter = getattr(target, "set_content", None)
            if callable(setter):
                try:
                    setter(text)
                    return node
                except Exception:
                    pass
            for attr in ("text", "content"):
                if hasattr(target, attr):
                    try:
                        setattr(target, attr, text)
                        return node
                    except Exception:
                        pass
        return text

    def _session_id(self, session_id: Optional[str]) -> str:
        if session_id:
            return self._safe_str(session_id)
        if self.config.require_explicit_session_id:
            raise LlamaIndexDenied("Missing session_id for LlamaIndex operation.")
        return f"llamaindex-{uuid.uuid4().hex}"

    def _run_sync(self, awaitable: Awaitable[Any]) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(awaitable)
        close = getattr(awaitable, "close", None)
        if callable(close):
            close()
        raise LlamaIndexDenied(
            "Synchronous LlamaIndex wrapper called inside a running event loop; use the async LlamaIndex method instead."
        )

    def _policy_context(self, *, agent_id: str, session_id: str, request_purpose: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ctx = {
            "request_id": str(uuid.uuid4()),
            "request_ts_ms": int(time.time() * 1000),
            "request_purpose": request_purpose,
            "session_id": session_id,
            "source_agent_id": agent_id,
            "platform": self.config.platform,
        }
        if extra:
            ctx.update(extra)
        return ctx

    def _decision_view(self, payload: Any) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        for candidate in (payload, payload.get("result"), payload.get("decision"), payload.get("analysis")):
            if isinstance(candidate, dict) and any(k in candidate for k in ("verdict", "decision", "blocked", "allowed", "reason", "valid")):
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

    def _is_allowed(self, payload: Any) -> bool:
        view = self._decision_view(payload)
        if "allowed" in view:
            return bool(view["allowed"])
        if "valid" in view:
            return bool(view["valid"])
        verdict = self._safe_str(view.get("verdict") or view.get("decision")).upper()
        return verdict in {"ALLOWED", "ALLOW", "APPROVED", "VALID"}

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
            await self._to_thread(
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

    def _report_incident_sync_best_effort(self, *, agent_id: str, incident_type: str, details: str, severity: Optional[str] = None) -> None:
        if not self.config.report_incidents:
            return
        try:
            self.client.report_incident(
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
        if isinstance(exc, LlamaIndexDenied):
            raise exc
        if self.config.fail_closed:
            raise LlamaIndexDenied(f"AgenticDome fail-closed: {context}: {exc}") from exc
        logger.warning("AgenticDome fail-open: %s: %s", context, exc)

    async def screen_input(self, *, text: str, agent_id: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(session_id)
        try:
            response = await self._to_thread(
                self.client.guardrail_validate,
                text=text,
                agent_id=effective_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="input",
                session_id=effective_session_id,
                policy_context=self._policy_context(agent_id=effective_agent_id, session_id=effective_session_id, request_purpose="llamaindex.input"),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=effective_agent_id, incident_type="blocked_prompt_input", details=reason)
                raise LlamaIndexDenied(f"AgenticDome blocked LlamaIndex input: {reason}")
            return response
        except Exception as exc:
            await self._handle_error(exc, "screen_input")
            return {}

    async def authorize_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        text: Optional[str] = None,
        tool_platform: Optional[str] = None,
    ) -> Dict[str, Any]:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(session_id)
        clean_args = self._strip_private_args(tool_args)
        effective_tool_platform = tool_platform or clean_args.get("tool_platform") or clean_args.get("platform") or self.config.default_tool_platform
        try:
            response = await self._to_thread(
                self.client.guardrail_validate,
                text=text or f"[LlamaIndex] {effective_agent_id} intends to execute {tool_name}",
                agent_id=effective_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="outbound",
                session_id=effective_session_id,
                tool_platform=self._safe_str(effective_tool_platform),
                tool_name=tool_name,
                tool_args=clean_args,
                policy_context=self._policy_context(
                    agent_id=effective_agent_id,
                    session_id=effective_session_id,
                    request_purpose="llamaindex.tool_execution",
                    extra={"tool_name": tool_name, "tool_platform": effective_tool_platform},
                ),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=effective_agent_id, incident_type="blocked_tool_execution", details=reason)
                raise LlamaIndexDenied(f"AgenticDome blocked LlamaIndex tool execution: {reason}")
            return response
        except Exception as exc:
            await self._handle_error(exc, "authorize_tool_call")
            return {}

    async def sanitize_text(self, *, text: str, agent_id: Optional[str] = None, session_id: Optional[str] = None, request_purpose: str = "llamaindex.output") -> str:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(session_id)
        try:
            response = await self._to_thread(
                self.client.mesh_validate,
                text=text,
                agent_id=effective_agent_id,
                direction="output",
                session_id=effective_session_id,
                platform=self.config.platform,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._policy_context(agent_id=effective_agent_id, session_id=effective_session_id, request_purpose=request_purpose),
            )
            if self._is_blocked(response):
                await self._report_incident_best_effort(agent_id=effective_agent_id, incident_type="blocked_output", details=self._reason(response))
                return "[OUTPUT BLOCKED BY AgenticDome]"
            sanitized = self._sanitized_text(response)
            return sanitized if sanitized is not None else text
        except Exception as exc:
            await self._handle_error(exc, "sanitize_text")
            return text

    async def authorize_manager_handoff(
        self,
        *,
        manager_agent_id: str,
        specialist_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_id: Optional[str] = None,
        text: Optional[str] = None,
        tool_platform: Optional[str] = None,
    ) -> Dict[str, Any]:
        effective_session_id = self._session_id(session_id)
        clean_args = self._strip_private_args(tool_args)
        effective_tool_platform = tool_platform or clean_args.get("tool_platform") or clean_args.get("platform") or self.config.default_tool_platform
        try:
            response = await self._to_thread(
                self.client.a2a_authorize_tool,
                text=text or f"[LlamaIndex] {manager_agent_id} delegates {tool_name} to {specialist_agent_id}",
                agent_id=specialist_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform=self._safe_str(effective_tool_platform),
                tool_name=tool_name,
                tool_args=clean_args,
                session_id=effective_session_id,
                direction="outbound",
                source_agent_id=manager_agent_id,
                policy_context=self._policy_context(
                    agent_id=manager_agent_id,
                    session_id=effective_session_id,
                    request_purpose="llamaindex.delegated_task",
                    extra={
                        "target_agent_id": specialist_agent_id,
                        "delegation_chain": [manager_agent_id, specialist_agent_id],
                        "tool_platform": effective_tool_platform,
                    },
                ),
            )
            if not self._is_allowed(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=manager_agent_id, incident_type="blocked_delegation", details=reason)
                raise LlamaIndexDenied(f"AgenticDome blocked LlamaIndex handoff: {reason}")
            view = self._decision_view(response)
            decision_token = self._safe_str(view.get("decision_token") or view.get("token"))
            if decision_token:
                self.token_store.put(
                    session_id=effective_session_id,
                    target_agent_id=specialist_agent_id,
                    tool_name=tool_name,
                    tool_args=clean_args,
                    record=DecisionTokenRecord(decision_token=decision_token, source_agent_id=manager_agent_id, created_at=time.time()),
                    ttl_s=self.config.handoff_token_ttl_s,
                )
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
        session_id: Optional[str] = None,
        decision_token: Optional[str] = None,
        source_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        effective_session_id = self._session_id(session_id)
        clean_args = self._strip_private_args(tool_args)
        token = decision_token
        source = source_agent_id
        if not token:
            pending = self.token_store.get(
                session_id=effective_session_id,
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
            raise LlamaIndexDenied("Missing AgenticDome decision token or source_agent_id for delegated LlamaIndex execution.")
        try:
            response = await self._to_thread(
                self.client.a2a_verify_decision_token_rpc,
                token,
                tool_name=tool_name,
                tool_args=clean_args,
                agent_id=specialist_agent_id,
                source_agent_id=source,
                platform=self.config.platform,
                require_allowed=True,
            )
            if not self._is_allowed(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=specialist_agent_id, incident_type="invalid_delegation_token", details=reason, severity="high")
                raise LlamaIndexDenied(f"AgenticDome blocked delegated LlamaIndex execution: {reason}")
            self.token_store.delete(
                session_id=effective_session_id,
                target_agent_id=specialist_agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
            )
            return response
        except Exception as exc:
            await self._handle_error(exc, "verify_delegated_execution")
            return {}

    async def verify_specialist_execution(self, **kwargs: Any) -> Dict[str, Any]:
        return await self.verify_delegated_execution(**kwargs)

    def wrap_tool_function(self, fn: Callable[..., Any], *, tool_name: Optional[str] = None, tool_platform: Optional[str] = None, agent_id: Optional[str] = None, session_id: Optional[str] = None) -> Callable[..., Awaitable[Any]]:
        name = tool_name or getattr(fn, "__name__", "llamaindex_tool")
        signature = inspect.signature(fn)

        async def secured(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind_partial(*args, **kwargs)
            bound.apply_defaults()
            tool_args = dict(bound.arguments)
            await self.authorize_tool_call(tool_name=name, tool_args=tool_args, agent_id=agent_id, session_id=session_id, tool_platform=tool_platform)
            result = fn(*args, **kwargs)
            if isawaitable(result):
                result = await result
            if not self.config.sanitize_tool_output:
                return result
            text = self._serialize_for_review(result)
            sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, request_purpose="llamaindex.tool_output")
            if isinstance(result, (dict, list, tuple)) and sanitized == text:
                return result
            return sanitized

        secured.__name__ = getattr(fn, "__name__", "secured_llamaindex_tool")
        secured.__doc__ = getattr(fn, "__doc__", None)
        return secured

    def secure_tool(self, *, tool_name: Optional[str] = None, tool_platform: Optional[str] = None, agent_id: Optional[str] = None, session_id: Optional[str] = None) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_function(fn, tool_name=tool_name, tool_platform=tool_platform, agent_id=agent_id, session_id=session_id)
        return decorator

    def to_function_tool(self, fn: Callable[..., Any], *, tool_name: Optional[str] = None, description: Optional[str] = None, tool_platform: Optional[str] = None, agent_id: Optional[str] = None, session_id: Optional[str] = None, **kwargs: Any) -> Any:
        from llama_index.core.tools import FunctionTool
        secured = self.wrap_tool_function(fn, tool_name=tool_name, tool_platform=tool_platform, agent_id=agent_id, session_id=session_id)
        return FunctionTool.from_defaults(async_fn=secured, name=tool_name or getattr(fn, "__name__", None), description=description, **kwargs)

    async def run_query_securely(
        self,
        *,
        query_callable: Callable[..., Any],
        query_text: str,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        sanitize_output: Optional[bool] = None,
        query_args: Optional[Tuple[Any, ...]] = None,
        **kwargs: Any,
    ) -> Any:
        await self.screen_input(text=query_text, agent_id=agent_id, session_id=session_id)
        result = query_callable(query_text, *(query_args or ()), **kwargs)
        if isawaitable(result):
            result = await result
        should_sanitize = self.config.sanitize_query_output if sanitize_output is None else sanitize_output
        if not should_sanitize:
            return result
        text = self._serialize_for_review(result)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, request_purpose="llamaindex.query_output")
        if isinstance(result, (dict, list, tuple)) and sanitized == text:
            return result
        return sanitized

    async def sanitize_retrieval_result(self, *, retrieval_result: Any, agent_id: Optional[str] = None, session_id: Optional[str] = None) -> Any:
        if isinstance(retrieval_result, list):
            sanitized_nodes = []
            for node in retrieval_result:
                text = self._node_text(node)
                sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, request_purpose="llamaindex.retrieval_result")
                sanitized_nodes.append(node if sanitized == text else self._set_node_text(node, sanitized))
            return sanitized_nodes

        text = self._serialize_for_review(retrieval_result)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, request_purpose="llamaindex.retrieval_result")
        if isinstance(retrieval_result, (dict, tuple)) and sanitized == text:
            return retrieval_result
        try:
            return json.loads(sanitized)
        except Exception:
            return sanitized

    def wrap_query_engine(self, query_engine: Any, *, agent_id: Optional[str] = None, session_id: Optional[str] = None, sanitize_output: Optional[bool] = None) -> Any:
        firewall = self

        class SecureQueryEngine:
            def __getattr__(self, name: str) -> Any:
                return getattr(query_engine, name)

            def query(self, query_text: str, *args: Any, **kwargs: Any) -> Any:
                return firewall._run_sync(
                    firewall.run_query_securely(
                        query_callable=query_engine.query,
                        query_text=query_text,
                        agent_id=agent_id,
                        session_id=session_id,
                        sanitize_output=sanitize_output,
                        query_args=args,
                        **kwargs,
                    )
                )

            async def aquery(self, query_text: str, *args: Any, **kwargs: Any) -> Any:
                callable_ = getattr(query_engine, "aquery", query_engine.query)
                return await firewall.run_query_securely(
                    query_callable=callable_,
                    query_text=query_text,
                    agent_id=agent_id,
                    session_id=session_id,
                    sanitize_output=sanitize_output,
                    query_args=args,
                    **kwargs,
                )

            def chat(self, message: str, *args: Any, **kwargs: Any) -> Any:
                return firewall._run_sync(
                    firewall.run_query_securely(
                        query_callable=query_engine.chat,
                        query_text=message,
                        agent_id=agent_id,
                        session_id=session_id,
                        sanitize_output=sanitize_output,
                        query_args=args,
                        **kwargs,
                    )
                )

            async def achat(self, message: str, *args: Any, **kwargs: Any) -> Any:
                callable_ = getattr(query_engine, "achat", query_engine.chat)
                return await firewall.run_query_securely(
                    query_callable=callable_,
                    query_text=message,
                    agent_id=agent_id,
                    session_id=session_id,
                    sanitize_output=sanitize_output,
                    query_args=args,
                    **kwargs,
                )

        return SecureQueryEngine()

    def wrap_retriever(self, retriever: Any, *, agent_id: Optional[str] = None, session_id: Optional[str] = None) -> Any:
        firewall = self

        class SecureRetriever:
            def __getattr__(self, name: str) -> Any:
                return getattr(retriever, name)

            def retrieve(self, query: Any, *args: Any, **kwargs: Any) -> Any:
                result = retriever.retrieve(query, *args, **kwargs)
                return firewall._run_sync(firewall.sanitize_retrieval_result(retrieval_result=result, agent_id=agent_id, session_id=session_id))

            async def aretrieve(self, query: Any, *args: Any, **kwargs: Any) -> Any:
                callable_ = getattr(retriever, "aretrieve", retriever.retrieve)
                result = callable_(query, *args, **kwargs)
                if isawaitable(result):
                    result = await result
                return await firewall.sanitize_retrieval_result(retrieval_result=result, agent_id=agent_id, session_id=session_id)

        return SecureRetriever()

    def create_node_postprocessor(self, *, agent_id: Optional[str] = None, session_id: Optional[str] = None) -> Any:
        firewall = self

        class AgenticDomeNodePostprocessor:
            def postprocess_nodes(self, nodes: List[Any], query_bundle: Any = None, **_: Any) -> List[Any]:
                return firewall._run_sync(firewall.sanitize_retrieval_result(retrieval_result=nodes, agent_id=agent_id, session_id=session_id))

            async def _apostprocess_nodes(self, nodes: List[Any], query_bundle: Any = None, **_: Any) -> List[Any]:
                return await firewall.sanitize_retrieval_result(retrieval_result=nodes, agent_id=agent_id, session_id=session_id)

        return AgenticDomeNodePostprocessor()

    def create_callback_handler(self, *, agent_id: Optional[str] = None, session_id: Optional[str] = None, enforce_input: bool = False) -> Any:
        firewall = self
        effective_agent_id = agent_id or self.config.default_agent_id
        try:
            from llama_index.core.callbacks.base import BaseCallbackHandler
        except Exception:  # pragma: no cover - LlamaIndex is an optional dependency.
            BaseCallbackHandler = object  # type: ignore

        class AgenticDomeCallbackHandler(BaseCallbackHandler):  # type: ignore[misc, valid-type]
            def __init__(self) -> None:
                if BaseCallbackHandler is object:
                    self.event_starts_to_ignore = []
                    self.event_ends_to_ignore = []
                    return
                try:
                    super().__init__(event_starts_to_ignore=[], event_ends_to_ignore=[])
                except TypeError:
                    super().__init__()
                    self.event_starts_to_ignore = []
                    self.event_ends_to_ignore = []

            def start_trace(self, trace_id: Optional[str] = None) -> None:
                logger.info("AgenticDome LlamaIndex trace started. trace_id=%s agent_id=%s", trace_id, effective_agent_id)

            def end_trace(self, trace_id: Optional[str] = None, trace_map: Optional[Dict[str, Any]] = None) -> None:
                logger.info("AgenticDome LlamaIndex trace ended. trace_id=%s agent_id=%s", trace_id, effective_agent_id)

            def on_event_start(self, event_type: Any, payload: Optional[Dict[str, Any]] = None, event_id: str = "", parent_id: str = "", **_: Any) -> str:
                payload = payload or {}
                logger.info("AgenticDome LlamaIndex event start. event_type=%s event_id=%s parent_id=%s", event_type, event_id, parent_id)
                if not enforce_input:
                    return event_id
                text = firewall._safe_str(payload.get("query_str") or payload.get("query") or payload.get("messages") or payload.get("prompt") or "")
                if not text.strip():
                    return event_id
                effective_session_id = firewall._session_id(session_id)
                try:
                    response = firewall.client.guardrail_validate(
                        text=text,
                        agent_id=effective_agent_id,
                        platform=firewall.config.platform,
                        source_platform=firewall.config.platform,
                        direction="input",
                        session_id=effective_session_id,
                        policy_context=firewall._policy_context(
                            agent_id=effective_agent_id,
                            session_id=effective_session_id,
                            request_purpose="llamaindex.callback_input",
                            extra={"event_type": firewall._safe_str(event_type), "event_id": event_id, "parent_id": parent_id},
                        ),
                    )
                    if firewall._is_blocked(response):
                        reason = firewall._reason(response)
                        firewall._report_incident_sync_best_effort(agent_id=effective_agent_id, incident_type="blocked_callback_input", details=reason)
                        raise LlamaIndexDenied(f"AgenticDome blocked LlamaIndex callback input: {reason}")
                except LlamaIndexDenied:
                    raise
                except Exception as exc:
                    if firewall.config.fail_closed:
                        raise LlamaIndexDenied(f"AgenticDome fail-closed: callback input: {exc}") from exc
                    logger.warning("AgenticDome fail-open: callback input: %s", exc)
                return event_id

            def on_event_end(self, event_type: Any, payload: Optional[Dict[str, Any]] = None, event_id: str = "", **_: Any) -> None:
                payload = payload or {}
                logger.info("AgenticDome LlamaIndex event end. event_type=%s event_id=%s", event_type, event_id)
                error = payload.get("exception") or payload.get("error")
                if error:
                    firewall._report_incident_sync_best_effort(
                        agent_id=effective_agent_id,
                        incident_type="llamaindex_callback_error",
                        details=firewall._safe_str(error),
                        severity="low",
                    )

        return AgenticDomeCallbackHandler()


__all__ = [
    "AgenticDomeLlamaIndexFirewall",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "FirewallConfig",
    "InMemoryDecisionTokenStore",
    "LlamaIndexConfigurationError",
    "LlamaIndexDenied",
    "LlamaIndexFirewallError",
    "RedisDecisionTokenStore",
    "load_config",
]
