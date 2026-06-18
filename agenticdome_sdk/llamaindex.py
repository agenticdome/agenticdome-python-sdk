
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from inspect import isawaitable
from typing import Any, Awaitable, Callable, Dict, Optional

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
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
    )


class LlamaIndexFirewallError(RuntimeError):
    """Base LlamaIndex firewall exception."""


class LlamaIndexConfigurationError(LlamaIndexFirewallError):
    """Raised when required AgenticDome configuration is missing."""


class LlamaIndexDenied(LlamaIndexFirewallError):
    """Raised when AgenticDome blocks or fail-closes a LlamaIndex operation."""


class AgenticDomeLlamaIndexFirewall:
    """AgenticDome firewall for LlamaIndex tools, query engines, retrievers, and outputs."""

    def __init__(self, *, config: Optional[FirewallConfig] = None, client: Optional[AgentGuardClient] = None) -> None:
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

    def _session_id(self, session_id: Optional[str]) -> str:
        if session_id:
            return self._safe_str(session_id)
        if self.config.require_explicit_session_id:
            raise LlamaIndexDenied("Missing session_id for LlamaIndex operation.")
        return f"llamaindex-{uuid.uuid4().hex}"

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

    async def authorize_tool_call(self, *, tool_name: str, tool_args: Dict[str, Any], agent_id: Optional[str] = None, session_id: Optional[str] = None, text: Optional[str] = None, tool_platform: Optional[str] = None) -> Dict[str, Any]:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(session_id)
        effective_tool_platform = tool_platform or tool_args.get("tool_platform") or tool_args.get("platform") or self.config.default_tool_platform
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
                tool_args=tool_args,
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

    async def run_query_securely(self, *, query_callable: Callable[..., Any], query_text: str, agent_id: Optional[str] = None, session_id: Optional[str] = None, sanitize_output: Optional[bool] = None, **kwargs: Any) -> Any:
        await self.screen_input(text=query_text, agent_id=agent_id, session_id=session_id)
        result = query_callable(query_text, **kwargs)
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
        text = self._serialize_for_review(retrieval_result)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, request_purpose="llamaindex.retrieval_result")
        if isinstance(retrieval_result, (dict, list, tuple)) and sanitized == text:
            return retrieval_result
        try:
            return json.loads(sanitized)
        except Exception:
            return sanitized


__all__ = [
    "AgenticDomeLlamaIndexFirewall",
    "FirewallConfig",
    "LlamaIndexConfigurationError",
    "LlamaIndexDenied",
    "LlamaIndexFirewallError",
    "load_config",
]
