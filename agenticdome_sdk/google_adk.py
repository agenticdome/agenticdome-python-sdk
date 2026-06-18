
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
    sanitize_model_output: bool = True
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
        platform=_env("AGENTICDOME_PLATFORM", "google_adk"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "google_adk"),
        default_agent_id=_env("AGENTICDOME_GOOGLE_ADK_AGENT_ID", "google_adk_agent"),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        sanitize_model_output=_env_bool("AGENTICDOME_SANITIZE_MODEL_OUTPUT", True),
        sanitize_tool_output=_env_bool("AGENTICDOME_SANITIZE_TOOL_OUTPUT", True),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
    )


class GoogleADKFirewallError(RuntimeError):
    """Base Google ADK firewall exception."""


class GoogleADKConfigurationError(GoogleADKFirewallError):
    """Raised when required AgenticDome configuration is missing."""


class GoogleADKDenied(GoogleADKFirewallError):
    """Raised when AgenticDome blocks or fail-closes an ADK operation."""


class AgenticDomeGoogleADKFirewall:
    """AgenticDome firewall for Google ADK model/tool callback boundaries."""

    def __init__(self, *, config: Optional[FirewallConfig] = None, client: Optional[AgentGuardClient] = None) -> None:
        self.config = config or load_config()
        if client is None and not (self.config.api_base and self.config.api_key and self.config.tenant_id):
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

    def close(self) -> None:
        close = getattr(self.client, "close", None)
        if callable(close):
            close()

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
        if self.config.require_explicit_session_id:
            raise GoogleADKDenied("Missing session_id/run_id/trace_id in Google ADK context.")
        return f"google-adk-{uuid.uuid4().hex}"

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
            response = await self._to_thread(
                self.client.guardrail_validate,
                text=text,
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="input",
                session_id=session_id,
                policy_context=self._policy_context(agent_id=agent_id, session_id=session_id, request_purpose="google_adk.before_model"),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_prompt_input", details=reason)
                raise GoogleADKDenied(f"AgenticDome blocked Google ADK model request: {reason}")
            return response
        except Exception as exc:
            await self._handle_error(exc, "screen_model_request")
            return {}

    async def authorize_tool_call(self, *, tool_name: str, tool_args: Dict[str, Any], tool_context: Any, text: Optional[str] = None, tool_platform: Optional[str] = None) -> Dict[str, Any]:
        agent_id = self._agent_id(tool_context)
        session_id = self._session_id(tool_context)
        effective_tool_platform = tool_platform or tool_args.get("tool_platform") or tool_args.get("platform") or self.config.default_tool_platform
        try:
            response = await self._to_thread(
                self.client.guardrail_validate,
                text=text or f"[Google ADK] {agent_id} intends to execute {tool_name}",
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="outbound",
                session_id=session_id,
                tool_platform=self._safe_str(effective_tool_platform),
                tool_name=tool_name,
                tool_args=tool_args,
                policy_context=self._policy_context(
                    agent_id=agent_id,
                    session_id=session_id,
                    request_purpose="google_adk.before_tool",
                    extra={"tool_name": tool_name, "tool_platform": effective_tool_platform},
                ),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=agent_id, incident_type="blocked_tool_execution", details=reason)
                raise GoogleADKDenied(f"AgenticDome blocked Google ADK tool execution: {reason}")
            return response
        except Exception as exc:
            await self._handle_error(exc, "authorize_tool_call")
            return {}

    async def sanitize_text(self, *, text: str, agent_id: str, session_id: str, request_purpose: str = "google_adk.output_review") -> str:
        try:
            response = await self._to_thread(
                self.client.mesh_validate,
                text=text,
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
        tool_name = self._safe_str(getattr(tool, "name", None) or getattr(tool, "__name__", None) or tool or "unknown_tool")
        await self.authorize_tool_call(tool_name=tool_name, tool_args=self._normalize_args(args), tool_context=tool_context)
        return None

    async def after_tool(self, tool: Any, args: Any = None, tool_context: Any = None, tool_response: Any = None) -> Any:
        if not self.config.sanitize_tool_output:
            return tool_response
        agent_id = self._agent_id(tool_context)
        session_id = self._session_id(tool_context)
        text = self._serialize_for_review(tool_response)
        sanitized = await self.sanitize_text(text=text, agent_id=agent_id, session_id=session_id, request_purpose="google_adk.after_tool")
        if isinstance(tool_response, (dict, list, tuple)) and sanitized == text:
            return tool_response
        return sanitized

    def _run_sync(self, coro: Awaitable[Any]) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        raise GoogleADKDenied("Synchronous Google ADK callback called inside a running event loop; register the async callback methods instead.")

    def before_model_callback(self, callback_context: Any, llm_request: Any) -> None:
        return self._run_sync(self.before_model(callback_context, llm_request))

    def after_model_callback(self, callback_context: Any, llm_response: Any) -> Any:
        return self._run_sync(self.after_model(callback_context, llm_response))

    def before_tool_callback(self, tool: Any, args: Any = None, tool_context: Any = None) -> None:
        return self._run_sync(self.before_tool(tool, args, tool_context))

    def after_tool_callback(self, tool: Any, args: Any = None, tool_context: Any = None, tool_response: Any = None) -> Any:
        return self._run_sync(self.after_tool(tool, args, tool_context, tool_response))

    def install_on_agent(self, agent: Any, *, prefer_async: bool = True, overwrite: bool = True) -> Any:
        mapping = {
            "before_model_callback": self.before_model if prefer_async else self.before_model_callback,
            "after_model_callback": self.after_model if prefer_async else self.after_model_callback,
            "before_tool_callback": self.before_tool if prefer_async else self.before_tool_callback,
            "after_tool_callback": self.after_tool if prefer_async else self.after_tool_callback,
        }
        for name, fn in mapping.items():
            if overwrite or not getattr(agent, name, None):
                setattr(agent, name, fn)
        return agent

    def _apply_text(self, value: Any, text: str) -> Any:
        out = value
        for attr in ("text", "content", "output", "message"):
            try:
                if hasattr(out, attr):
                    setattr(out, attr, text)
                    return out
            except Exception:
                pass
        if isinstance(value, dict):
            out = dict(value)
            for key in ("text", "content", "output", "message"):
                if key in out:
                    out[key] = text
                    return out
        return text

    def wrap_tool_handler(self, *, tool_name: str, handler: Callable[..., Any], tool_platform: Optional[str] = None) -> Callable[..., Awaitable[Any]]:
        async def secured(tool_context: Any, args: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args)
            await self.authorize_tool_call(tool_name=tool_name, tool_args=tool_args, tool_context=tool_context, tool_platform=tool_platform)
            result = handler(tool_context, tool_args, *a, **kw)
            if isawaitable(result):
                result = await result
            if not self.config.sanitize_tool_output:
                return result
            return await self.after_tool(tool_name, tool_args, tool_context, result)
        return secured

    def secure_tool(self, *, tool_name: str, tool_platform: Optional[str] = None) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_handler(tool_name=tool_name, handler=handler, tool_platform=tool_platform)
        return decorator


__all__ = [
    "AgenticDomeGoogleADKFirewall",
    "FirewallConfig",
    "GoogleADKConfigurationError",
    "GoogleADKDenied",
    "GoogleADKFirewallError",
    "load_config",
]
