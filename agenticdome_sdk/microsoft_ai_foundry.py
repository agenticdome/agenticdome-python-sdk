from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional

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

    api_version: str = "2025-09-01"

    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    report_incidents: bool = True
    blocked_incident_severity: str = "medium"


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE", "https://au.agenticdome.io").rstrip("/"),
        bearer_token=(
            _env("AGENTICDOME_BEARER_TOKEN", "")
            or _env("AGENTGUARD_BEARER_TOKEN", "")
            or _env("AZURE_AI_FOUNDRY_AGENTICDOME_BEARER_TOKEN", "")
        ),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        platform=_env("AGENTICDOME_PLATFORM", "microsoft_ai_foundry"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "microsoft_ai_foundry"),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        api_version=_env("AGENTICDOME_COPILOT_API_VERSION", "2025-09-01"),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
    )


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
        if not self.config.api_base or not self.config.bearer_token:
            raise MicrosoftAIFoundryConfigurationError(
                "AgenticDome Microsoft AI Foundry firewall misconfigured. "
                "Set AGENTICDOME_API_BASE and AGENTICDOME_BEARER_TOKEN."
            )

        self.client = client or AgentGuardClient(
            api_base=self.config.api_base,
            api_key=self.config.api_key,
            tenant_id=self.config.tenant_id or None,
            bearer_token=self.config.bearer_token,
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
        if self.config.require_explicit_session_id:
            raise MicrosoftAIFoundryDenied("Missing session_id/run_id/trace_id in Microsoft AI Foundry context.")
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
            response = await self._to_thread(
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
            return response
        except Exception as exc:
            await self._handle_error(exc, "validate_prompt_contract")
            return {}

    async def analyze_tool_execution(self, *, payload: Dict[str, Any], agent_id: str) -> Dict[str, Any]:
        try:
            response = await self._to_thread(
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
        if not self.config.api_key:
            logger.info("AgenticDome Mesh skipped for Microsoft AI Foundry: no AGENTICDOME_API_KEY configured.")
            return text
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
            return sanitized if sanitized is not None else text
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
        if preserve_structured_output and isinstance(raw_result, (dict, list, tuple)) and sanitized == result_text:
            return raw_result
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
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
    ) -> Callable[..., Awaitable[Any]]:
        async def secured(ctx: Any, args: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args)
            agent_id = self._agent_id(ctx)
            session_id = self._session_id(ctx)
            user_id = self._user_id(ctx)
            prompt_text = (
                text_builder(ctx, tool_args)
                if text_builder
                else self._prompt_text(ctx) or f"[Microsoft AI Foundry] {agent_id} intends to execute {tool_name}"
            )
            policy_context = (
                policy_context_builder(ctx, tool_args)
                if policy_context_builder
                else {"framework": "microsoft_ai_foundry", "agent_name": agent_id}
            )
            effective_tool_platform = self._tool_platform(tool_platform, tool_args)
            payload = (
                analysis_payload_builder(ctx, tool_args)
                if analysis_payload_builder
                else self.build_tool_analysis_payload(
                    text=prompt_text,
                    agent_id=agent_id,
                    session_id=session_id,
                    user_id=user_id,
                    tool_name=tool_name,
                    tool_args=tool_args,
                    tool_platform=effective_tool_platform,
                    policy_context=policy_context,
                )
            )
            await self.analyze_tool_execution(payload=payload, agent_id=agent_id)
            if asyncio.iscoroutinefunction(handler):
                raw_result = await handler(ctx, tool_args, *a, **kw)
            else:
                raw_result = await asyncio.to_thread(handler, ctx, tool_args, *a, **kw)
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
        sanitize_output: bool = True,
        preserve_structured_output: bool = True,
    ) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_executor(
                tool_name=tool_name or getattr(handler, "__name__", "foundry_tool"),
                handler=handler,
                tool_platform=tool_platform,
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
        policy_context = self._ctx_attr(ctx, "policy_context", default={}) or {}
        payload = (
            validation_payload_builder(ctx, input_text)
            if validation_payload_builder
            else self.build_prompt_validation_payload(
                text=input_text,
                agent_id=agent_id,
                session_id=session_id,
                user_id=user_id,
                policy_context=policy_context,
            )
        )
        await self.validate_prompt_contract(payload=payload, agent_id=agent_id)
        if asyncio.iscoroutinefunction(run_callable):
            result = await run_callable(input_text=input_text, session_id=session_id, **kwargs)
        else:
            result = await asyncio.to_thread(run_callable, input_text=input_text, session_id=session_id, **kwargs)
        if not sanitize_output:
            return result
        output_text = output_extractor(result) if output_extractor else self._serialize_for_review(result)
        return await self.sanitize_text(
            text=output_text,
            agent_id=agent_id,
            session_id=session_id,
            policy_context={**policy_context, "request_purpose": "microsoft_ai_foundry.final_user_output"},
        )

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
    "AgenticDomeMicrosoftAIFoundryFirewall",
]
