from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from inspect import isawaitable
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

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
# This module protects the local Python boundaries around Bedrock Runtime calls:
#   - Converse / ConverseStream request construction
#   - InvokeModel payload submission
#   - local tool-use handlers and Bedrock Agents action-group handlers
#   - knowledge-base / retrieval results before they are used or returned
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
        platform=_env("AGENTICDOME_PLATFORM", "aws_bedrock"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "aws_bedrock"),
        default_agent_id=_env("AGENTICDOME_BEDROCK_AGENT_ID", "aws_bedrock_agent"),
        default_model_id=_env("AGENTICDOME_BEDROCK_MODEL_ID", ""),
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


class AWSBedrockFirewallError(RuntimeError):
    """Base AWS Bedrock firewall exception."""


class AWSBedrockConfigurationError(AWSBedrockFirewallError):
    """Raised when required AgenticDome configuration is missing."""


class AWSBedrockDenied(AWSBedrockFirewallError):
    """Raised when AgenticDome blocks or fail-closes a Bedrock operation."""


class AgenticDomeAWSBedrockFirewall:
    """Firewall for local AWS Bedrock Runtime and Bedrock Agents boundaries."""

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
        return default

    def _agent_id(self, ctx: Any = None, explicit: Optional[str] = None) -> str:
        value = explicit or self._ctx_attr(ctx, "agent_id", "agent_name", "name") if ctx is not None else explicit
        return self._safe_str(value) or self.config.default_agent_id

    def _session_id(self, ctx: Any = None, explicit: Optional[str] = None) -> str:
        if explicit:
            return self._safe_str(explicit)
        if ctx is not None:
            for key in ("session_id", "run_id", "trace_id", "conversation_id", "request_id", "invocation_id"):
                value = self._ctx_attr(ctx, key)
                if value:
                    return self._safe_str(value)
        if self.config.require_explicit_session_id:
            raise AWSBedrockDenied("Missing session_id/run_id/trace_id in AWS Bedrock context.")
        return f"bedrock-{uuid.uuid4().hex}"

    def _user_id(self, ctx: Any = None) -> Optional[str]:
        value = self._ctx_attr(ctx, "user_id", "principal_id", "caller_id") if ctx is not None else None
        text = self._safe_str(value)
        return text or None

    def _policy_context(
        self,
        *,
        agent_id: str,
        session_id: str,
        request_purpose: str,
        model_id: Optional[str] = None,
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
        if model_id:
            ctx.setdefault("model_id", model_id)
        if extra:
            ctx.update(extra)
        return ctx

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
                for key in ("text", "inputText", "prompt", "content", "toolUse", "toolResult", "json"):
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
            "prompt",
            "inputText",
            "input_text",
            "text",
            "query",
            "instruction",
            "system",
        )
        parts: List[str] = []
        for key in direct_keys:
            if payload.get(key):
                parts.append(self._serialize_for_review(payload[key]))
        if payload.get("messages"):
            parts.append(self.extract_text_from_converse_messages(payload.get("messages"), payload.get("system")))
        if payload.get("contents"):
            parts.append(self.extract_text_from_converse_messages(payload.get("contents"), payload.get("system")))
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
        for key in ("outputText", "completion", "generation", "answer", "text"):
            if payload.get(key):
                parts.append(self._serialize_for_review(payload[key]))
        return "\n".join(part for part in parts if part).strip() or self._serialize_for_review(payload)

    # ------------------------------------------------------------------
    # Core AgenticDome controls
    # ------------------------------------------------------------------

    async def screen_prompt(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        model_id: Optional[str] = None,
        user_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            response = await self._to_thread(
                self.client.guardrail_validate,
                text=text,
                agent_id=agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                direction="input",
                session_id=session_id,
                user_id=user_id,
                policy_context=self._policy_context(
                    agent_id=agent_id,
                    session_id=session_id,
                    model_id=model_id,
                    request_purpose="aws_bedrock.prompt_input",
                    policy_context=policy_context,
                ),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type="blocked_prompt_input",
                    details=reason,
                )
                raise AWSBedrockDenied(f"AgenticDome blocked Bedrock prompt: {reason}")
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
    ) -> Dict[str, Any]:
        effective_tool_platform = tool_platform or tool_args.get("tool_platform") or tool_args.get("platform") or self.config.default_tool_platform
        try:
            response = await self._to_thread(
                self.client.guardrail_validate,
                text=text,
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
                    model_id=model_id,
                    request_purpose="aws_bedrock.tool_execution",
                    policy_context=policy_context,
                    extra={"tool_name": tool_name, "tool_platform": effective_tool_platform},
                ),
            )
            if self._is_blocked(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(
                    agent_id=agent_id,
                    incident_type="blocked_tool_execution",
                    details=reason,
                )
                raise AWSBedrockDenied(f"AgenticDome blocked Bedrock tool execution: {reason}")
            return response
        except Exception as exc:
            await self._handle_error(exc, "authorize_tool_call")
            return {}

    async def sanitize_text(
        self,
        *,
        text: str,
        agent_id: str,
        session_id: str,
        model_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> str:
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
                    model_id=model_id,
                    request_purpose="aws_bedrock.output_review",
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

    # ------------------------------------------------------------------
    # AWS Bedrock Runtime wrappers
    # ------------------------------------------------------------------

    async def converse_securely(
        self,
        *,
        bedrock_runtime_client: Any,
        model_id: str,
        messages: List[Dict[str, Any]],
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        system: Optional[Any] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        sanitize_output: Optional[bool] = None,
        **converse_kwargs: Any,
    ) -> Any:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(explicit=session_id)
        prompt_text = self.extract_text_from_converse_messages(messages, system)
        await self.screen_prompt(
            text=prompt_text or self._serialize_for_review(messages),
            agent_id=effective_agent_id,
            session_id=effective_session_id,
            model_id=model_id,
            policy_context=policy_context,
        )

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
        sanitized = await self.sanitize_text(
            text=response_text,
            agent_id=effective_agent_id,
            session_id=effective_session_id,
            model_id=model_id,
            policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.converse_output"},
        )
        return self._apply_sanitized_text_to_converse_response(response, sanitized)

    async def invoke_model_securely(
        self,
        *,
        bedrock_runtime_client: Any,
        model_id: str,
        body: Any,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        sanitize_output: Optional[bool] = None,
        **invoke_kwargs: Any,
    ) -> Any:
        effective_agent_id = agent_id or self.config.default_agent_id
        effective_session_id = self._session_id(explicit=session_id)
        prompt_text = self.extract_text_from_invoke_body(body)
        await self.screen_prompt(
            text=prompt_text,
            agent_id=effective_agent_id,
            session_id=effective_session_id,
            model_id=model_id,
            policy_context=policy_context,
        )

        call_kwargs = dict(invoke_kwargs)
        call_kwargs.update({"modelId": model_id, "body": body})
        response = bedrock_runtime_client.invoke_model(**call_kwargs)
        if isawaitable(response):
            response = await response

        should_sanitize = self.config.sanitize_model_output if sanitize_output is None else sanitize_output
        if not should_sanitize:
            return response
        return await self.sanitize_invoke_model_response(
            response=response,
            agent_id=effective_agent_id,
            session_id=effective_session_id,
            model_id=model_id,
            policy_context=policy_context,
        )

    async def sanitize_invoke_model_response(
        self,
        *,
        response: Any,
        agent_id: str,
        session_id: str,
        model_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        if not isinstance(response, dict) or "body" not in response:
            text = self.extract_text_from_bedrock_response(response)
            return await self.sanitize_text(
                text=text,
                agent_id=agent_id,
                session_id=session_id,
                model_id=model_id,
                policy_context=policy_context,
            )

        out = dict(response)
        body = out.get("body")
        if hasattr(body, "read"):
            raw = body.read()
        else:
            raw = body
        parsed = self._json_loads_maybe(raw)
        text = self.extract_text_from_bedrock_response(parsed)
        sanitized = await self.sanitize_text(
            text=text,
            agent_id=agent_id,
            session_id=session_id,
            model_id=model_id,
            policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.invoke_model_output"},
        )
        if isinstance(parsed, dict):
            for key in ("outputText", "completion", "generation", "answer", "text"):
                if isinstance(parsed.get(key), str):
                    parsed[key] = sanitized
                    out["body"] = json.dumps(parsed).encode("utf-8")
                    return out
        out["body"] = sanitized.encode("utf-8")
        return out

    # ------------------------------------------------------------------
    # Tool, action-group, and retrieval helpers
    # ------------------------------------------------------------------

    def wrap_tool_handler(
        self,
        *,
        tool_name: str,
        handler: Callable[..., Any],
        tool_platform: Optional[str] = None,
        text_builder: Optional[Callable[[Any, Dict[str, Any]], str]] = None,
        policy_context_builder: Optional[Callable[[Any, Dict[str, Any]], Dict[str, Any]]] = None,
        sanitize_output: Optional[bool] = None,
        preserve_structured_output: bool = True,
    ) -> Callable[..., Awaitable[Any]]:
        async def secured(ctx: Any, args: Any = None, *a: Any, **kw: Any) -> Any:
            tool_args = self._normalize_args(args)
            agent_id = self._agent_id(ctx)
            session_id = self._session_id(ctx)
            model_id = self._safe_str(self._ctx_attr(ctx, "model_id", "modelId", default=self.config.default_model_id)) or None
            text = text_builder(ctx, tool_args) if text_builder else f"[AWS Bedrock] {agent_id} intends to execute {tool_name}"
            policy_context = policy_context_builder(ctx, tool_args) if policy_context_builder else {"framework": "aws_bedrock", "agent_name": agent_id}

            await self.authorize_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                agent_id=agent_id,
                session_id=session_id,
                text=text,
                model_id=model_id,
                tool_platform=tool_platform,
                policy_context=policy_context,
            )

            raw_result = handler(ctx, tool_args, *a, **kw)
            if isawaitable(raw_result):
                raw_result = await raw_result

            should_sanitize = self.config.sanitize_tool_output if sanitize_output is None else sanitize_output
            if not should_sanitize:
                return raw_result

            result_text = self._serialize_for_review(raw_result)
            sanitized = await self.sanitize_text(
                text=result_text,
                agent_id=agent_id,
                session_id=session_id,
                model_id=model_id,
                policy_context={**policy_context, "request_purpose": "aws_bedrock.tool_output_review", "tool_name": tool_name},
            )
            if preserve_structured_output and isinstance(raw_result, (dict, list, tuple)) and sanitized == result_text:
                return raw_result
            return sanitized

        return secured

    def secure_tool(self, *, tool_name: str, tool_platform: Optional[str] = None, **options: Any) -> Callable[[Callable[..., Any]], Callable[..., Awaitable[Any]]]:
        def decorator(handler: Callable[..., Any]) -> Callable[..., Awaitable[Any]]:
            return self.wrap_tool_handler(tool_name=tool_name, handler=handler, tool_platform=tool_platform, **options)
        return decorator

    async def sanitize_retrieval_result(
        self,
        *,
        retrieval_result: Any,
        agent_id: str,
        session_id: str,
        model_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        text = self._serialize_for_review(retrieval_result)
        sanitized = await self.sanitize_text(
            text=text,
            agent_id=agent_id,
            session_id=session_id,
            model_id=model_id,
            policy_context={**(policy_context or {}), "request_purpose": "aws_bedrock.retrieval_result_review"},
        )
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
    "FirewallConfig",
    "load_config",
]
