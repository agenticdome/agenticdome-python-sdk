from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import uuid
from dataclasses import dataclass
from inspect import isawaitable
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from .client import AgentGuardClient

try:
    from .exceptions import AgentGuardHTTPError
except Exception:  # pragma: no cover - compatibility with older package layouts
    try:
        from .client import AgentGuardHTTPError
    except Exception:  # pragma: no cover
        class AgentGuardHTTPError(Exception):
            pass


logger = logging.getLogger("AgenticDome.mcp_host")
logger.setLevel(logging.INFO)

Forwarder = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]


# ============================================================================
# AgenticDome x MCP Host / Gateway
#
# This adapter belongs in the process that owns the MCP forwarding boundary. It
# does not implement an MCP server; it protects the JSON-RPC traffic that a host,
# gateway, proxy, or enterprise router sends to third-party MCP servers.
# ============================================================================


def _env(name: str, default: str = "") -> str:
    return os.getenv(name) or os.getenv(name.replace("AGENTICDOME_", "AgenticDome_"), default)


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

    host_agent_id: str = "MCP_Enterprise_Host"
    platform: str = "mcp"
    tool_platform: str = "mcp_third_party_server"

    timeout_s: int = 20
    fail_closed: bool = True
    require_explicit_session_id: bool = False

    sanitize_tool_output: bool = True
    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    verify_decision_tokens: bool = True
    report_incidents: bool = True
    blocked_incident_severity: str = "medium"
    screen_upstream_prompt: bool = True


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE", "").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY", ""),
        tenant_id=_env("AGENTICDOME_TENANT_ID", ""),
        host_agent_id=_env("AGENTICDOME_MCP_HOST_ID", "MCP_Enterprise_Host"),
        platform=_env("AGENTICDOME_PLATFORM", "mcp"),
        tool_platform=_env("AGENTICDOME_MCP_TOOL_PLATFORM", "mcp_third_party_server"),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        sanitize_tool_output=_env_bool("AGENTICDOME_SANITIZE_TOOL_OUTPUT", True),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        verify_decision_tokens=_env_bool("AGENTICDOME_VERIFY_DECISION_TOKENS", True),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
        screen_upstream_prompt=_env_bool("AGENTICDOME_SCREEN_UPSTREAM_PROMPT", True),
    )


class MCPFirewallError(RuntimeError):
    """Base exception for MCP host firewall failures."""


class MCPConfigurationError(MCPFirewallError):
    """Raised when the adapter is missing required AgenticDome configuration."""


class MCPToolBlocked(MCPFirewallError):
    """Raised when AgenticDome blocks or fail-closes MCP request forwarding."""


class AgenticDomeMCPHostFirewall:
    """Runtime firewall for MCP hosts, gateways, and JSON-RPC forwarding proxies.

    Place this at the exact boundary where your host receives an MCP JSON-RPC
    request and before it forwards `tools/call` to a third-party MCP server.
    """

    def __init__(self, config: Optional[FirewallConfig] = None, *, client: Optional[AgentGuardClient] = None) -> None:
        self.config = config or load_config()
        if client is None and not (self.config.api_base and self.config.api_key and self.config.tenant_id):
            raise MCPConfigurationError(
                "AgenticDome MCP host firewall is misconfigured. "
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

    # ------------------------------------------------------------------
    # JSON-RPC helpers
    # ------------------------------------------------------------------

    @staticmethod
    def jsonrpc_error(id_: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
        error: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": "2.0", "id": id_, "error": error}

    @staticmethod
    def jsonrpc_result(id_: Any, result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": id_, "result": result}

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
    def _safe_dict(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        if value is None:
            return {}
        return {"_raw": str(value)}

    @staticmethod
    def _request_id(req: Dict[str, Any]) -> Any:
        return req.get("id")

    @staticmethod
    def _is_tools_call(req: Dict[str, Any]) -> bool:
        return str(req.get("method") or "").strip() == "tools/call"

    @classmethod
    def _extract_tool_call(cls, req: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        params = req.get("params")
        if not isinstance(params, dict):
            params = {}
        tool_name = cls._safe_str(params.get("name") or "unknown_tool")
        return tool_name, cls._safe_dict(params.get("arguments"))

    @staticmethod
    def _strip_internal_args(tool_args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            k: v
            for k, v in (tool_args or {}).items()
            if not str(k).startswith("_AgenticDome_")
            and str(k) not in {"decision_token", "source_agent_id", "AgenticDome_decision_token"}
        }

    @staticmethod
    def _replace_tool_args(req: Dict[str, Any], new_args: Dict[str, Any]) -> Dict[str, Any]:
        out = copy.deepcopy(req)
        params = out.get("params")
        if not isinstance(params, dict):
            params = {}
            out["params"] = params
        params["arguments"] = new_args
        return out

    @staticmethod
    def _extract_result(payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, dict):
            return {}
        result = payload.get("result")
        return result if isinstance(result, dict) else payload

    def _verdict(self, payload: Dict[str, Any]) -> str:
        env = self._extract_result(payload)
        return self._safe_str(env.get("verdict") or env.get("decision") or env.get("action")).upper()

    def _reason(self, payload: Dict[str, Any]) -> str:
        env = self._extract_result(payload)
        return self._safe_str(env.get("reason") or env.get("message") or env.get("explanation") or payload)

    def _session_id(self, context: Dict[str, Any]) -> str:
        for key in ("session_id", "run_id", "trace_id", "conversation_id", "request_id"):
            value = context.get(key)
            if value:
                return self._safe_str(value)
        if self.config.require_explicit_session_id:
            raise MCPToolBlocked("Missing session_id/run_id/trace_id in MCP host context.")
        return f"mcp-{uuid.uuid4()}"

    def _host_id(self, context: Dict[str, Any]) -> str:
        return self._safe_str(context.get("host_id") or context.get("agent_id") or self.config.host_agent_id)

    def _tool_platform(self, context: Dict[str, Any], tool_args: Dict[str, Any]) -> str:
        return self._safe_str(
            context.get("tool_platform")
            or tool_args.get("tool_platform")
            or tool_args.get("platform")
            or self.config.tool_platform
        )

    def _policy_context(
        self,
        *,
        context: Dict[str, Any],
        session_id: str,
        request_purpose: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {
            "request_purpose": request_purpose,
            "session_id": session_id,
            "platform": self.config.platform,
            "host_app": context.get("host_app"),
            "workspace": context.get("workspace"),
            "device_id": context.get("device_id"),
            "jsonrpc_request_id": context.get("jsonrpc_request_id"),
        }

        for key in ("source_agent_id", "user_id", "principal_id", "caller_id"):
            if context.get(key):
                ctx[key] = context.get(key)

        raw_extra = context.get("extra_policy_context")
        if isinstance(raw_extra, dict):
            ctx.update(raw_extra)
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
            await self._to_thread(
                self.client.report_incident,
                agent_id=agent_id,
                incident_type=incident_type,
                severity=severity or self.config.blocked_incident_severity,
                details=details,
                tenant_id=self.config.tenant_id,
                platform=self.config.platform,
            )
        except Exception as exc:
            logger.warning("AgenticDome incident reporting failed; continuing. reason=%s", exc)

    def _fail_or_raise(self, message: str, exc: Optional[Exception] = None) -> None:
        if self.config.fail_closed:
            if exc is not None:
                raise MCPToolBlocked(message) from exc
            raise MCPToolBlocked(message)
        logger.warning("AgenticDome FAIL-OPEN: %s", message)

    # ------------------------------------------------------------------
    # Optional upstream prompt screening
    # ------------------------------------------------------------------

    async def screen_upstream_prompt(self, *, text: str, context: Dict[str, Any]) -> Dict[str, Any]:
        session_id = self._session_id(context)
        host_id = self._host_id(context)
        source_agent_id = self._safe_str(context.get("source_agent_id") or "") or None
        user_id = None if source_agent_id else self._safe_str(context.get("user_id") or "") or None

        try:
            response = await self._to_thread(
                self.client.guardrail_validate,
                text=text,
                agent_id=host_id,
                direction="input",
                session_id=session_id,
                platform=self.config.platform,
                source_platform=self.config.platform if source_agent_id else None,
                source_agent_id=source_agent_id,
                user_id=user_id,
                policy_context=self._policy_context(
                    context=context,
                    session_id=session_id,
                    request_purpose="mcp_upstream_prompt_screening",
                ),
            )

            if self._verdict(response) == "BLOCKED":
                reason = self._reason(response)
                await self._report_incident_best_effort(
                    agent_id=host_id,
                    incident_type="blocked_prompt_input",
                    details=reason,
                )
                raise MCPToolBlocked(f"AgenticDome blocked upstream prompt: {reason}")
            return response
        except MCPToolBlocked:
            raise
        except (AgentGuardHTTPError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome upstream prompt screening failed: {exc}", exc=exc)
            return {}

    # ------------------------------------------------------------------
    # Delegation token verification
    # ------------------------------------------------------------------

    async def verify_decision_token_if_present(
        self,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if not self.config.verify_decision_tokens:
            return None

        token = self._safe_str(
            context.get("decision_token")
            or tool_args.get("_AgenticDome_decision_token")
            or tool_args.get("AgenticDome_decision_token")
            or tool_args.get("decision_token")
            or ""
        )
        source_agent_id = self._safe_str(
            context.get("source_agent_id")
            or tool_args.get("_AgenticDome_source_agent_id")
            or tool_args.get("source_agent_id")
            or ""
        )

        if not token and not source_agent_id:
            return None
        if not token or not source_agent_id:
            await self._report_incident_best_effort(
                agent_id=self._host_id(context),
                incident_type="missing_delegation_token",
                details=f"tool={tool_name}",
                severity="high",
            )
            raise MCPToolBlocked("Missing AgenticDome decision token or source_agent_id for delegated MCP execution.")

        clean_args = self._strip_internal_args(tool_args)
        try:
            if hasattr(self.client, "a2a_verify_decision_token_rpc"):
                response = await self._to_thread(
                    self.client.a2a_verify_decision_token_rpc,
                    token=token,
                    tool_name=tool_name,
                    tool_args=clean_args,
                    agent_id=self._host_id(context),
                    source_agent_id=source_agent_id,
                    platform=self.config.platform,
                    require_allowed=True,
                )
            else:
                response = await self._to_thread(
                    self.client.a2a_action_call,
                    "security.decision.verify",
                    {
                        "token": token,
                        "tool_name": tool_name,
                        "tool_args": clean_args,
                        "agent_id": self._host_id(context),
                        "source_agent_id": source_agent_id,
                        "platform": self.config.platform,
                        "require_allowed": True,
                    },
                )

            result = self._extract_result(response)
            if not bool(result.get("valid") or result.get("allowed")):
                await self._report_incident_best_effort(
                    agent_id=self._host_id(context),
                    incident_type="invalid_delegation_token",
                    details=self._safe_str(result),
                    severity="high",
                )
                raise MCPToolBlocked(
                    f"AgenticDome blocked delegated MCP execution: {result.get('reason') or result}"
                )
            return result
        except MCPToolBlocked:
            raise
        except (AgentGuardHTTPError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome decision-token verification failed: {exc}", exc=exc)
            return None

    # ------------------------------------------------------------------
    # MCP tool authorization
    # ------------------------------------------------------------------

    async def authorize_mcp_tool_call(
        self,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        session_id = self._session_id(context)
        host_id = self._host_id(context)
        clean_args = self._strip_internal_args(tool_args)
        tool_platform = self._tool_platform(context, clean_args)

        try:
            return await self._to_thread(
                self.client.mcp_guardrail_validate,
                text=self._safe_str(
                    context.get("user_prompt")
                    or context.get("request_text")
                    or f"MCP host is attempting to call tool: {tool_name}"
                ),
                agent_id=host_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform=tool_platform,
                tool_name=tool_name,
                tool_args=clean_args,
                policy_context=self._policy_context(
                    context=context,
                    session_id=session_id,
                    request_purpose="mcp_tool_execution",
                    extra={"tool_platform": tool_platform, "tool_name": tool_name},
                ),
                direction="outbound",
                request_id=str(context.get("jsonrpc_request_id") or "1"),
            )
        except (AgentGuardHTTPError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome MCP authorization failed: {exc}", exc=exc)
            return {"verdict": "ALLOWED", "reason": "fail-open"}

    # ------------------------------------------------------------------
    # Output sanitization
    # ------------------------------------------------------------------

    async def sanitize_text(self, *, text: str, context: Dict[str, Any]) -> str:
        session_id = self._session_id(context)
        host_id = self._host_id(context)
        try:
            response = await self._to_thread(
                self.client.mesh_validate,
                agent_id=host_id,
                session_id=session_id,
                direction="output",
                text=text,
                policy_context=self._policy_context(
                    context=context,
                    session_id=session_id,
                    request_purpose="mcp_tool_output_sanitization",
                    extra={
                        "redact_pii": self.config.redact_pii,
                        "redact_secrets": self.config.redact_secrets,
                        "block_on_sensitive_output": self.config.block_on_sensitive_output,
                    },
                ),
            )

            env = self._extract_result(response)
            if self._verdict(env) == "BLOCKED":
                await self._report_incident_best_effort(
                    agent_id=host_id,
                    incident_type="blocked_output",
                    details=self._reason(env),
                )
                return "[OUTPUT BLOCKED BY AgenticDome]"

            sanitized_text = env.get("text") or env.get("sanitized_text") or response.get("text") or response.get("sanitized_text")
            return self._safe_str(sanitized_text) if sanitized_text is not None else text
        except (AgentGuardHTTPError, Exception) as exc:
            logger.warning("AgenticDome MCP output sanitization failed. reason=%s", exc)
            if self.config.fail_closed:
                raise MCPToolBlocked("AgenticDome MCP output sanitization failed") from exc
            return text

    async def sanitize_mcp_result(self, *, tool_output: Any, context: Dict[str, Any]) -> Any:
        """Sanitize common MCP result shapes while preserving JSON-RPC response structure."""
        if tool_output is None:
            return None
        if isinstance(tool_output, str):
            return await self.sanitize_text(text=tool_output, context=context)
        if isinstance(tool_output, list):
            return [await self.sanitize_mcp_result(tool_output=item, context=context) for item in tool_output]
        if not isinstance(tool_output, dict):
            return await self.sanitize_text(text=self._safe_str(tool_output), context=context)

        out = copy.deepcopy(tool_output)
        touched_text = False

        content = out.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    item["text"] = await self.sanitize_text(text=item["text"], context=context)
                    touched_text = True

        if isinstance(out.get("text"), str):
            out["text"] = await self.sanitize_text(text=out["text"], context=context)
            touched_text = True

        if touched_text:
            return out

        serialized = json.dumps(out, default=str, sort_keys=True)
        sanitized = await self.sanitize_text(text=serialized, context=context)
        if sanitized == serialized:
            return out
        try:
            return json.loads(sanitized)
        except Exception:
            return sanitized

    # ------------------------------------------------------------------
    # Main interceptor APIs
    # ------------------------------------------------------------------

    async def preflight_request(self, *, mcp_request: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Gate a JSON-RPC request before it is forwarded to a third-party MCP server."""
        if not isinstance(mcp_request, dict):
            return self.jsonrpc_error(None, -32600, "Invalid Request")
        if not self._is_tools_call(mcp_request):
            return mcp_request

        rid = self._request_id(mcp_request)
        tool_name, tool_args = self._extract_tool_call(mcp_request)
        local_context = dict(context or {})
        local_context["jsonrpc_request_id"] = rid

        try:
            prompt_text = self._safe_str(local_context.get("user_prompt") or local_context.get("request_text") or "")
            if self.config.screen_upstream_prompt and prompt_text:
                await self.screen_upstream_prompt(text=prompt_text, context=local_context)

            await self.verify_decision_token_if_present(tool_name=tool_name, tool_args=tool_args, context=local_context)
            decision = await self.authorize_mcp_tool_call(tool_name=tool_name, tool_args=tool_args, context=local_context)

            if self._verdict(decision) == "BLOCKED":
                reason = self._reason(decision)
                await self._report_incident_best_effort(
                    agent_id=self._host_id(local_context),
                    incident_type="blocked_tool_execution",
                    details=reason,
                )
                return self.jsonrpc_error(rid, -32000, f"AgenticDome Blocked: {reason}", data={"tool": tool_name})

            return self._replace_tool_args(mcp_request, self._strip_internal_args(tool_args))
        except MCPToolBlocked as exc:
            return self.jsonrpc_error(rid, -32000, f"AgenticDome Blocked: {exc}", data={"tool": tool_name})
        except (AgentGuardHTTPError, Exception) as exc:
            if self.config.fail_closed:
                return self.jsonrpc_error(rid, -32000, f"AgenticDome Blocked: {exc}", data={"tool": tool_name})
            logger.warning("AgenticDome MCP preflight failed open. reason=%s", exc)
            return mcp_request

    async def _invoke_forwarder(
        self,
        forward_to_third_party: Callable[[Dict[str, Any]], Any],
        request: Dict[str, Any],
    ) -> Dict[str, Any]:
        response = forward_to_third_party(request)
        if isawaitable(response):
            response = await response
        return response

    async def forward_with_firewall(
        self,
        *,
        mcp_request: Dict[str, Any],
        context: Dict[str, Any],
        forward_to_third_party: Callable[[Dict[str, Any]], Any],
    ) -> Dict[str, Any]:
        """Preflight, forward, and optionally sanitize a third-party MCP response."""
        gated = await self.preflight_request(mcp_request=mcp_request, context=context)
        if isinstance(gated, dict) and "error" in gated:
            return gated

        response = await self._invoke_forwarder(forward_to_third_party, gated)
        if not self.config.sanitize_tool_output or not isinstance(response, dict) or "result" not in response:
            return response

        sanitized_response = copy.deepcopy(response)
        try:
            sanitized_response["result"] = await self.sanitize_mcp_result(
                tool_output=sanitized_response["result"],
                context=context,
            )
            return sanitized_response
        except MCPToolBlocked:
            raise
        except Exception as exc:
            logger.warning("AgenticDome MCP result sanitization failed; returning original response. reason=%s", exc)
            return response


__all__ = [
    "AgenticDomeMCPHostFirewall",
    "FirewallConfig",
    "MCPConfigurationError",
    "MCPFirewallError",
    "MCPToolBlocked",
    "load_config",
]
