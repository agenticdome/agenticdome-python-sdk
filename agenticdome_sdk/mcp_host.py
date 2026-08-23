
from __future__ import annotations

import asyncio
import copy
import hashlib
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
from typing import Any, AsyncIterator, Callable, Deque, Dict, Iterable, List, Optional, Tuple

from .client import AgenticDomeClient
from ._mode import credentials_or_local_sim

try:
    from .exceptions import AgenticDomeHTTPError
except Exception:  # pragma: no cover - compatibility with older package layouts
    try:
        from .client import AgenticDomeHTTPError
    except Exception:  # pragma: no cover
        class AgenticDomeHTTPError(Exception):
            pass


logger = logging.getLogger("AgenticDome.mcp_host")
logger.setLevel(logging.INFO)



# ============================================================================
# AgenticDome x MCP Host / Gateway
#
# This adapter belongs in the process that owns the MCP forwarding boundary. It
# does not implement an MCP server; it protects the JSON-RPC traffic that a host,
# gateway, proxy, or enterprise router sends to third-party MCP servers.
# ============================================================================


def _env(name: str, default: str = "") -> str:
    return os.getenv(name) or os.getenv(name.replace("AGENTICDOME_", "agenticdome_"), default)


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
    sanitize_resource_output: bool = True
    sanitize_prompt_output: bool = True
    sanitize_sampling_output: bool = True
    sanitize_streaming_output: bool = True
    redact_pii: bool = True
    redact_secrets: bool = True
    block_on_sensitive_output: bool = False

    protect_tools_list: bool = True
    protect_resources_list: bool = True
    protect_resources_read: bool = True
    protect_prompts_list: bool = True
    protect_prompts_get: bool = True
    protect_sampling_create_message: bool = True

    verify_decision_tokens: bool = True
    handoff_token_ttl_s: int = 900
    redis_url: str = ""
    redis_key_prefix: str = "AgenticDome:mcp:handoff"

    max_output_chars: int = 100_000
    max_tool_arg_chars: int = 20_000
    max_request_text_chars: int = 20_000
    rate_limit_per_minute: int = 0

    mcp_server_id: str = ""
    mcp_server_name: str = ""
    mcp_server_url: str = ""
    mcp_server_trust_level: str = ""
    mcp_server_vendor: str = ""

    audit_logging: bool = True
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
        sanitize_resource_output=_env_bool("AGENTICDOME_SANITIZE_RESOURCE_OUTPUT", True),
        sanitize_prompt_output=_env_bool("AGENTICDOME_SANITIZE_PROMPT_OUTPUT", True),
        sanitize_sampling_output=_env_bool("AGENTICDOME_SANITIZE_SAMPLING_OUTPUT", True),
        sanitize_streaming_output=_env_bool("AGENTICDOME_SANITIZE_STREAMING_OUTPUT", True),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        protect_tools_list=_env_bool("AGENTICDOME_MCP_PROTECT_TOOLS_LIST", True),
        protect_resources_list=_env_bool("AGENTICDOME_MCP_PROTECT_RESOURCES_LIST", True),
        protect_resources_read=_env_bool("AGENTICDOME_MCP_PROTECT_RESOURCES_READ", True),
        protect_prompts_list=_env_bool("AGENTICDOME_MCP_PROTECT_PROMPTS_LIST", True),
        protect_prompts_get=_env_bool("AGENTICDOME_MCP_PROTECT_PROMPTS_GET", True),
        protect_sampling_create_message=_env_bool("AGENTICDOME_MCP_PROTECT_SAMPLING_CREATE_MESSAGE", True),
        verify_decision_tokens=_env_bool("AGENTICDOME_VERIFY_DECISION_TOKENS", True),
        handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
        redis_url=_env("AGENTICDOME_REDIS_URL", "").strip(),
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:mcp:handoff"),
        max_output_chars=_env_int("AGENTICDOME_MCP_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_MCP_MAX_TOOL_ARG_CHARS", 20_000),
        max_request_text_chars=_env_int("AGENTICDOME_MCP_MAX_REQUEST_TEXT_CHARS", 20_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_MCP_RATE_LIMIT_PER_MINUTE", 0),
        mcp_server_id=_env("AGENTICDOME_MCP_SERVER_ID", ""),
        mcp_server_name=_env("AGENTICDOME_MCP_SERVER_NAME", ""),
        mcp_server_url=_env("AGENTICDOME_MCP_SERVER_URL", ""),
        mcp_server_trust_level=_env("AGENTICDOME_MCP_SERVER_TRUST_LEVEL", ""),
        mcp_server_vendor=_env("AGENTICDOME_MCP_SERVER_VENDOR", ""),
        audit_logging=_env_bool("AGENTICDOME_MCP_AUDIT_LOGGING", True),
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
        return f"{self._tenant_id}:{session_id}:{target_agent_id}:{_tool_fingerprint(tool_name, tool_args)}"

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
        return f"{self._prefix}:{self._tenant_id}:{session_id}:{target_agent_id}:{_tool_fingerprint(tool_name, tool_args)}"

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
            logger.info("AgenticDome MCP host firewall using Redis token store.")
            return RedisDecisionTokenStore(config.redis_url, config.redis_key_prefix, config.tenant_id)
        except Exception as exc:
            logger.warning("Redis token store unavailable; falling back to memory. reason=%s", exc)
    return InMemoryDecisionTokenStore(config.tenant_id)


class AgenticDomeMCPHostFirewall:
    """Runtime firewall for MCP hosts, gateways, and JSON-RPC forwarding proxies.

    Place this at the exact boundary where your host receives MCP JSON-RPC
    requests and before it forwards them to third-party MCP servers.
    """

    def __init__(
        self,
        config: Optional[FirewallConfig] = None,
        *,
        client: Optional[AgenticDomeClient] = None,
        token_store: Optional[DecisionTokenStore] = None,
    ) -> None:
        self.config = config or load_config()
        if not credentials_or_local_sim(self.config.api_base, self.config.api_key, self.config.tenant_id):
            raise MCPConfigurationError(
                "AgenticDome MCP host firewall is misconfigured. "
                "Set AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID."
            )

        self.client = client or AgenticDomeClient(
            api_base=self.config.api_base,
            api_key=self.config.api_key,
            tenant_id=self.config.tenant_id,
            timeout=self.config.timeout_s,
        )
        self.token_store = token_store or _build_token_store(self.config)
        self._rate_lock = Lock()
        self._rate_events: Dict[str, Deque[float]] = defaultdict(deque)

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
    def _method(req: Dict[str, Any]) -> str:
        return str(req.get("method") or "").strip()

    @classmethod
    def _is_tools_call(cls, req: Dict[str, Any]) -> bool:
        return cls._method(req) == "tools/call"

    @classmethod
    def _params(cls, req: Dict[str, Any]) -> Dict[str, Any]:
        params = req.get("params")
        return params if isinstance(params, dict) else {}

    @classmethod
    def _extract_tool_call(cls, req: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        params = cls._params(req)
        tool_name = cls._safe_str(params.get("name") or "unknown_tool")
        return tool_name, cls._safe_dict(params.get("arguments"))

    @classmethod
    def _extract_resource_read(cls, req: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        params = cls._params(req)
        uri = cls._safe_str(params.get("uri") or "unknown_resource")
        return uri, dict(params)

    @classmethod
    def _extract_prompt_get(cls, req: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        params = cls._params(req)
        name = cls._safe_str(params.get("name") or "unknown_prompt")
        return name, dict(params)

    @staticmethod
    def _strip_internal_args(tool_args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            k: v
            for k, v in (tool_args or {}).items()
            if not str(k).startswith("_agenticdome_")
            and str(k) not in {
                "decision_token",
                "source_agent_id",
                "agenticdome_decision_token",
                "agenticdome_source_agent_id",
            }
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
    def _replace_params(req: Dict[str, Any], new_params: Dict[str, Any]) -> Dict[str, Any]:
        out = copy.deepcopy(req)
        out["params"] = dict(new_params)
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

    def _is_allowed(self, payload: Dict[str, Any]) -> bool:
        env = self._extract_result(payload)
        if "allowed" in env:
            return bool(env["allowed"])
        if "valid" in env:
            return bool(env["valid"])
        return self._verdict(payload) in {"ALLOWED", "ALLOW", "APPROVED", "VALID"}

    def _reason(self, payload: Dict[str, Any]) -> str:
        env = self._extract_result(payload)
        return self._safe_str(env.get("reason") or env.get("message") or env.get("explanation") or payload)

    def _sanitized_args(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        env = self._extract_result(payload)
        for key in ("sanitized_tool_args", "sanitized_args", "tool_args"):
            value = env.get(key)
            if isinstance(value, dict):
                return self._strip_internal_args(value)
        return None

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

    def _target_agent_id(self, context: Dict[str, Any]) -> str:
        return self._safe_str(context.get("target_agent_id") or context.get("mcp_agent_id") or self._host_id(context))

    def _server_value(self, context: Dict[str, Any], key: str, config_value: str) -> str:
        value = context.get(key) or context.get(key.replace("mcp_server_", "server_")) or config_value
        return self._safe_str(value)

    def _server_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        values = {
            "mcp_server_id": self._server_value(context, "mcp_server_id", self.config.mcp_server_id),
            "mcp_server_name": self._server_value(context, "mcp_server_name", self.config.mcp_server_name),
            "mcp_server_url": self._server_value(context, "mcp_server_url", self.config.mcp_server_url),
            "mcp_server_trust_level": self._server_value(context, "mcp_server_trust_level", self.config.mcp_server_trust_level),
            "mcp_server_vendor": self._server_value(context, "mcp_server_vendor", self.config.mcp_server_vendor),
        }
        return {key: value for key, value in values.items() if value}

    def _tool_platform(self, context: Dict[str, Any], tool_args: Dict[str, Any]) -> str:
        server_id = self._server_context(context).get("mcp_server_id")
        return self._safe_str(
            context.get("tool_platform")
            or tool_args.get("tool_platform")
            or tool_args.get("platform")
            or server_id
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
        ctx.update(self._server_context(context))

        for key in ("source_agent_id", "user_id", "principal_id", "caller_id", "target_agent_id"):
            if context.get(key):
                ctx[key] = context.get(key)

        raw_extra = context.get("extra_policy_context")
        if isinstance(raw_extra, dict):
            ctx.update(raw_extra)
        if extra:
            ctx.update(extra)
        return {key: value for key, value in ctx.items() if value is not None and value != ""}

    def _audit(self, event: str, *, context: Dict[str, Any], details: Optional[Dict[str, Any]] = None) -> None:
        if not self.config.audit_logging:
            return
        payload = {
            "event": event,
            "host_id": self._host_id(context),
            "session_id": context.get("session_id") or context.get("run_id") or context.get("trace_id"),
            **self._server_context(context),
        }
        if details:
            payload.update(details)
        logger.info("AgenticDome MCP audit: %s", json.dumps(payload, sort_keys=True, default=str))

    def _rate_key(self, *, context: Dict[str, Any], method: str) -> str:
        principal = context.get("user_id") or context.get("principal_id") or context.get("source_agent_id") or self._host_id(context)
        server = self._server_context(context).get("mcp_server_id", "default")
        return f"{principal}:{server}:{method}"

    def _check_rate_limit(self, *, context: Dict[str, Any], method: str) -> None:
        limit = self.config.rate_limit_per_minute
        if limit <= 0:
            return
        key = self._rate_key(context=context, method=method)
        now = time.time()
        cutoff = now - 60
        with self._rate_lock:
            events = self._rate_events[key]
            while events and events[0] < cutoff:
                events.popleft()
            if len(events) >= limit:
                raise MCPToolBlocked(f"MCP rate limit exceeded for {method}")
            events.append(now)

    def _enforce_arg_size(self, *, tool_name: str, tool_args: Dict[str, Any]) -> None:
        if self.config.max_tool_arg_chars <= 0:
            return
        serialized = json.dumps(tool_args or {}, sort_keys=True, default=str)
        if len(serialized) > self.config.max_tool_arg_chars:
            raise MCPToolBlocked(f"MCP tool arguments exceed max size for {tool_name}")

    def _bounded_request_text(self, text: str) -> str:
        if self.config.max_request_text_chars > 0 and len(text) > self.config.max_request_text_chars:
            return text[: self.config.max_request_text_chars] + "\n[TRUNCATED BY AgenticDome MCP HOST]"
        return text

    def _bounded_output_text(self, text: str, context: Dict[str, Any]) -> str:
        if self.config.max_output_chars > 0 and len(text) > self.config.max_output_chars:
            self._audit("mcp_output_truncated", context=context, details={"original_chars": len(text), "max_chars": self.config.max_output_chars})
            return text[: self.config.max_output_chars] + "\n[TRUNCATED BY AgenticDome MCP HOST]"
        return text

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
                text=self._bounded_request_text(text),
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
        except (AgenticDomeHTTPError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome upstream prompt screening failed: {exc}", exc=exc)
            return {}

    # ------------------------------------------------------------------
    # Delegation handoff and token verification
    # ------------------------------------------------------------------

    async def authorize_manager_handoff(
        self,
        *,
        manager_agent_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Dict[str, Any],
        text: Optional[str] = None,
        tool_platform: Optional[str] = None,
    ) -> Dict[str, Any]:
        session_id = self._session_id(context)
        clean_args = self._strip_internal_args(tool_args)
        effective_tool_platform = tool_platform or self._tool_platform(context, clean_args)
        self._enforce_arg_size(tool_name=tool_name, tool_args=clean_args)

        try:
            response = await self._to_thread(
                self.client.a2a_authorize_tool,
                text=self._bounded_request_text(text or f"MCP manager {manager_agent_id} delegates {tool_name} to {target_agent_id}"),
                agent_id=target_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform=effective_tool_platform,
                tool_name=tool_name,
                tool_args=clean_args,
                session_id=session_id,
                direction="outbound",
                source_agent_id=manager_agent_id,
                policy_context=self._policy_context(
                    context=context,
                    session_id=session_id,
                    request_purpose="mcp_manager_handoff",
                    extra={
                        "source_agent_id": manager_agent_id,
                        "target_agent_id": target_agent_id,
                        "delegation_chain": [manager_agent_id, target_agent_id],
                        "tool_platform": effective_tool_platform,
                    },
                ),
            )
            if not self._is_allowed(response):
                reason = self._reason(response)
                await self._report_incident_best_effort(agent_id=manager_agent_id, incident_type="blocked_delegation", details=reason)
                raise MCPToolBlocked(f"AgenticDome blocked MCP handoff: {reason}")
            env = self._extract_result(response)
            token = self._safe_str(env.get("decision_token") or env.get("token"))
            if token:
                self.token_store.put(
                    session_id=session_id,
                    target_agent_id=target_agent_id,
                    tool_name=tool_name,
                    tool_args=clean_args,
                    record=DecisionTokenRecord(decision_token=token, source_agent_id=manager_agent_id, created_at=time.time()),
                    ttl_s=self.config.handoff_token_ttl_s,
                )
            self._audit("mcp_handoff_authorized", context=context, details={"manager_agent_id": manager_agent_id, "target_agent_id": target_agent_id, "tool_name": tool_name})
            return response
        except MCPToolBlocked:
            raise
        except (AgenticDomeHTTPError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome MCP handoff authorization failed: {exc}", exc=exc)
            return {}

    async def verify_decision_token_if_present(
        self,
        *,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if not self.config.verify_decision_tokens:
            return None

        clean_args = self._strip_internal_args(tool_args)
        target_agent_id = self._target_agent_id(context)
        token = self._safe_str(
            context.get("decision_token")
            or tool_args.get("_agenticdome_decision_token")
            or tool_args.get("agenticdome_decision_token")
            or tool_args.get("decision_token")
            or ""
        )
        source_agent_id = self._safe_str(
            context.get("source_agent_id")
            or tool_args.get("_agenticdome_source_agent_id")
            or tool_args.get("agenticdome_source_agent_id")
            or tool_args.get("source_agent_id")
            or ""
        )

        if not token:
            pending = self.token_store.get(
                session_id=self._session_id(context),
                target_agent_id=target_agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
            )
            if pending:
                token = pending.decision_token
                source_agent_id = pending.source_agent_id

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

        try:
            if hasattr(self.client, "a2a_verify_decision_token_rpc"):
                response = await self._to_thread(
                    self.client.a2a_verify_decision_token_rpc,
                    token=token,
                    tool_name=tool_name,
                    tool_args=clean_args,
                    agent_id=target_agent_id,
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
                        "agent_id": target_agent_id,
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

            self.token_store.delete(
                session_id=self._session_id(context),
                target_agent_id=target_agent_id,
                tool_name=tool_name,
                tool_args=clean_args,
            )
            self._audit("mcp_decision_token_verified", context=context, details={"tool_name": tool_name, "source_agent_id": source_agent_id})
            return result
        except MCPToolBlocked:
            raise
        except (AgenticDomeHTTPError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome decision-token verification failed: {exc}", exc=exc)
            return None

    # ------------------------------------------------------------------
    # MCP authorization
    # ------------------------------------------------------------------

    async def _mcp_guardrail(
        self,
        *,
        operation_name: str,
        operation_args: Dict[str, Any],
        context: Dict[str, Any],
        request_purpose: str,
        text: str,
        tool_platform: Optional[str] = None,
    ) -> Dict[str, Any]:
        session_id = self._session_id(context)
        host_id = self._host_id(context)
        clean_args = self._strip_internal_args(operation_args)
        effective_tool_platform = tool_platform or self._tool_platform(context, clean_args)
        self._enforce_arg_size(tool_name=operation_name, tool_args=clean_args)

        policy_context = self._policy_context(
            context=context,
            session_id=session_id,
            request_purpose=request_purpose,
            extra={"tool_platform": effective_tool_platform, "mcp_method": context.get("mcp_method")},
        )
        common_kwargs = {
            "text": self._bounded_request_text(text),
            "agent_id": host_id,
            "platform": self.config.platform,
            "source_platform": self.config.platform,
            "tool_platform": effective_tool_platform,
            "tool_name": operation_name,
            "tool_args": clean_args,
            "policy_context": policy_context,
            "direction": "outbound",
        }
        call = getattr(self.client, "mcp_guardrail_validate", None)
        if callable(call):
            common_kwargs["request_id"] = str(context.get("jsonrpc_request_id") or "1")
        else:
            call = self.client.guardrail_validate

        try:
            return await self._to_thread(call, **common_kwargs)
        except (AgenticDomeHTTPError, Exception) as exc:
            self._fail_or_raise(f"AgenticDome MCP authorization failed: {exc}", exc=exc)
            return {"verdict": "ALLOWED", "reason": "fail-open"}

    async def authorize_mcp_tool_call(self, *, tool_name: str, tool_args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return await self._mcp_guardrail(
            operation_name=tool_name,
            operation_args=tool_args,
            context=context,
            request_purpose="mcp_tool_execution",
            text=self._safe_str(context.get("user_prompt") or context.get("request_text") or f"MCP host is attempting to call tool: {tool_name}"),
        )

    async def authorize_mcp_resource_read(self, *, uri: str, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return await self._mcp_guardrail(
            operation_name="mcp.resources/read",
            operation_args={"uri": uri, **params},
            context=context,
            request_purpose="mcp_resource_read",
            text=self._safe_str(context.get("user_prompt") or context.get("request_text") or f"MCP host is attempting to read resource: {uri}"),
        )

    async def authorize_mcp_prompt_get(self, *, name: str, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return await self._mcp_guardrail(
            operation_name="mcp.prompts/get",
            operation_args={"name": name, **params},
            context=context,
            request_purpose="mcp_prompt_get",
            text=self._safe_str(context.get("user_prompt") or context.get("request_text") or f"MCP host is attempting to get prompt: {name}"),
        )

    async def authorize_mcp_method(self, *, method: str, params: Dict[str, Any], context: Dict[str, Any], request_purpose: str) -> Dict[str, Any]:
        return await self._mcp_guardrail(
            operation_name=f"mcp.{method}",
            operation_args={"method": method, **params},
            context=context,
            request_purpose=request_purpose,
            text=self._safe_str(context.get("user_prompt") or context.get("request_text") or f"MCP host is attempting JSON-RPC method: {method}"),
        )

    async def _handle_blocking_decision(self, *, decision: Dict[str, Any], rid: Any, context: Dict[str, Any], method: str, operation: str) -> Optional[Dict[str, Any]]:
        if self._verdict(decision) != "BLOCKED":
            return None
        reason = self._reason(decision)
        await self._report_incident_best_effort(
            agent_id=self._host_id(context),
            incident_type="blocked_mcp_operation",
            details=f"method={method} operation={operation} reason={reason}",
        )
        return self.jsonrpc_error(rid, -32000, f"AgenticDome Blocked: {reason}", data={"method": method, "operation": operation})

    # ------------------------------------------------------------------
    # Output sanitization and filtering
    # ------------------------------------------------------------------

    async def sanitize_text(self, *, text: str, context: Dict[str, Any], request_purpose: str = "mcp_output_sanitization") -> str:
        session_id = self._session_id(context)
        host_id = self._host_id(context)
        bounded_text = self._bounded_output_text(text, context)
        try:
            response = await self._to_thread(
                self.client.mesh_validate,
                agent_id=host_id,
                session_id=session_id,
                direction="output",
                text=bounded_text,
                platform=self.config.platform,
                redact_pii=self.config.redact_pii,
                redact_secrets=self.config.redact_secrets,
                block_on_sensitive_output=self.config.block_on_sensitive_output,
                policy_context=self._policy_context(
                    context=context,
                    session_id=session_id,
                    request_purpose=request_purpose,
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
            return self._safe_str(sanitized_text) if sanitized_text is not None else bounded_text
        except (AgenticDomeHTTPError, Exception) as exc:
            logger.warning("AgenticDome MCP output sanitization failed. reason=%s", exc)
            if self.config.fail_closed:
                raise MCPToolBlocked("AgenticDome MCP output sanitization failed") from exc
            return bounded_text

    async def sanitize_mcp_result(self, *, tool_output: Any, context: Dict[str, Any], request_purpose: str = "mcp_tool_output_sanitization") -> Any:
        """Sanitize common MCP result shapes while preserving JSON-RPC response structure."""
        if tool_output is None:
            return None
        if isinstance(tool_output, str):
            return await self.sanitize_text(text=tool_output, context=context, request_purpose=request_purpose)
        if isinstance(tool_output, list):
            return [await self.sanitize_mcp_result(tool_output=item, context=context, request_purpose=request_purpose) for item in tool_output]
        if not isinstance(tool_output, dict):
            return await self.sanitize_text(text=self._safe_str(tool_output), context=context, request_purpose=request_purpose)

        out = copy.deepcopy(tool_output)
        touched_text = False

        for list_key in ("content", "messages"):
            items = out.get(list_key)
            if isinstance(items, list):
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    if isinstance(item.get("text"), str):
                        item["text"] = await self.sanitize_text(text=item["text"], context=context, request_purpose=request_purpose)
                        touched_text = True
                    content = item.get("content")
                    if isinstance(content, dict) and isinstance(content.get("text"), str):
                        content["text"] = await self.sanitize_text(text=content["text"], context=context, request_purpose=request_purpose)
                        touched_text = True
                    elif isinstance(content, str):
                        item["content"] = await self.sanitize_text(text=content, context=context, request_purpose=request_purpose)
                        touched_text = True

        for key in ("text", "description"):
            if isinstance(out.get(key), str):
                out[key] = await self.sanitize_text(text=out[key], context=context, request_purpose=request_purpose)
                touched_text = True

        if touched_text:
            return out

        serialized = json.dumps(out, default=str, sort_keys=True)
        sanitized = await self.sanitize_text(text=serialized, context=context, request_purpose=request_purpose)
        if sanitized == serialized:
            return out
        try:
            return json.loads(sanitized)
        except Exception:
            return sanitized

    async def _filter_named_list_result(
        self,
        *,
        list_result: Any,
        context: Dict[str, Any],
        method: str,
        result_key: str,
        identity_key: str,
        request_purpose: str,
        allowed_keys: Tuple[str, ...],
        blocked_keys: Tuple[str, ...],
    ) -> Any:
        result = copy.deepcopy(list_result)
        items = result.get(result_key) if isinstance(result, dict) else result
        if not isinstance(items, list):
            return result

        identities = [self._safe_str(item.get(identity_key)) for item in items if isinstance(item, dict)]
        decision = await self.authorize_mcp_method(
            method=method,
            params={result_key: identities},
            context=context,
            request_purpose=request_purpose,
        )
        if self._verdict(decision) == "BLOCKED":
            filtered: List[Any] = []
        else:
            env = self._extract_result(decision)
            allowed = next((env.get(key) for key in allowed_keys if isinstance(env.get(key), list)), None)
            blocked = next((env.get(key) for key in blocked_keys if isinstance(env.get(key), list)), [])
            allowed_set = {self._safe_str(item) for item in allowed} if isinstance(allowed, list) else None
            blocked_set = {self._safe_str(item) for item in blocked} if isinstance(blocked, list) else set()
            filtered = []
            for item in items:
                if not isinstance(item, dict):
                    filtered.append(item)
                    continue
                identity = self._safe_str(item.get(identity_key))
                if allowed_set is not None and identity not in allowed_set:
                    continue
                if identity in blocked_set:
                    continue
                filtered.append(item)

        if isinstance(result, dict):
            result[result_key] = filtered
            return result
        return filtered

    async def filter_tools_list_result(self, *, tools_result: Any, context: Dict[str, Any]) -> Any:
        return await self._filter_named_list_result(
            list_result=tools_result,
            context=context,
            method="tools/list",
            result_key="tools",
            identity_key="name",
            request_purpose="mcp_tools_list_filtering",
            allowed_keys=("allowed_tools", "visible_tools"),
            blocked_keys=("blocked_tools", "hidden_tools"),
        )

    async def filter_resources_list_result(self, *, resources_result: Any, context: Dict[str, Any]) -> Any:
        return await self._filter_named_list_result(
            list_result=resources_result,
            context=context,
            method="resources/list",
            result_key="resources",
            identity_key="uri",
            request_purpose="mcp_resources_list_filtering",
            allowed_keys=("allowed_resources", "visible_resources", "allowed_uris", "visible_uris"),
            blocked_keys=("blocked_resources", "hidden_resources", "blocked_uris", "hidden_uris"),
        )

    async def filter_prompts_list_result(self, *, prompts_result: Any, context: Dict[str, Any]) -> Any:
        return await self._filter_named_list_result(
            list_result=prompts_result,
            context=context,
            method="prompts/list",
            result_key="prompts",
            identity_key="name",
            request_purpose="mcp_prompts_list_filtering",
            allowed_keys=("allowed_prompts", "visible_prompts"),
            blocked_keys=("blocked_prompts", "hidden_prompts"),
        )

    async def sanitize_streaming_response(self, *, chunks: Any, context: Dict[str, Any]) -> AsyncIterator[Any]:
        if hasattr(chunks, "__aiter__"):
            async for chunk in chunks:
                yield await self._sanitize_response_chunk(chunk=chunk, context=context)
            return
        if isinstance(chunks, Iterable) and not isinstance(chunks, (str, bytes, dict)):
            for chunk in chunks:
                yield await self._sanitize_response_chunk(chunk=chunk, context=context)
            return
        yield await self._sanitize_response_chunk(chunk=chunks, context=context)

    async def _sanitize_response_chunk(self, *, chunk: Any, context: Dict[str, Any]) -> Any:
        if isinstance(chunk, str):
            return await self.sanitize_text(text=chunk, context=context, request_purpose="mcp_streaming_output_sanitization")
        if isinstance(chunk, dict) and "result" in chunk:
            out = copy.deepcopy(chunk)
            out["result"] = await self.sanitize_mcp_result(tool_output=out["result"], context=context, request_purpose="mcp_streaming_output_sanitization")
            return out
        return await self.sanitize_mcp_result(tool_output=chunk, context=context, request_purpose="mcp_streaming_output_sanitization")

    # ------------------------------------------------------------------
    # Main interceptor APIs
    # ------------------------------------------------------------------

    async def preflight_request(self, *, mcp_request: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Gate a JSON-RPC request before it is forwarded to a third-party MCP server."""
        if not isinstance(mcp_request, dict):
            return self.jsonrpc_error(None, -32600, "Invalid Request")

        rid = self._request_id(mcp_request)
        method = self._method(mcp_request)
        params = self._params(mcp_request)
        local_context = dict(context or {})
        local_context["jsonrpc_request_id"] = rid
        local_context["mcp_method"] = method

        try:
            self._check_rate_limit(context=local_context, method=method)
            prompt_text = self._safe_str(local_context.get("user_prompt") or local_context.get("request_text") or "")
            if self.config.screen_upstream_prompt and prompt_text:
                await self.screen_upstream_prompt(text=prompt_text, context=local_context)

            if method == "tools/call":
                tool_name, tool_args = self._extract_tool_call(mcp_request)
                await self.verify_decision_token_if_present(tool_name=tool_name, tool_args=tool_args, context=local_context)
                decision = await self.authorize_mcp_tool_call(tool_name=tool_name, tool_args=tool_args, context=local_context)
                blocked = await self._handle_blocking_decision(decision=decision, rid=rid, context=local_context, method=method, operation=tool_name)
                if blocked:
                    return blocked
                forwarded_args = self._sanitized_args(decision) or self._strip_internal_args(tool_args)
                self._audit("mcp_request_allowed", context=local_context, details={"method": method, "operation": tool_name})
                return self._replace_tool_args(mcp_request, forwarded_args)

            if method == "resources/read" and self.config.protect_resources_read:
                uri, resource_params = self._extract_resource_read(mcp_request)
                decision = await self.authorize_mcp_resource_read(uri=uri, params=resource_params, context=local_context)
                blocked = await self._handle_blocking_decision(decision=decision, rid=rid, context=local_context, method=method, operation=uri)
                if blocked:
                    return blocked
                sanitized_params = self._sanitized_args(decision)
                self._audit("mcp_request_allowed", context=local_context, details={"method": method, "operation": uri})
                return self._replace_params(mcp_request, sanitized_params) if sanitized_params else mcp_request

            if method == "prompts/get" and self.config.protect_prompts_get:
                name, prompt_params = self._extract_prompt_get(mcp_request)
                decision = await self.authorize_mcp_prompt_get(name=name, params=prompt_params, context=local_context)
                blocked = await self._handle_blocking_decision(decision=decision, rid=rid, context=local_context, method=method, operation=name)
                if blocked:
                    return blocked
                sanitized_params = self._sanitized_args(decision)
                self._audit("mcp_request_allowed", context=local_context, details={"method": method, "operation": name})
                return self._replace_params(mcp_request, sanitized_params) if sanitized_params else mcp_request

            if method == "sampling/createMessage" and self.config.protect_sampling_create_message:
                decision = await self.authorize_mcp_method(method=method, params=params, context=local_context, request_purpose="mcp_sampling_create_message")
                blocked = await self._handle_blocking_decision(decision=decision, rid=rid, context=local_context, method=method, operation=method)
                if blocked:
                    return blocked
                sanitized_params = self._sanitized_args(decision)
                self._audit("mcp_request_allowed", context=local_context, details={"method": method})
                return self._replace_params(mcp_request, sanitized_params) if sanitized_params else mcp_request

            list_methods = {
                "tools/list": self.config.protect_tools_list,
                "resources/list": self.config.protect_resources_list,
                "prompts/list": self.config.protect_prompts_list,
            }
            if list_methods.get(method):
                decision = await self.authorize_mcp_method(method=method, params=params, context=local_context, request_purpose=f"mcp_{method.replace('/', '_')}")
                blocked = await self._handle_blocking_decision(decision=decision, rid=rid, context=local_context, method=method, operation=method)
                if blocked:
                    return blocked
                self._audit("mcp_request_allowed", context=local_context, details={"method": method})
                return mcp_request

            return mcp_request
        except MCPToolBlocked as exc:
            return self.jsonrpc_error(rid, -32000, f"AgenticDome Blocked: {exc}", data={"method": method})
        except (AgenticDomeHTTPError, Exception) as exc:
            if self.config.fail_closed:
                return self.jsonrpc_error(rid, -32000, f"AgenticDome Blocked: {exc}", data={"method": method})
            logger.warning("AgenticDome MCP preflight failed open. reason=%s", exc)
            return mcp_request

    async def _invoke_forwarder(
        self,
        forward_to_third_party: Callable[[Dict[str, Any]], Any],
        request: Dict[str, Any],
    ) -> Any:
        response = forward_to_third_party(request)
        if isawaitable(response):
            response = await response
        return response

    async def _sanitize_forwarded_response(self, *, method: str, response: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(response, dict) or "result" not in response:
            return response

        sanitized_response = copy.deepcopy(response)
        result = sanitized_response["result"]
        if method == "tools/list" and self.config.protect_tools_list:
            sanitized_response["result"] = await self.filter_tools_list_result(tools_result=result, context=context)
            return sanitized_response
        if method == "resources/list" and self.config.protect_resources_list:
            sanitized_response["result"] = await self.filter_resources_list_result(resources_result=result, context=context)
            return sanitized_response
        if method == "prompts/list" and self.config.protect_prompts_list:
            sanitized_response["result"] = await self.filter_prompts_list_result(prompts_result=result, context=context)
            return sanitized_response
        if method == "resources/read" and self.config.sanitize_resource_output:
            sanitized_response["result"] = await self.sanitize_mcp_result(tool_output=result, context=context, request_purpose="mcp_resource_output_sanitization")
            return sanitized_response
        if method == "prompts/get" and self.config.sanitize_prompt_output:
            sanitized_response["result"] = await self.sanitize_mcp_result(tool_output=result, context=context, request_purpose="mcp_prompt_output_sanitization")
            return sanitized_response
        if method == "sampling/createMessage" and self.config.sanitize_sampling_output:
            sanitized_response["result"] = await self.sanitize_mcp_result(tool_output=result, context=context, request_purpose="mcp_sampling_output_sanitization")
            return sanitized_response
        if method == "tools/call" and self.config.sanitize_tool_output:
            sanitized_response["result"] = await self.sanitize_mcp_result(tool_output=result, context=context, request_purpose="mcp_tool_output_sanitization")
            return sanitized_response
        return sanitized_response

    async def forward_with_firewall(
        self,
        *,
        mcp_request: Dict[str, Any],
        context: Dict[str, Any],
        forward_to_third_party: Callable[[Dict[str, Any]], Any],
    ) -> Any:
        """Preflight, forward, and optionally sanitize a third-party MCP response."""
        method = self._method(mcp_request) if isinstance(mcp_request, dict) else ""
        local_context = dict(context or {})
        local_context["mcp_method"] = method

        gated = await self.preflight_request(mcp_request=mcp_request, context=context)
        if isinstance(gated, dict) and "error" in gated:
            return gated

        response = await self._invoke_forwarder(forward_to_third_party, gated)
        if self.config.sanitize_streaming_output and hasattr(response, "__aiter__"):
            return self.sanitize_streaming_response(chunks=response, context=local_context)
        if self.config.sanitize_streaming_output and inspect.isgenerator(response):
            return self.sanitize_streaming_response(chunks=response, context=local_context)
        if not isinstance(response, dict):
            return response

        try:
            return await self._sanitize_forwarded_response(method=method, response=response, context=local_context)
        except MCPToolBlocked:
            raise
        except Exception as exc:
            logger.warning("AgenticDome MCP result sanitization failed; returning original response. reason=%s", exc)
            return response


__all__ = [
    "AgenticDomeMCPHostFirewall",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "FirewallConfig",
    "InMemoryDecisionTokenStore",
    "MCPConfigurationError",
    "MCPFirewallError",
    "MCPToolBlocked",
    "RedisDecisionTokenStore",
    "load_config",
]
