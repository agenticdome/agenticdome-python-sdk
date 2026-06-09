from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar

import anyio

try:
    from pydantic_ai import Agent, RunContext
    from pydantic_ai.models import ModelResponse
except Exception as exc:  # pragma: no cover
    raise ImportError(
        "AgenticDome PydanticAI integration requires pydantic-ai. "
        "Install with: pip install 'agenticdome-python-sdk[pydanticai]'"
    ) from exc

from agenticdome_sdk.client import AgentGuardClient

try:
    from agenticdome_sdk.exceptions import AgentGuardHTTPError
except Exception:  # pragma: no cover
    try:
        from agenticdome_sdk.client import AgentGuardHTTPError  # type: ignore
    except Exception:
        class AgentGuardHTTPError(Exception):  # type: ignore
            pass


logger = logging.getLogger("agenticdome.pydanticai")
logger.setLevel(logging.INFO)

DepsT = TypeVar("DepsT")


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class FirewallConfig:
    api_base: str = field(
        default_factory=lambda: os.getenv(
            "AGENTICDOME_API_BASE",
            "https://au.agenticdome.io",
        ).rstrip("/")
    )
    api_key: str = field(default_factory=lambda: os.getenv("AGENTICDOME_API_KEY", ""))
    tenant_id: str = field(default_factory=lambda: os.getenv("AGENTICDOME_TENANT_ID", ""))

    platform: str = field(default_factory=lambda: os.getenv("AGENTICDOME_PLATFORM", "pydanticai"))
    timeout_s: int = field(default_factory=lambda: _env_int("AGENTICDOME_TIMEOUT_S", 20))
    fail_closed: bool = field(default_factory=lambda: _env_bool("AGENTICDOME_FAIL_CLOSED", True))

    require_explicit_session_id: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False)
    )
    default_tool_platform: str = field(
        default_factory=lambda: os.getenv("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "python")
    )

    redact_pii: bool = field(default_factory=lambda: _env_bool("AGENTICDOME_REDACT_PII", True))
    redact_secrets: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_REDACT_SECRETS", True)
    )
    block_on_sensitive_output: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False)
    )

    enable_a2a_for_delegation: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_ENABLE_A2A_FOR_DELEGATION", True)
    )
    handoff_token_ttl_s: int = field(
        default_factory=lambda: _env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900)
    )

    redis_url: str = field(default_factory=lambda: os.getenv("AGENTICDOME_REDIS_URL", "").strip())
    redis_key_prefix: str = field(
        default_factory=lambda: os.getenv(
            "AGENTICDOME_REDIS_KEY_PREFIX",
            "AgenticDome:pydanticai:handoff",
        )
    )

    report_incidents: bool = field(
        default_factory=lambda: _env_bool("AGENTICDOME_REPORT_INCIDENTS", True)
    )
    blocked_incident_severity: str = field(
        default_factory=lambda: os.getenv("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium")
    )


class PydanticAIFirewallError(RuntimeError):
    """Base exception for AgenticDome PydanticAI firewall errors."""


class PydanticAIFirewallDenied(PydanticAIFirewallError):
    """Raised when AgenticDome explicitly blocks execution."""


@dataclass(frozen=True)
class DecisionTokenRecord:
    decision_token: str
    source_agent_id: str
    created_at: float


# ------------------------------------------------------------------
# Token Store
# ------------------------------------------------------------------

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


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def _tool_fingerprint(tool_name: str, tool_args: Dict[str, Any]) -> str:
    payload = {
        "tool_name": tool_name or "",
        "tool_args": tool_args or {},
    }
    return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()


class InMemoryDecisionTokenStore(DecisionTokenStore):
    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id
        self._lock = Lock()
        self._data: Dict[str, Tuple[float, DecisionTokenRecord]] = {}

    def _key(
        self,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        fp = _tool_fingerprint(tool_name, tool_args)
        return f"{self._tenant_id}:{session_id}:{target_agent_id}:{fp}"

    def _cleanup(self) -> None:
        now = time.time()
        expired = [
            key for key, (expires_at, _) in self._data.items()
            if expires_at <= now
        ]
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
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
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
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
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
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        with self._lock:
            self._data.pop(key, None)


class RedisDecisionTokenStore(DecisionTokenStore):
    def __init__(self, url: str, prefix: str, tenant_id: str) -> None:
        import redis

        self.r = redis.Redis.from_url(url, decode_responses=True)
        self.prefix = f"{prefix}:{tenant_id}"

    def _key(
        self,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        fp = _tool_fingerprint(tool_name, tool_args)
        return f"{self.prefix}:{session_id}:{target_agent_id}:{fp}"

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
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        payload = {
            "decision_token": record.decision_token,
            "source_agent_id": record.source_agent_id,
            "created_at": record.created_at,
        }
        self.r.setex(key, ttl_s, json.dumps(payload))

    def get(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> Optional[DecisionTokenRecord]:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        raw = self.r.get(key)
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
            return None

    def delete(
        self,
        *,
        session_id: str,
        target_agent_id: str,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        key = self._key(session_id, target_agent_id, tool_name, tool_args)
        self.r.delete(key)


def _build_token_store(config: FirewallConfig) -> DecisionTokenStore:
    if config.redis_url:
        try:
            return RedisDecisionTokenStore(
                config.redis_url,
                config.redis_key_prefix,
                config.tenant_id,
            )
        except ImportError:
            logger.warning(
                "Redis package missing. Install with: "
                "pip install 'agenticdome-python-sdk[redis]'. "
                "Using in-memory token cache."
            )
        except Exception as exc:
            logger.warning(
                "Redis token store unavailable: %s. Using in-memory token cache.",
                exc,
            )

    return InMemoryDecisionTokenStore(config.tenant_id)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _safe_getattr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _safe_setattr(obj: Any, name: str, value: Any) -> None:
    try:
        setattr(obj, name, value)
        return
    except Exception:
        pass

    try:
        if hasattr(obj, "__dict__"):
            obj.__dict__[name] = value
    except Exception:
        pass


def _is_handoff_tool(tool_name: str) -> bool:
    lower = tool_name.lower()
    return any(marker in lower for marker in ("delegate", "handoff", "route", "transfer"))


def _target_agent_id(kwargs: Dict[str, Any]) -> str:
    return str(
        kwargs.get("target_agent_id")
        or kwargs.get("coworker")
        or kwargs.get("agent")
        or kwargs.get("specialist_agent_id")
        or "specialist"
    )


def _target_tool_name(current_tool_name: str, kwargs: Dict[str, Any]) -> str:
    return str(
        kwargs.get("target_tool_name")
        or kwargs.get("tool_name")
        or kwargs.get("skill_name")
        or current_tool_name
    )


def _target_tool_args(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    raw = (
        kwargs.get("target_tool_args")
        or kwargs.get("skill_args")
        or kwargs.get("arguments")
        or {}
    )

    if isinstance(raw, dict):
        return dict(raw)

    return {"_raw_input": str(raw)}


def _strip_private_args(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in kwargs.items()
        if not key.startswith("_AgenticDome_") and not key.startswith("_decision_")
    }


def _run_async_from_sync(async_fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return anyio.from_thread.run(async_fn, *args, **kwargs)
    except RuntimeError:
        return anyio.run(async_fn, *args, **kwargs)


# ------------------------------------------------------------------
# PydanticAI Firewall
# ------------------------------------------------------------------

class CyberSecFirewall:
    """
    AgenticDome Security Firewall for PydanticAI.

    Provides:
    - Prompt ingress screening where supported by the PydanticAI runtime
    - Tool execution authorization
    - Manager-to-specialist delegation token generation
    - Specialist decision-token verification
    - Output DLP sanitization
    """

    def __init__(self, config: Optional[FirewallConfig] = None) -> None:
        self.config = config or FirewallConfig()

        if not self.config.api_base or not self.config.api_key or not self.config.tenant_id:
            logger.warning(
                "AgenticDome PydanticAI firewall unconfigured. "
                "Set AGENTICDOME_API_BASE, AGENTICDOME_API_KEY, and AGENTICDOME_TENANT_ID. "
                "Runtime will operate in fail-open mode for SDK calls."
            )
            self.client: Optional[AgentGuardClient] = None
        else:
            self.client = AgentGuardClient(
                api_base=self.config.api_base,
                api_key=self.config.api_key,
                tenant_id=self.config.tenant_id,
                timeout=self.config.timeout_s,
            )

        self.token_store = _build_token_store(self.config)

    async def _to_thread(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))

    def _client_call(self, method_names: Tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
        if self.client is None:
            return None

        last_type_error: Optional[TypeError] = None

        for method_name in method_names:
            method = getattr(self.client, method_name, None)
            if method is None:
                continue

            try:
                return method(*args, **kwargs)
            except TypeError as exc:
                last_type_error = exc
                continue

        if last_type_error:
            raise last_type_error

        raise AttributeError(
            f"AgenticDome client does not implement any of: {', '.join(method_names)}"
        )

    def _extract_payload(self, response: Any) -> Dict[str, Any]:
        if isinstance(response, dict):
            result = response.get("result")
            if isinstance(result, dict):
                return result
            return response
        return {}

    def _extract_verdict(self, response: Any) -> str:
        payload = self._extract_payload(response)
        return str(payload.get("verdict") or payload.get("decision") or "ALLOWED").upper()

    def _reason(self, response: Any) -> str:
        payload = self._extract_payload(response)
        return str(payload.get("reason") or payload.get("message") or response)

    def _decision_token(self, response: Any) -> Optional[str]:
        payload = self._extract_payload(response)
        token = payload.get("decision_token") or payload.get("token")
        return str(token) if token else None

    def _agent_name(self, ctx: RunContext[Any], fallback: str = "unnamed_agent") -> str:
        agent = _safe_getattr(ctx, "agent")
        value = (
            _safe_getattr(agent, "name")
            or _safe_getattr(ctx, "agent_name")
            or _safe_getattr(_safe_getattr(ctx, "deps"), "agent_id")
        )
        return str(value) if value else fallback

    def _session_id(self, ctx: RunContext[Any]) -> str:
        deps = _safe_getattr(ctx, "deps")

        for attr in ("run_id", "trace_id", "session_id", "task_id"):
            value = _safe_getattr(ctx, attr) or _safe_getattr(deps, attr)
            if value:
                return str(value)

        if self.config.require_explicit_session_id:
            raise PydanticAIFirewallDenied(
                "Strict mode error: missing session_id, run_id, trace_id, or task_id."
            )

        return f"pydanticai-session-{id(ctx)}"

    def _report_incident(
        self,
        *,
        agent_id: str,
        incident_type: str,
        severity: Optional[str] = None,
        details: str = "",
    ) -> None:
        if self.client is None or not self.config.report_incidents:
            return

        try:
            self._client_call(
                ("report_incident", "reportIncident"),
                agent_id=agent_id,
                incident_type=incident_type,
                severity=severity or self.config.blocked_incident_severity,
                details=details,
                tenant_id=self.config.tenant_id,
                is_agent=True,
                platform=self.config.platform,
            )
        except Exception as exc:
            logger.debug("AgenticDome incident reporting failed: %s", exc)

    def _handle_error(self, stage: str, exc: Exception, agent_id: str = "unknown") -> None:
        logger.error("AgenticDome PydanticAI %s error: %s", stage, exc)

        self._report_incident(
            agent_id=agent_id,
            incident_type=f"pydanticai_{stage}_error",
            severity=self.config.blocked_incident_severity,
            details=str(exc),
        )

        if self.config.fail_closed:
            if isinstance(exc, PydanticAIFirewallDenied):
                raise exc
            raise PydanticAIFirewallDenied(f"AgenticDome security check failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Agent lifecycle hooks
    # ------------------------------------------------------------------

    def attach_to_agent(self, agent: Agent[DepsT, Any]) -> None:
        """
        Attach prompt ingress and response egress hooks to a PydanticAI Agent
        when the installed PydanticAI runtime exposes compatible hook decorators.

        PydanticAI hook APIs may vary by version. If lifecycle decorators are not
        available, use secure_tool() around tools for tool perimeter security.
        """

        before_runner_init = getattr(agent, "before_runner_init", None)
        after_runner_end = getattr(agent, "after_runner_end", None)

        if callable(before_runner_init):
            @before_runner_init
            def _ingress_prompt_shield(ctx: RunContext[DepsT], prompt: str) -> str:
                if self.client is None or not str(prompt or "").strip():
                    return prompt

                agent_id = getattr(agent, "name", None) or self._agent_name(ctx)

                try:
                    response = self._client_call(
                        ("guardrail_validate", "guardrailValidate"),
                        text=str(prompt),
                        agent_id=agent_id,
                        platform=self.config.platform,
                        source_platform=self.config.platform,
                        direction="input",
                        session_id=self._session_id(ctx),
                        policy_context={
                            "source_agent_id": agent_id,
                            "request_purpose": "pydanticai_prompt_input",
                            "platform": self.config.platform,
                        },
                    )

                    if self._extract_verdict(response) == "BLOCKED":
                        raise PydanticAIFirewallDenied(
                            f"AgenticDome prompt shield blocked input: {self._reason(response)}"
                        )
                except Exception as exc:
                    self._handle_error("before_runner_init", exc, agent_id)

                return prompt

        else:
            logger.info(
                "PydanticAI agent does not expose before_runner_init. "
                "Prompt lifecycle hook not attached."
            )

        if callable(after_runner_end):
            @after_runner_end
            def _egress_dlp_shield(
                ctx: RunContext[DepsT],
                response: ModelResponse,
            ) -> ModelResponse:
                if self.client is None:
                    return response

                agent_id = getattr(agent, "name", None) or self._agent_name(ctx)

                try:
                    messages = getattr(response, "messages", None)
                    if not messages:
                        return response

                    last_msg = messages[-1]
                    parts = getattr(last_msg, "parts", None)
                    if not parts:
                        return response

                    for part in parts:
                        content = getattr(part, "content", None)
                        if not isinstance(content, str):
                            continue

                        scan = self._client_call(
                            ("mesh_validate", "meshValidate"),
                            text=content,
                            agent_id=agent_id,
                            direction="output",
                            session_id=self._session_id(ctx),
                            platform=self.config.platform,
                            redact_pii=self.config.redact_pii,
                            redact_secrets=self.config.redact_secrets,
                            block_on_sensitive_output=self.config.block_on_sensitive_output,
                            policy_context={
                                "source_agent_id": agent_id,
                                "request_purpose": "pydanticai_output_review",
                                "platform": self.config.platform,
                                "redact_pii": self.config.redact_pii,
                                "redact_secrets": self.config.redact_secrets,
                                "block_on_sensitive_output": self.config.block_on_sensitive_output,
                            },
                        )

                        payload = self._extract_payload(scan)
                        verdict = self._extract_verdict(scan)

                        if verdict == "BLOCKED" or self.config.block_on_sensitive_output:
                            part.content = (
                                "[EGRESS PAYLOAD TERMINATED BY AGENTICDOME DLP SECURITY MESH]"
                            )
                            continue

                        sanitized = (
                            payload.get("sanitized_text")
                            or payload.get("text")
                            or payload.get("output")
                        )

                        if sanitized is not None:
                            part.content = str(sanitized)

                except Exception as exc:
                    logger.error("AgenticDome PydanticAI after_runner_end error: %s", exc)
                    if self.config.fail_closed:
                        try:
                            messages = getattr(response, "messages", None)
                            if messages and getattr(messages[-1], "parts", None):
                                for part in messages[-1].parts:
                                    if hasattr(part, "content"):
                                        part.content = (
                                            "[FATAL ERROR: AGENTICDOME SECURITY CHECK FAULTED]"
                                        )
                        except Exception:
                            pass

                return response

        else:
            logger.info(
                "PydanticAI agent does not expose after_runner_end. "
                "Output lifecycle hook not attached."
            )

    # ------------------------------------------------------------------
    # Tool perimeter
    # ------------------------------------------------------------------

    def secure_tool(self, tool_func: Callable[..., Any]) -> Callable[..., Any]:
        """
        Decorator that protects a PydanticAI tool.

        It performs:
        - Delegation-token verification for specialist calls
        - A2A authorization and token minting for manager handoff tools
        - Direct tool authorization for normal tools
        - Output DLP screening after execution
        """

        if asyncio.iscoroutinefunction(tool_func):
            @functools.wraps(tool_func)
            async def _async_wrapper(ctx: RunContext[Any], *args: Any, **kwargs: Any) -> Any:
                clean_kwargs, _ = await self._pre_execute_tool_check(
                    ctx,
                    tool_func.__name__,
                    dict(kwargs),
                )
                result = await tool_func(ctx, *args, **clean_kwargs)
                return await self._post_execute_tool_sanitize(ctx, result)

            return _async_wrapper

        @functools.wraps(tool_func)
        def _sync_wrapper(ctx: RunContext[Any], *args: Any, **kwargs: Any) -> Any:
            clean_kwargs, _ = _run_async_from_sync(
                self._pre_execute_tool_check,
                ctx,
                tool_func.__name__,
                dict(kwargs),
            )
            result = tool_func(ctx, *args, **clean_kwargs)
            return _run_async_from_sync(self._post_execute_tool_sanitize, ctx, result)

        return _sync_wrapper

    async def _pre_execute_tool_check(
        self,
        ctx: RunContext[Any],
        name: str,
        kwargs: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], bool]:
        if self.client is None:
            return kwargs, False

        session_id = self._session_id(ctx)
        agent_id = self._agent_name(ctx)

        token = kwargs.pop("_AgenticDome_decision_token", None) or kwargs.pop("_decision_token", None)
        source_agent_id = kwargs.pop("_AgenticDome_source_agent_id", None) or kwargs.pop(
            "_source_agent_id",
            None,
        )

        clean_kwargs = _strip_private_args(kwargs)

        # Case A: Specialist execution verifies delegated decision token.
        if token and source_agent_id:
            response = await self._to_thread(
                self._client_call,
                ("a2a_verify_decision_token_rpc", "a2aVerifyDecisionTokenRpc", "a2a_verify_decision_token"),
                str(token),
                tool_name=name,
                tool_args=clean_kwargs,
                agent_id=agent_id,
                source_agent_id=str(source_agent_id),
                platform=self.config.platform,
                require_allowed=True,
            )

            payload = self._extract_payload(response)

            if payload and payload.get("valid") is False:
                raise PydanticAIFirewallDenied(
                    f"AgenticDome rejected handoff token: {self._reason(response)}"
                )

            return clean_kwargs, True

        # Case B: Manager handoff tool authorizes delegation and injects token.
        if self.config.enable_a2a_for_delegation and _is_handoff_tool(name):
            target_agent_id = _target_agent_id(clean_kwargs)
            target_tool_name = _target_tool_name(name, clean_kwargs)
            target_args = _target_tool_args(clean_kwargs)

            response = await self._to_thread(
                self._client_call,
                ("a2a_authorize_tool", "a2aAuthorizeTool"),
                text=f"PydanticAI manager {agent_id} delegating {target_tool_name} to {target_agent_id}",
                agent_id=target_agent_id,
                platform=self.config.platform,
                source_platform=self.config.platform,
                tool_platform=str(clean_kwargs.get("tool_platform") or self.config.default_tool_platform),
                tool_name=target_tool_name,
                tool_args=target_args,
                session_id=session_id,
                direction="outbound",
                source_agent_id=agent_id,
                policy_context={
                    "source_agent_id": agent_id,
                    "request_purpose": "pydanticai_delegated_task",
                    "platform": self.config.platform,
                    "delegation_chain": [agent_id, target_agent_id],
                },
            )

            if self._extract_verdict(response) == "BLOCKED":
                raise PydanticAIFirewallDenied(
                    f"AgenticDome blocked PydanticAI delegation: {self._reason(response)}"
                )

            decision_token = self._decision_token(response)

            if decision_token:
                clean_kwargs["_AgenticDome_decision_token"] = decision_token
                clean_kwargs["_AgenticDome_source_agent_id"] = agent_id

                target_args["_AgenticDome_decision_token"] = decision_token
                target_args["_AgenticDome_source_agent_id"] = agent_id

                if "target_tool_args" in clean_kwargs or "skill_args" not in clean_kwargs:
                    clean_kwargs["target_tool_args"] = target_args
                else:
                    clean_kwargs["skill_args"] = target_args

                self.token_store.put(
                    session_id=session_id,
                    target_agent_id=target_agent_id,
                    tool_name=target_tool_name,
                    tool_args=target_args,
                    record=DecisionTokenRecord(
                        decision_token=decision_token,
                        source_agent_id=agent_id,
                        created_at=time.time(),
                    ),
                    ttl_s=self.config.handoff_token_ttl_s,
                )

            return clean_kwargs, False

        # Case C: Direct tool authorization.
        response = await self._to_thread(
            self._client_call,
            ("guardrail_validate", "guardrailValidate"),
            text=f"PydanticAI tool execution: {name}",
            agent_id=agent_id,
            platform=self.config.platform,
            source_platform=self.config.platform,
            tool_platform=str(clean_kwargs.get("tool_platform") or self.config.default_tool_platform),
            tool_name=name,
            tool_args=clean_kwargs,
            direction="outbound",
            session_id=session_id,
            policy_context={
                "source_agent_id": agent_id,
                "request_purpose": "pydanticai_tool_execution",
                "platform": self.config.platform,
            },
        )

        if self._extract_verdict(response) == "BLOCKED":
            raise PydanticAIFirewallDenied(
                f"AgenticDome blocked tool execution '{name}': {self._reason(response)}"
            )

        return clean_kwargs, False

    async def _post_execute_tool_sanitize(self, ctx: RunContext[Any], result: Any) -> Any:
        if self.client is None:
            return result

        agent_id = self._agent_name(ctx)

        if isinstance(result, (dict, list, tuple)):
            raw_text = json.dumps(result, default=str)
        else:
            raw_text = str(result)

        response = await self._to_thread(
            self._client_call,
            ("mesh_validate", "meshValidate"),
            text=raw_text,
            agent_id=agent_id,
            direction="output",
            session_id=self._session_id(ctx),
            platform=self.config.platform,
            redact_pii=self.config.redact_pii,
            redact_secrets=self.config.redact_secrets,
            block_on_sensitive_output=self.config.block_on_sensitive_output,
            policy_context={
                "source_agent_id": agent_id,
                "request_purpose": "pydanticai_tool_output_review",
                "platform": self.config.platform,
                "redact_pii": self.config.redact_pii,
                "redact_secrets": self.config.redact_secrets,
                "block_on_sensitive_output": self.config.block_on_sensitive_output,
            },
        )

        payload = self._extract_payload(response)
        verdict = self._extract_verdict(response)

        if verdict == "BLOCKED":
            return "[BLOCKED BY AGENTICDOME ACTION LAYER DLP]"

        sanitized = (
            payload.get("sanitized_text")
            or payload.get("text")
            or payload.get("output")
        )

        if sanitized is not None:
            if isinstance(result, str):
                return str(sanitized)

            if self.config.block_on_sensitive_output:
                return str(sanitized)

        return result


__all__ = [
    "FirewallConfig",
    "PydanticAIFirewallError",
    "PydanticAIFirewallDenied",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "CyberSecFirewall",
]
