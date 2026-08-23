from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from ._framework_firewall import (
    DecisionTokenRecord,
    DecisionTokenStore,
    FrameworkFirewallBase,
    FrameworkFirewallConfig,
    InMemoryDecisionTokenStore,
    RedisDecisionTokenStore,
)
from .client import AgenticDomeClient

import logging


logger = logging.getLogger("agenticdome.smolagents")

try:  # Keep the core SDK importable without optional framework dependencies.
    from smolagents import Tool as _SmolTool

    _SMOLAGENTS_AVAILABLE = True
except ImportError:  # pragma: no cover - the fallback is exercised by packaging users
    _SMOLAGENTS_AVAILABLE = False

    class _SmolTool:  # type: ignore[no-redef]
        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            return self.forward(*args, **kwargs)


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, os.getenv(name.replace("AGENTICDOME", "AgenticDome"), default))


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name)
    return default if value == "" else value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class FirewallConfig(FrameworkFirewallConfig):
    platform: str = "smolagents"
    agent_id: str = "smolagent"
    default_tool_platform: str = "python"
    redis_key_prefix: str = "AgenticDome:smolagents:handoff"
    scan_code_expressions: bool = True
    strict_delegated_execution: bool = True


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY"),
        tenant_id=_env("AGENTICDOME_TENANT_ID"),
        platform=_env("AGENTICDOME_PLATFORM", "smolagents"),
        agent_id=_env("AGENTICDOME_SMOLAGENTS_AGENT_ID", "smolagent"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "python"),
        timeout_s=_env_int("AGENTICDOME_TIMEOUT_S", 20),
        fail_closed=_env_bool("AGENTICDOME_FAIL_CLOSED", True),
        production_mode=_env_bool("AGENTICDOME_PRODUCTION_MODE", False),
        require_explicit_session_id=_env_bool("AGENTICDOME_REQUIRE_SESSION_ID", False),
        require_stable_session_id_in_prod=_env_bool("AGENTICDOME_REQUIRE_STABLE_SESSION_ID_IN_PROD", True),
        redact_pii=_env_bool("AGENTICDOME_REDACT_PII", True),
        redact_secrets=_env_bool("AGENTICDOME_REDACT_SECRETS", True),
        block_on_sensitive_output=_env_bool("AGENTICDOME_BLOCK_ON_SENSITIVE_OUTPUT", False),
        handoff_token_ttl_s=_env_int("AGENTICDOME_HANDOFF_TOKEN_TTL_S", 900),
        redis_url=_env("AGENTICDOME_REDIS_URL").strip(),
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:smolagents:handoff"),
        token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET"),
        max_input_chars=_env_int("AGENTICDOME_SMOLAGENTS_MAX_INPUT_CHARS", 50_000),
        max_output_chars=_env_int("AGENTICDOME_SMOLAGENTS_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_SMOLAGENTS_MAX_TOOL_ARG_CHARS", 20_000),
        streaming_buffer_chars=_env_int("AGENTICDOME_SMOLAGENTS_STREAMING_BUFFER_CHARS", 4_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_SMOLAGENTS_RATE_LIMIT_PER_MINUTE", 0),
        retry_attempts=_env_int("AGENTICDOME_SMOLAGENTS_RETRY_ATTEMPTS", 2),
        retry_backoff_s=_env_float("AGENTICDOME_SMOLAGENTS_RETRY_BACKOFF_S", 0.25),
        circuit_breaker_failures=_env_int("AGENTICDOME_SMOLAGENTS_CIRCUIT_BREAKER_FAILURES", 5),
        circuit_breaker_reset_s=_env_int("AGENTICDOME_SMOLAGENTS_CIRCUIT_BREAKER_RESET_S", 60),
        audit_logging=_env_bool("AGENTICDOME_SMOLAGENTS_AUDIT_LOGGING", True),
        otel_enabled=_env_bool("AGENTICDOME_SMOLAGENTS_OTEL_ENABLED", True),
        emergency_block_tools=_env("AGENTICDOME_SMOLAGENTS_EMERGENCY_BLOCK_TOOLS"),
        emergency_block_agents=_env("AGENTICDOME_SMOLAGENTS_EMERGENCY_BLOCK_AGENTS"),
        strict_delegated_execution=_env_bool("AGENTICDOME_SMOLAGENTS_STRICT_DELEGATED_EXECUTION", True),
        scan_code_expressions=_env_bool("AGENTICDOME_SMOLAGENTS_SCAN_CODE_EXPRESSIONS", True),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
    )


class SmolagentsFirewallError(RuntimeError):
    """Base error for the Hugging Face smolagents adapter."""


class SmolagentsFirewallDenied(SmolagentsFirewallError):
    """Raised when AgenticDome denies a smolagents boundary."""


class SmolagentsFirewallConfigurationError(SmolagentsFirewallError):
    """Raised when credentials or stable runtime context are missing."""


ToolBlocked = SmolagentsFirewallDenied
FirewallMisconfigured = SmolagentsFirewallConfigurationError


class SecureSmolTool(_SmolTool):
    """A native smolagents ``Tool`` that authorizes immediately before ``forward``."""

    skip_forward_signature_validation = True

    def __init__(
        self,
        native_tool: Any,
        firewall: "AgenticDomeSmolagentsFirewall",
        *,
        session_id: str,
        agent_id: str,
        tool_platform: Optional[str] = None,
    ) -> None:
        if not _SMOLAGENTS_AVAILABLE:
            raise ImportError(
                "smolagents integration requires: pip install 'agenticdome-python-sdk[smolagents]'"
            )
        self.native_tool = native_tool
        self.firewall = firewall
        self.session_id = session_id
        self.agent_id = agent_id
        self.tool_platform = tool_platform
        self.name = str(native_tool.name)
        self.description = str(native_tool.description)
        self.inputs = dict(native_tool.inputs)
        self.output_type = str(native_tool.output_type)
        self.output_schema = getattr(native_tool, "output_schema", None)
        self.is_initialized = True

    def forward(self, *args: Any, **kwargs: Any) -> Any:
        call_args = dict(kwargs)
        for index, value in enumerate(args):
            if index < len(self.inputs):
                call_args.setdefault(list(self.inputs)[index], value)
        decision = self.firewall.authorize_tool_call(
            session_id=self.session_id,
            agent_id=self.agent_id,
            tool_name=self.name,
            tool_args=call_args,
            text=f"[smolagents] {self.agent_id} calls {self.name}",
            tool_platform=self.tool_platform,
        )
        clean = self.firewall.sanitized_args(decision, call_args)
        result = self.native_tool(**clean)
        return self.firewall.review_value(
            result,
            session_id=self.session_id,
            agent_id=self.agent_id,
            policy_context={"tool_name": self.name, "request_purpose": "smolagents_tool_output"},
        )


class SecurePythonExecutor:
    """Transparent CodeAgent executor proxy that scans code before execution."""

    def __init__(
        self,
        native_executor: Any,
        firewall: "AgenticDomeSmolagentsFirewall",
        *,
        session_id: str,
        agent_id: str,
    ) -> None:
        self.native_executor = native_executor
        self.firewall = firewall
        self.session_id = session_id
        self.agent_id = agent_id
        self._agenticdome_wrapped = True

    def __call__(self, code: str) -> Any:
        executable = code
        if self.firewall.config.scan_code_expressions:
            decision = self.firewall.authorize_tool_call(
                session_id=self.session_id,
                agent_id=self.agent_id,
                tool_name="python_interpreter",
                tool_args={"code": code},
                text=f"[smolagents CodeAgent] generated Python expression:\n{code}",
                tool_platform="python",
                policy_context={"request_purpose": "smolagents_code_execution", "code_execution": True},
            )
            executable = str(self.firewall.sanitized_args(decision, {"code": code}).get("code", code))
        return self.native_executor(executable)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.native_executor, name)


class SecureManagedAgent:
    """Authorize and verify a smolagents manager-to-managed-agent invocation."""

    def __init__(
        self,
        native_agent: Any,
        firewall: "AgenticDomeSmolagentsFirewall",
        *,
        session_id: str,
        manager_agent_id: str,
    ) -> None:
        self.native_agent = native_agent
        self.firewall = firewall
        self.session_id = session_id
        self.manager_agent_id = manager_agent_id
        self.name = str(native_agent.name)
        self.description = str(native_agent.description)
        self.inputs = getattr(native_agent, "inputs", {})
        self.output_type = getattr(native_agent, "output_type", "string")
        self._agenticdome_wrapped = True

    def __call__(self, task: str, **kwargs: Any) -> Any:
        tool_name = f"managed_agent.{self.name}"
        tool_args = {"task": task, **kwargs}
        self.firewall.authorize_manager_handoff(
            session_id=self.session_id,
            manager_agent_id=self.manager_agent_id,
            specialist_agent_id=self.name,
            tool_name=tool_name,
            tool_args=tool_args,
            text=f"[smolagents] {self.manager_agent_id} delegates a task to {self.name}",
            tool_platform="smolagents",
        )
        if self.firewall.config.strict_delegated_execution:
            self.firewall.verify_specialist_execution(
                session_id=self.session_id,
                specialist_agent_id=self.name,
                tool_name=tool_name,
                tool_args=tool_args,
            )
        result = self.native_agent(task, **kwargs)
        return self.firewall.review_value(
            result,
            session_id=self.session_id,
            agent_id=self.name,
            policy_context={"source_agent_id": self.manager_agent_id, "request_purpose": "smolagents_handoff_output"},
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self.native_agent, name)


class AgenticDomeSmolagentsFirewall(FrameworkFirewallBase):
    """Tool, generated-code, managed-agent, and output enforcement for smolagents."""

    def __init__(
        self,
        config: Optional[FirewallConfig] = None,
        *,
        client: Optional[AgenticDomeClient] = None,
        token_store: Optional[DecisionTokenStore] = None,
    ) -> None:
        super().__init__(
            config or load_config(),
            client=client,
            token_store=token_store,
            denied_error=SmolagentsFirewallDenied,
            configuration_error=SmolagentsFirewallConfigurationError,
            label="smolagents",
            logger=logger,
        )

    authorize_direct_tool_call = FrameworkFirewallBase.authorize_tool_call

    def wrap_tool(
        self,
        native_tool: Any,
        *,
        session_id: str,
        agent_id: Optional[str] = None,
        tool_platform: Optional[str] = None,
    ) -> SecureSmolTool:
        return SecureSmolTool(
            native_tool,
            self,
            session_id=session_id,
            agent_id=agent_id or self.config.agent_id,
            tool_platform=tool_platform,
        )

    def create_step_callback(
        self,
        *,
        session_id: str,
        agent_id: Optional[str] = None,
    ) -> Callable[..., None]:
        """Sanitize observations before the next model step consumes them."""
        effective_agent_id = agent_id or self.config.agent_id

        def callback(memory_step: Any, agent: Any = None) -> None:
            del agent
            for attribute in ("observations", "action_output"):
                value = getattr(memory_step, attribute, None)
                if value is None:
                    continue
                reviewed = self.review_value(
                    value,
                    session_id=session_id,
                    agent_id=effective_agent_id,
                    policy_context={"request_purpose": "smolagents_step_observation"},
                )
                try:
                    setattr(memory_step, attribute, reviewed)
                except Exception:
                    pass

        callback.__name__ = "agenticdome_smolagents_step_callback"
        return callback

    def attach_firewall(
        self,
        agent: Any,
        *,
        session_id: str,
        agent_id: Optional[str] = None,
        include_step_callback: bool = True,
    ) -> Any:
        """Patch an initialized CodeAgent/ToolCallingAgent at native boundaries."""
        effective_agent_id = agent_id or getattr(agent, "name", None) or self.config.agent_id
        existing_firewall = getattr(agent, "_agenticdome_firewall", None)
        existing_session_id = getattr(agent, "_agenticdome_session_id", None)
        if existing_firewall is not None and (
            existing_firewall is not self or existing_session_id != session_id
        ):
            raise ValueError(
                "This smolagents instance is already attached to a different AgenticDome firewall or session. "
                "Create a fresh agent instance for strict session isolation."
            )
        tools = getattr(agent, "tools", None)
        if isinstance(tools, dict):
            for name, native_tool in list(tools.items()):
                if name == "final_answer" or isinstance(native_tool, SecureSmolTool):
                    continue
                tools[name] = self.wrap_tool(native_tool, session_id=session_id, agent_id=effective_agent_id)

        executor = getattr(agent, "python_executor", None)
        if executor is not None and not getattr(executor, "_agenticdome_wrapped", False):
            agent.python_executor = SecurePythonExecutor(
                executor, self, session_id=session_id, agent_id=effective_agent_id
            )

        managed = getattr(agent, "managed_agents", None)
        if isinstance(managed, dict):
            for name, child in list(managed.items()):
                if getattr(child, "_agenticdome_wrapped", False):
                    continue
                self.attach_firewall(child, session_id=session_id, agent_id=name, include_step_callback=include_step_callback)
                managed[name] = SecureManagedAgent(
                    child,
                    self,
                    session_id=session_id,
                    manager_agent_id=effective_agent_id,
                )

        if include_step_callback and not getattr(agent, "_agenticdome_step_callback", False):
            registry = getattr(agent, "step_callbacks", None)
            if registry is not None and hasattr(registry, "register"):
                try:
                    from smolagents import ActionStep

                    registry.register(
                        ActionStep,
                        self.create_step_callback(session_id=session_id, agent_id=effective_agent_id),
                    )
                    agent._agenticdome_step_callback = True
                except (ImportError, AttributeError):
                    pass
        agent._agenticdome_firewall = self
        agent._agenticdome_session_id = session_id
        return agent

    attach = attach_firewall

    def run_agent_securely(
        self,
        agent: Any,
        task: str,
        *,
        session_id: str,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        **run_kwargs: Any,
    ) -> Any:
        effective_agent_id = agent_id or getattr(agent, "name", None) or self.config.agent_id
        if run_kwargs.get("stream"):
            raise ValueError("Use run_agent_stream_securely() for smolagents streaming runs.")
        self.screen_input(
            session_id=session_id,
            agent_id=effective_agent_id,
            text=task,
            policy_context=policy_context,
        )
        self.attach_firewall(agent, session_id=session_id, agent_id=effective_agent_id)
        result = agent.run(task, **run_kwargs)
        raw = getattr(result, "output", result)
        reviewed = self.review_value(
            raw,
            session_id=session_id,
            agent_id=effective_agent_id,
            policy_context={**(policy_context or {}), "request_purpose": "smolagents_final_output"},
        )
        if hasattr(result, "output"):
            try:
                result.output = reviewed
                return result
            except Exception:
                pass
        return reviewed

    def run_agent_stream_securely(
        self,
        agent: Any,
        task: str,
        *,
        session_id: str,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        **run_kwargs: Any,
    ) -> Any:
        """Yield only DLP-reviewed smolagents stream events."""
        effective_agent_id = agent_id or getattr(agent, "name", None) or self.config.agent_id
        self.screen_input(session_id=session_id, agent_id=effective_agent_id, text=task, policy_context=policy_context)
        self.attach_firewall(agent, session_id=session_id, agent_id=effective_agent_id)
        stream = agent.run(task, stream=True, **run_kwargs)
        for event in stream:
            for attribute in ("output", "observations", "action_output", "content"):
                value = getattr(event, attribute, None)
                if value is None:
                    continue
                try:
                    setattr(
                        event,
                        attribute,
                        self.review_value(
                            value,
                            session_id=session_id,
                            agent_id=effective_agent_id,
                            policy_context={"request_purpose": "smolagents_stream_output"},
                        ),
                    )
                except Exception:
                    pass
            yield event


def attach_firewall(agent: Any, *, firewall: Optional[AgenticDomeSmolagentsFirewall] = None, **kwargs: Any) -> Any:
    return (firewall or AgenticDomeSmolagentsFirewall()).attach_firewall(agent, **kwargs)


__all__ = [
    "FirewallConfig",
    "load_config",
    "SmolagentsFirewallError",
    "SmolagentsFirewallDenied",
    "SmolagentsFirewallConfigurationError",
    "ToolBlocked",
    "FirewallMisconfigured",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "SecureSmolTool",
    "SecurePythonExecutor",
    "SecureManagedAgent",
    "AgenticDomeSmolagentsFirewall",
    "attach_firewall",
]
