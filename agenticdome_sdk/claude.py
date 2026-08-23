from __future__ import annotations

import copy
import os
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

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


logger = logging.getLogger("agenticdome.claude")


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
    platform: str = "claude_agent_sdk"
    agent_id: str = "claude_agent"
    default_tool_platform: str = "claude_agent_sdk"
    redis_key_prefix: str = "AgenticDome:claude:handoff"


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY"),
        tenant_id=_env("AGENTICDOME_TENANT_ID"),
        platform=_env("AGENTICDOME_PLATFORM", "claude_agent_sdk"),
        agent_id=_env("AGENTICDOME_CLAUDE_AGENT_ID", "claude_agent"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "claude_agent_sdk"),
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
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:claude:handoff"),
        token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET"),
        max_input_chars=_env_int("AGENTICDOME_CLAUDE_MAX_INPUT_CHARS", 50_000),
        max_output_chars=_env_int("AGENTICDOME_CLAUDE_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_CLAUDE_MAX_TOOL_ARG_CHARS", 20_000),
        streaming_buffer_chars=_env_int("AGENTICDOME_CLAUDE_STREAMING_BUFFER_CHARS", 4_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_CLAUDE_RATE_LIMIT_PER_MINUTE", 0),
        retry_attempts=_env_int("AGENTICDOME_CLAUDE_RETRY_ATTEMPTS", 2),
        retry_backoff_s=_env_float("AGENTICDOME_CLAUDE_RETRY_BACKOFF_S", 0.25),
        circuit_breaker_failures=_env_int("AGENTICDOME_CLAUDE_CIRCUIT_BREAKER_FAILURES", 5),
        circuit_breaker_reset_s=_env_int("AGENTICDOME_CLAUDE_CIRCUIT_BREAKER_RESET_S", 60),
        audit_logging=_env_bool("AGENTICDOME_CLAUDE_AUDIT_LOGGING", True),
        otel_enabled=_env_bool("AGENTICDOME_CLAUDE_OTEL_ENABLED", True),
        emergency_block_tools=_env("AGENTICDOME_CLAUDE_EMERGENCY_BLOCK_TOOLS"),
        emergency_block_agents=_env("AGENTICDOME_CLAUDE_EMERGENCY_BLOCK_AGENTS"),
        strict_delegated_execution=_env_bool("AGENTICDOME_CLAUDE_STRICT_DELEGATED_EXECUTION", True),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "medium"),
    )


class ClaudeFirewallError(RuntimeError):
    """Base error for the Claude Agent SDK adapter."""


class ClaudeFirewallDenied(ClaudeFirewallError):
    """Raised when AgenticDome denies a Claude SDK boundary."""


class ClaudeFirewallConfigurationError(ClaudeFirewallError):
    """Raised when AgenticDome credentials or runtime context are missing."""


ToolBlocked = ClaudeFirewallDenied
FirewallMisconfigured = ClaudeFirewallConfigurationError


class AgenticDomeClaudeFirewall(FrameworkFirewallBase):
    """Native hooks and run wrappers for Anthropic's Claude Agent SDK."""

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
            denied_error=ClaudeFirewallDenied,
            configuration_error=ClaudeFirewallConfigurationError,
            label="Claude Agent SDK",
            logger=logger,
        )

    authorize_direct_tool_call = FrameworkFirewallBase.authorize_tool_call

    def _hook_session(self, input_data: Dict[str, Any], configured: Optional[str]) -> str:
        return self.session_id(
            configured or str(input_data.get("session_id") or input_data.get("transcript_path") or "") or None,
            input_data,
        )

    @staticmethod
    def _hook_actor(
        input_data: Dict[str, Any],
        configured_agent_id: str,
        policy_context: Optional[Dict[str, Any]],
    ) -> tuple[str, Dict[str, Any], Optional[str]]:
        """Attribute tool and output events to the SDK subagent that emitted them."""
        sdk_agent_id = str(input_data.get("agent_id") or "").strip()
        sdk_agent_type = str(input_data.get("agent_type") or "").strip()
        active_agent_id = sdk_agent_id or configured_agent_id
        context = dict(policy_context or {})
        if sdk_agent_id:
            context.setdefault("claude_subagent_id", sdk_agent_id)
            context.setdefault("claude_subagent_type", sdk_agent_type or "unknown")
            context.setdefault("delegation_chain", [configured_agent_id, sdk_agent_id])
        source_agent_id = configured_agent_id if sdk_agent_id and sdk_agent_id != configured_agent_id else None
        return active_agent_id, context, source_agent_id

    def create_hooks(
        self,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, List[Callable[..., Any]]]:
        """Return raw Claude hook callbacks; use ``create_hook_matchers`` for options."""
        effective_agent_id = agent_id or self.config.agent_id

        async def user_prompt_submit(input_data: Dict[str, Any], tool_use_id: Optional[str], context: Dict[str, Any]) -> Dict[str, Any]:
            del tool_use_id, context
            try:
                await self.ascreen_input(
                    session_id=self._hook_session(input_data, session_id),
                    agent_id=effective_agent_id,
                    text=str(input_data.get("prompt") or ""),
                    policy_context=policy_context,
                )
                return {}
            except ClaudeFirewallDenied as exc:
                return {"decision": "block", "reason": str(exc), "systemMessage": "AgenticDome blocked this prompt."}

        async def pre_tool_use(input_data: Dict[str, Any], tool_use_id: Optional[str], context: Dict[str, Any]) -> Dict[str, Any]:
            del tool_use_id, context
            tool_name = str(input_data.get("tool_name") or "unknown_tool")
            tool_input = self.normalize_args(input_data.get("tool_input"))
            active_agent_id, active_policy_context, source_agent_id = self._hook_actor(
                input_data, effective_agent_id, policy_context
            )
            try:
                decision = await self.aauthorize_tool_call(
                    session_id=self._hook_session(input_data, session_id),
                    agent_id=active_agent_id,
                    tool_name=tool_name,
                    tool_args=tool_input,
                    text=f"[Claude Agent SDK] {active_agent_id} calls {tool_name}",
                    policy_context=active_policy_context,
                    source_agent_id=source_agent_id,
                )
                clean = self.sanitized_args(decision, tool_input)
                output: Dict[str, Any] = {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "permissionDecisionReason": "Allowed by AgenticDome",
                    }
                }
                if clean != tool_input:
                    output["hookSpecificOutput"]["updatedInput"] = clean
                return output
            except ClaudeFirewallDenied as exc:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": str(exc),
                    }
                }

        async def post_tool_use(input_data: Dict[str, Any], tool_use_id: Optional[str], context: Dict[str, Any]) -> Dict[str, Any]:
            del tool_use_id, context
            sid = self._hook_session(input_data, session_id)
            active_agent_id, active_policy_context, _ = self._hook_actor(
                input_data, effective_agent_id, policy_context
            )
            raw = input_data.get("tool_response")
            reviewed = await self.areview_value(
                raw,
                session_id=sid,
                agent_id=active_agent_id,
                policy_context={**active_policy_context, "tool_name": input_data.get("tool_name")},
            )
            if reviewed == raw:
                return {}
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": reviewed,
                    "additionalContext": "AgenticDome reviewed the tool output.",
                }
            }

        return {
            "UserPromptSubmit": [user_prompt_submit],
            "PreToolUse": [pre_tool_use],
            "PostToolUse": [post_tool_use],
        }

    def create_hook_matchers(self, **kwargs: Any) -> Dict[str, List[Any]]:
        try:
            from claude_agent_sdk import HookMatcher
        except ImportError as exc:
            raise ImportError(
                "Claude Agent SDK integration requires: pip install 'agenticdome-python-sdk[claude]'"
            ) from exc
        raw = self.create_hooks(**kwargs)
        result: Dict[str, List[Any]] = {}
        session_key = str(kwargs.get("session_id") or "")
        agent_key = str(kwargs.get("agent_id") or self.config.agent_id)
        for event, callbacks in raw.items():
            matcher = HookMatcher(matcher=None, hooks=callbacks)
            matcher._agenticdome_hook_key = (id(self), event, session_key, agent_key)
            result[event] = [matcher]
        return result

    def install_on_options(self, options: Any, **kwargs: Any) -> Any:
        """Merge AgenticDome hooks into a ``ClaudeAgentOptions`` instance."""
        hooks = dict(getattr(options, "hooks", None) or {})
        for event, matchers in self.create_hook_matchers(**kwargs).items():
            installed = hooks.setdefault(event, [])
            existing_keys = {getattr(item, "_agenticdome_hook_key", None) for item in installed}
            installed.extend(
                matcher
                for matcher in matchers
                if getattr(matcher, "_agenticdome_hook_key", None) not in existing_keys
            )
        options.hooks = hooks
        return options

    attach = install_on_options

    async def _sanitize_message(self, message: Any, *, session_id: str, agent_id: str, policy_context: Optional[Dict[str, Any]]) -> Any:
        try:
            secured = copy.copy(message)
        except Exception:
            secured = message
        content = getattr(secured, "content", None)
        if isinstance(content, list):
            copied = list(content)
            for index, block in enumerate(copied):
                text = getattr(block, "text", None)
                if not isinstance(text, str):
                    continue
                reviewed = await self.asanitize_output(
                    session_id=session_id, agent_id=agent_id, text=text, policy_context=policy_context
                )
                try:
                    new_block = copy.copy(block)
                    setattr(new_block, "text", reviewed)
                    copied[index] = new_block
                except Exception:
                    setattr(block, "text", reviewed)
            try:
                secured.content = copied
            except Exception:
                pass
        result = getattr(secured, "result", None)
        if isinstance(result, str):
            reviewed = await self.asanitize_output(
                session_id=session_id, agent_id=agent_id, text=result, policy_context=policy_context
            )
            try:
                secured.result = reviewed
            except Exception:
                pass
        return secured

    async def secure_query(
        self,
        prompt: str,
        *,
        session_id: str,
        agent_id: Optional[str] = None,
        options: Any = None,
        query_fn: Optional[Callable[..., Any]] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[Any]:
        """Guard the one-shot ``query()`` async message pipeline."""
        effective_agent_id = agent_id or self.config.agent_id
        await self.ascreen_input(
            session_id=session_id, agent_id=effective_agent_id, text=prompt, policy_context=policy_context
        )
        if query_fn is None:
            try:
                from claude_agent_sdk import ClaudeAgentOptions, query as query_fn
            except ImportError as exc:
                raise ImportError(
                    "Claude Agent SDK integration requires: pip install 'agenticdome-python-sdk[claude]'"
                ) from exc
            if options is None:
                options = ClaudeAgentOptions()
        if options is not None:
            self.install_on_options(
                options,
                session_id=session_id,
                agent_id=effective_agent_id,
                policy_context=policy_context,
            )
        kwargs: Dict[str, Any] = {"prompt": prompt}
        if options is not None:
            kwargs["options"] = options
        stream = query_fn(**kwargs)
        if hasattr(stream, "__await__"):
            stream = await stream
        async for message in stream:
            yield await self._sanitize_message(
                message, session_id=session_id, agent_id=effective_agent_id, policy_context=policy_context
            )

    async def run_client_securely(
        self,
        client: Any,
        prompt: str,
        *,
        session_id: str,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[Any]:
        """Guard a connected ``ClaudeSDKClient`` query/receive cycle."""
        effective_agent_id = agent_id or self.config.agent_id
        await self.ascreen_input(
            session_id=session_id, agent_id=effective_agent_id, text=prompt, policy_context=policy_context
        )
        await client.query(prompt)
        async for message in client.receive_response():
            yield await self._sanitize_message(
                message, session_id=session_id, agent_id=effective_agent_id, policy_context=policy_context
            )

    def secure_sdk_tool(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        *,
        session_id: str,
        agent_id: Optional[str] = None,
        tool_platform: Optional[str] = None,
    ) -> Callable[[Callable[..., Any]], Any]:
        """Compose AgenticDome enforcement with Claude's native ``@tool`` decorator."""
        try:
            from claude_agent_sdk import tool
        except ImportError as exc:
            raise ImportError(
                "Claude Agent SDK integration requires: pip install 'agenticdome-python-sdk[claude]'"
            ) from exc

        def decorator(fn: Callable[..., Any]) -> Any:
            secured = self.wrap_tool_handler(
                tool_name=name,
                handler=fn,
                session_id=session_id,
                agent_id=agent_id,
                tool_platform=tool_platform,
            )
            return tool(name, description, input_schema)(secured)

        return decorator


__all__ = [
    "FirewallConfig",
    "load_config",
    "ClaudeFirewallError",
    "ClaudeFirewallDenied",
    "ClaudeFirewallConfigurationError",
    "ToolBlocked",
    "FirewallMisconfigured",
    "DecisionTokenRecord",
    "DecisionTokenStore",
    "InMemoryDecisionTokenStore",
    "RedisDecisionTokenStore",
    "AgenticDomeClaudeFirewall",
]
