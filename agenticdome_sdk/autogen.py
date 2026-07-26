from __future__ import annotations

import copy
import hashlib
import inspect
import json
import logging
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from types import MethodType
from typing import Any, AsyncIterator, Callable, Deque, Dict, Iterable, List, Optional

from ._framework_firewall import DecisionTokenStore, FrameworkFirewallBase, FrameworkFirewallConfig
from .client import AgentGuardClient


logger = logging.getLogger("agenticdome.autogen")


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
    platform: str = "autogen"
    agent_id: str = "autogen_agent"
    default_tool_platform: str = "autogen"
    redis_key_prefix: str = "AgenticDome:autogen:handoff"
    conversation_window_messages: int = 12
    max_tool_calls_per_window: int = 8
    freeze_on_policy_block: bool = True
    revoke_agent_on_freeze: bool = True


def load_config() -> FirewallConfig:
    return FirewallConfig(
        api_base=_env("AGENTICDOME_API_BASE").rstrip("/"),
        api_key=_env("AGENTICDOME_API_KEY"),
        tenant_id=_env("AGENTICDOME_TENANT_ID"),
        platform=_env("AGENTICDOME_PLATFORM", "autogen"),
        agent_id=_env("AGENTICDOME_AUTOGEN_AGENT_ID", "autogen_agent"),
        default_tool_platform=_env("AGENTICDOME_DEFAULT_TOOL_PLATFORM", "autogen"),
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
        redis_key_prefix=_env("AGENTICDOME_REDIS_KEY_PREFIX", "AgenticDome:autogen:handoff"),
        token_hmac_secret=_env("AGENTICDOME_TOKEN_HMAC_SECRET"),
        max_input_chars=_env_int("AGENTICDOME_AUTOGEN_MAX_INPUT_CHARS", 50_000),
        max_output_chars=_env_int("AGENTICDOME_AUTOGEN_MAX_OUTPUT_CHARS", 100_000),
        max_tool_arg_chars=_env_int("AGENTICDOME_AUTOGEN_MAX_TOOL_ARG_CHARS", 20_000),
        streaming_buffer_chars=_env_int("AGENTICDOME_AUTOGEN_STREAMING_BUFFER_CHARS", 4_000),
        rate_limit_per_minute=_env_int("AGENTICDOME_AUTOGEN_RATE_LIMIT_PER_MINUTE", 0),
        retry_attempts=_env_int("AGENTICDOME_AUTOGEN_RETRY_ATTEMPTS", 2),
        retry_backoff_s=_env_float("AGENTICDOME_AUTOGEN_RETRY_BACKOFF_S", 0.25),
        circuit_breaker_failures=_env_int("AGENTICDOME_AUTOGEN_CIRCUIT_BREAKER_FAILURES", 5),
        circuit_breaker_reset_s=_env_int("AGENTICDOME_AUTOGEN_CIRCUIT_BREAKER_RESET_S", 60),
        audit_logging=_env_bool("AGENTICDOME_AUTOGEN_AUDIT_LOGGING", True),
        otel_enabled=_env_bool("AGENTICDOME_AUTOGEN_OTEL_ENABLED", True),
        emergency_block_tools=_env("AGENTICDOME_AUTOGEN_EMERGENCY_BLOCK_TOOLS"),
        emergency_block_agents=_env("AGENTICDOME_AUTOGEN_EMERGENCY_BLOCK_AGENTS"),
        strict_delegated_execution=_env_bool("AGENTICDOME_AUTOGEN_STRICT_DELEGATED_EXECUTION", True),
        scan_code_expressions=_env_bool("AGENTICDOME_AUTOGEN_SCAN_CODE", True),
        report_incidents=_env_bool("AGENTICDOME_REPORT_INCIDENTS", True),
        blocked_incident_severity=_env("AGENTICDOME_BLOCKED_INCIDENT_SEVERITY", "high"),
        conversation_window_messages=_env_int("AGENTICDOME_AUTOGEN_CONVERSATION_WINDOW", 12),
        max_tool_calls_per_window=_env_int("AGENTICDOME_AUTOGEN_MAX_TOOL_CALLS_PER_WINDOW", 8),
        freeze_on_policy_block=_env_bool("AGENTICDOME_AUTOGEN_FREEZE_ON_BLOCK", True),
        revoke_agent_on_freeze=_env_bool("AGENTICDOME_AUTOGEN_REVOKE_ON_FREEZE", True),
    )


class AutoGenFirewallError(RuntimeError):
    """Base error for the Microsoft AutoGen adapter."""


class AutoGenFirewallDenied(AutoGenFirewallError):
    """Raised when an AutoGen message, tool, handoff, or team run is denied."""


class AutoGenFirewallConfigurationError(AutoGenFirewallError):
    """Raised when AgenticDome runtime configuration is incomplete."""


ToolBlocked = AutoGenFirewallDenied
FirewallMisconfigured = AutoGenFirewallConfigurationError


def _agent_name(value: Any, fallback: str) -> str:
    if value is None:
        return fallback
    for key in ("name", "id", "agent_id", "type"):
        candidate = value.get(key) if isinstance(value, dict) else getattr(value, key, None)
        if candidate:
            return str(candidate)
    return fallback


def _content(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("content", "text", "message", "task", "arguments"):
            if key in value and value[key] is not None:
                return _content(value[key])
        return json.dumps(value, sort_keys=True, default=str)
    if isinstance(value, (list, tuple)):
        return "\n".join(filter(None, (_content(item) for item in value)))
    for key in ("content", "text", "message", "task", "arguments"):
        candidate = getattr(value, key, None)
        if candidate is not None:
            return _content(candidate)
    return str(value)


def _replace_content(value: Any, content: str) -> Any:
    if isinstance(value, str):
        return content
    if isinstance(value, dict):
        updated = dict(value)
        key = next((item for item in ("content", "text", "message", "task") if item in updated), "content")
        updated[key] = content
        return updated
    model_copy = getattr(value, "model_copy", None)
    if callable(model_copy) and hasattr(value, "content"):
        try:
            return model_copy(update={"content": content})
        except Exception:
            pass
    if hasattr(value, "content"):
        try:
            updated = copy.copy(value)
            setattr(updated, "content", content)
            return updated
        except Exception:
            pass
    return value


class SecureAutoGenTeam:
    """Dependency-light proxy for current AutoGen AgentChat Team.run/run_stream."""

    def __init__(
        self,
        team: Any,
        firewall: "AgenticDomeAutoGenFirewall",
        *,
        session_id: str,
        agent_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._team = team
        self._firewall = firewall
        self._session_id = session_id
        self._agent_id = agent_id
        self._policy_context = dict(policy_context or {})

    def __getattr__(self, name: str) -> Any:
        return getattr(self._team, name)

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        task = kwargs.get("task", args[0] if args else None)
        if task is not None:
            secured = await self._firewall.ainspect_message(
                task,
                session_id=self._session_id,
                sender_agent_id="user",
                recipient_agent_id=self._agent_id,
                direction="team_input",
                policy_context=self._policy_context,
            )
            if "task" in kwargs:
                kwargs["task"] = secured
            elif args:
                args = (secured, *args[1:])
        result = await self._team.run(*args, **kwargs)
        return await self._firewall.areview_team_result(
            result,
            session_id=self._session_id,
            agent_id=self._agent_id,
            policy_context=self._policy_context,
        )

    async def run_stream(self, *args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        task = kwargs.get("task", args[0] if args else None)
        if task is not None:
            secured = await self._firewall.ainspect_message(
                task,
                session_id=self._session_id,
                sender_agent_id="user",
                recipient_agent_id=self._agent_id,
                direction="team_input",
                policy_context=self._policy_context,
            )
            if "task" in kwargs:
                kwargs["task"] = secured
            elif args:
                args = (secured, *args[1:])
        async for event in self._team.run_stream(*args, **kwargs):
            yield await self._firewall.ainspect_message(
                event,
                session_id=self._session_id,
                sender_agent_id=_agent_name(event, self._agent_id),
                recipient_agent_id="team_output",
                direction="team_stream",
                policy_context=self._policy_context,
                sanitize=True,
            )


class AgenticDomeAutoGenFirewall(FrameworkFirewallBase):
    """Native policy boundaries for AutoGen AgentChat/Core and legacy ConversableAgent."""

    def __init__(
        self,
        config: Optional[FirewallConfig] = None,
        *,
        client: Optional[AgentGuardClient] = None,
        token_store: Optional[DecisionTokenStore] = None,
    ) -> None:
        resolved = config or load_config()
        super().__init__(
            resolved,
            client=client,
            token_store=token_store,
            denied_error=AutoGenFirewallDenied,
            configuration_error=AutoGenFirewallConfigurationError,
            label="Microsoft AutoGen",
            logger=logger,
        )
        self.config: FirewallConfig = resolved
        self._conversation_lock = Lock()
        self._conversation_windows: Dict[str, Deque[Dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=max(1, self.config.conversation_window_messages))
        )
        self._frozen_sessions: Dict[str, str] = {}

    authorize_direct_tool_call = FrameworkFirewallBase.authorize_tool_call

    def is_session_frozen(self, session_id: str) -> bool:
        with self._conversation_lock:
            return session_id in self._frozen_sessions

    def frozen_reason(self, session_id: str) -> Optional[str]:
        with self._conversation_lock:
            return self._frozen_sessions.get(session_id)

    def unfreeze_session(self, session_id: str) -> None:
        with self._conversation_lock:
            self._frozen_sessions.pop(session_id, None)
            self._conversation_windows.pop(session_id, None)

    def freeze_session(self, session_id: str, *, agent_id: str, reason: str) -> None:
        with self._conversation_lock:
            self._frozen_sessions[session_id] = reason
        self._audit("conversation_frozen", session_id=session_id, agent_id=agent_id, reason=reason)
        if self.config.report_incidents and hasattr(self.client, "report_incident"):
            try:
                self._client_call_sync(
                    self.client.report_incident,
                    agent_id=agent_id,
                    incident_type="autogen_conversation_policy_block",
                    severity=self.config.blocked_incident_severity,
                    details=reason,
                    platform=self.config.platform,
                )
            except Exception as exc:
                logger.warning("AutoGen incident reporting failed after enforcement: %s", exc)
        if self.config.revoke_agent_on_freeze and hasattr(self.client, "revoke_decision_token"):
            try:
                self._client_call_sync(
                    self.client.revoke_decision_token,
                    agent_id=agent_id,
                    reason=f"AutoGen session {session_id} frozen: {reason}",
                )
            except Exception as exc:
                logger.warning("AutoGen revocation-epoch advance failed after enforcement: %s", exc)

    @staticmethod
    def _is_tool_event(message: Any) -> bool:
        name = type(message).__name__.lower()
        if any(marker in name for marker in ("functioncall", "toolcall", "codeexecution")):
            return True
        if isinstance(message, dict):
            return bool(message.get("tool_name") or message.get("function_call") or message.get("tool_calls"))
        return bool(getattr(message, "name", None) and getattr(message, "arguments", None) is not None)

    def _record_event(
        self,
        *,
        session_id: str,
        sender_agent_id: str,
        recipient_agent_id: str,
        direction: str,
        text: str,
        tool_event: bool,
    ) -> Dict[str, Any]:
        event = {
            "sender": sender_agent_id,
            "recipient": recipient_agent_id,
            "direction": direction,
            "text": text,
            "tool_event": tool_event,
        }
        with self._conversation_lock:
            window = self._conversation_windows[session_id]
            window.append(event)
            snapshot = list(window)
        tool_calls = sum(1 for item in snapshot if item["tool_event"])
        digest = hashlib.sha256(
            json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        return {
            "family": 2,
            "family_name": "multi_agent_behavioral_trust",
            "conversation_window_size": len(snapshot),
            "conversation_window_limit": max(1, self.config.conversation_window_messages),
            "tool_calls_in_window": tool_calls,
            "tool_call_limit": max(0, self.config.max_tool_calls_per_window),
            "conversation_digest": digest,
            "conversation_participants": sorted(
                {item["sender"] for item in snapshot} | {item["recipient"] for item in snapshot}
            ),
        }

    def inspect_message(
        self,
        message: Any,
        *,
        session_id: str,
        sender_agent_id: str,
        recipient_agent_id: str,
        direction: str,
        policy_context: Optional[Dict[str, Any]] = None,
        sanitize: bool = True,
    ) -> Any:
        if self.is_session_frozen(session_id):
            raise AutoGenFirewallDenied(
                f"AgenticDome froze AutoGen session {session_id}: {self.frozen_reason(session_id)}"
            )
        text = _content(message)
        metrics = self._record_event(
            session_id=session_id,
            sender_agent_id=sender_agent_id,
            recipient_agent_id=recipient_agent_id,
            direction=direction,
            text=text,
            tool_event=self._is_tool_event(message),
        )
        context = {
            **dict(policy_context or {}),
            **metrics,
            "source_agent_id": sender_agent_id,
            "target_agent_id": recipient_agent_id,
            "conversation_direction": direction,
            "semantic_deviation_evaluation": "server_side",
        }
        if metrics["tool_call_limit"] and metrics["tool_calls_in_window"] > metrics["tool_call_limit"]:
            reason = "AutoGen tool-call frequency exceeded the certified rolling-window limit."
            self.freeze_session(session_id, agent_id=sender_agent_id, reason=reason)
            raise AutoGenFirewallDenied(reason)
        try:
            self.screen_input(
                session_id=session_id,
                agent_id=recipient_agent_id,
                text=text,
                policy_context=context,
            )
            if not sanitize or text == "":
                return message
            reviewed = self.sanitize_output(
                session_id=session_id,
                agent_id=sender_agent_id,
                text=text,
                policy_context=context,
            )
            return _replace_content(message, reviewed)
        except AutoGenFirewallDenied as exc:
            if self.config.freeze_on_policy_block:
                self.freeze_session(session_id, agent_id=sender_agent_id, reason=str(exc))
            raise

    async def ainspect_message(self, message: Any, **kwargs: Any) -> Any:
        # AgentGuardClient is intentionally synchronous. Keeping one enforcement
        # path here avoids ordering races between consecutive AutoGen team events.
        return self.inspect_message(message, **kwargs)

    def wrap_team(
        self,
        team: Any,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> SecureAutoGenTeam:
        sid = self.session_id(session_id, team)
        aid = agent_id or _agent_name(team, self.config.agent_id)
        return SecureAutoGenTeam(team, self, session_id=sid, agent_id=aid, policy_context=policy_context)

    async def areview_team_result(
        self,
        result: Any,
        *,
        session_id: str,
        agent_id: str,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        messages = getattr(result, "messages", None)
        if not isinstance(messages, list):
            return await self.ainspect_message(
                result,
                session_id=session_id,
                sender_agent_id=agent_id,
                recipient_agent_id="application",
                direction="team_output",
                policy_context=policy_context,
                sanitize=True,
            )
        secured = []
        for message in messages:
            secured.append(
                await self.ainspect_message(
                    message,
                    session_id=session_id,
                    sender_agent_id=_agent_name(message, agent_id),
                    recipient_agent_id="application",
                    direction="team_output",
                    policy_context=policy_context,
                    sanitize=True,
                )
            )
        try:
            updated = copy.copy(result)
            updated.messages = secured
            return updated
        except Exception:
            return result

    def _attach_method(
        self,
        agent: Any,
        method_name: str,
        *,
        session_id: str,
        agent_id: str,
        direction: str,
        policy_context: Optional[Dict[str, Any]],
    ) -> bool:
        original = getattr(agent, method_name, None)
        if not callable(original):
            return False
        marker = f"_agenticdome_original_{method_name}"
        if hasattr(agent, marker):
            return False
        setattr(agent, marker, original)
        is_async = inspect.iscoroutinefunction(original)

        async def async_wrapper(_agent: Any, message: Any, *args: Any, **kwargs: Any) -> Any:
            peer = args[0] if args else kwargs.get("recipient") or kwargs.get("sender")
            peer_id = _agent_name(peer, "autogen_peer")
            sender, recipient = (agent_id, peer_id) if direction == "send" else (peer_id, agent_id)
            secured = await self.ainspect_message(
                message,
                session_id=session_id,
                sender_agent_id=sender,
                recipient_agent_id=recipient,
                direction=f"legacy_{direction}",
                policy_context=policy_context,
                sanitize=True,
            )
            return await original(secured, *args, **kwargs)

        def sync_wrapper(_agent: Any, message: Any, *args: Any, **kwargs: Any) -> Any:
            peer = args[0] if args else kwargs.get("recipient") or kwargs.get("sender")
            peer_id = _agent_name(peer, "autogen_peer")
            sender, recipient = (agent_id, peer_id) if direction == "send" else (peer_id, agent_id)
            secured = self.inspect_message(
                message,
                session_id=session_id,
                sender_agent_id=sender,
                recipient_agent_id=recipient,
                direction=f"legacy_{direction}",
                policy_context=policy_context,
                sanitize=True,
            )
            return original(secured, *args, **kwargs)

        setattr(agent, method_name, MethodType(async_wrapper if is_async else sync_wrapper, agent))
        return True

    def attach_conversable_agent(
        self,
        agent: Any,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Attach to legacy AutoGen 0.2 ConversableAgent send/receive lifecycles."""
        sid = self.session_id(session_id, agent)
        aid = agent_id or _agent_name(agent, self.config.agent_id)
        for name, direction in (("send", "send"), ("receive", "receive"), ("a_send", "send"), ("a_receive", "receive")):
            self._attach_method(
                agent,
                name,
                session_id=sid,
                agent_id=aid,
                direction=direction,
                policy_context=policy_context,
            )
        return agent

    def attach_agentchat_agent(
        self,
        agent: Any,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Attach to current AutoGen BaseChatAgent.on_messages/on_messages_stream."""
        sid = self.session_id(session_id, agent)
        aid = agent_id or _agent_name(agent, self.config.agent_id)
        original = getattr(agent, "on_messages", None)
        if callable(original) and not hasattr(agent, "_agenticdome_original_on_messages"):
            setattr(agent, "_agenticdome_original_on_messages", original)

            async def on_messages(_agent: Any, messages: Iterable[Any], *args: Any, **kwargs: Any) -> Any:
                secured = []
                for message in messages:
                    secured.append(
                        await self.ainspect_message(
                            message,
                            session_id=sid,
                            sender_agent_id=_agent_name(message, "autogen_peer"),
                            recipient_agent_id=aid,
                            direction="agentchat_receive",
                            policy_context=policy_context,
                            sanitize=True,
                        )
                    )
                response = await original(secured, *args, **kwargs)
                chat_message = getattr(response, "chat_message", None)
                if chat_message is not None:
                    reviewed = await self.ainspect_message(
                        chat_message,
                        session_id=sid,
                        sender_agent_id=aid,
                        recipient_agent_id="autogen_team",
                        direction="agentchat_send",
                        policy_context=policy_context,
                        sanitize=True,
                    )
                    try:
                        updated = copy.copy(response)
                        updated.chat_message = reviewed
                        return updated
                    except Exception:
                        pass
                return response

            setattr(agent, "on_messages", MethodType(on_messages, agent))
        return agent

    def create_intervention_handler(
        self,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Create an AutoGen Core intervention handler for messages and FunctionCall tools."""
        try:
            from autogen_core import DefaultInterventionHandler, DropMessage, FunctionCall
        except ImportError as exc:
            raise ImportError(
                "AutoGen integration requires Python 3.10+ and: pip install 'agenticdome-python-sdk[autogen]'"
            ) from exc

        firewall = self
        sid = self.session_id(session_id)
        aid = agent_id or self.config.agent_id

        class AgenticDomeInterventionHandler(DefaultInterventionHandler):
            async def on_send(self, message: Any, *, message_context: Any, recipient: Any) -> Any:
                sender = _agent_name(getattr(message_context, "sender", None), aid)
                recipient_id = _agent_name(recipient, "autogen_recipient")
                try:
                    if isinstance(message, FunctionCall):
                        args = firewall.normalize_args(getattr(message, "arguments", {}))
                        # Keep Core message ordering deterministic. The SDK client is
                        # synchronous, and dispatching this boundary to the loop's
                        # default executor can outlive short-lived AutoGen runtimes.
                        decision = firewall.authorize_tool_call(
                            session_id=sid,
                            agent_id=sender,
                            source_agent_id=sender,
                            tool_name=str(getattr(message, "name", "autogen.tool")),
                            tool_args=args,
                            tool_platform="autogen_core",
                            text=f"[Microsoft AutoGen] {sender} requests a tool execution",
                            policy_context={**dict(policy_context or {}), "recipient_agent_id": recipient_id},
                        )
                        clean = firewall.sanitized_args(decision, args)
                        if clean != args:
                            try:
                                return message.model_copy(update={"arguments": json.dumps(clean)})
                            except Exception:
                                pass
                    return await firewall.ainspect_message(
                        message,
                        session_id=sid,
                        sender_agent_id=sender,
                        recipient_agent_id=recipient_id,
                        direction="core_send",
                        policy_context=policy_context,
                        sanitize=True,
                    )
                except AutoGenFirewallDenied:
                    return DropMessage

        return AgenticDomeInterventionHandler()

    def create_termination_condition(
        self,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        policy_context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Create a composable AgentChat termination condition that freezes on policy denial."""
        try:
            from autogen_agentchat.base import TerminationCondition
            from autogen_agentchat.messages import StopMessage
        except ImportError as exc:
            raise ImportError(
                "AutoGen integration requires Python 3.10+ and: pip install 'agenticdome-python-sdk[autogen]'"
            ) from exc

        firewall = self
        sid = self.session_id(session_id)
        aid = agent_id or self.config.agent_id

        class AgenticDomeTermination(TerminationCondition):
            @property
            def terminated(self) -> bool:
                return firewall.is_session_frozen(sid)

            async def __call__(self, messages: Iterable[Any]) -> Optional[Any]:
                try:
                    for message in messages:
                        await firewall.ainspect_message(
                            message,
                            session_id=sid,
                            sender_agent_id=_agent_name(message, aid),
                            recipient_agent_id="autogen_team",
                            direction="termination_check",
                            policy_context=policy_context,
                            sanitize=False,
                        )
                except AutoGenFirewallDenied as exc:
                    return StopMessage(content=str(exc), source="AgenticDome")
                return None

            async def reset(self) -> None:
                firewall.unfreeze_session(sid)

        return AgenticDomeTermination()


__all__ = [
    "AgenticDomeAutoGenFirewall",
    "AutoGenFirewallConfigurationError",
    "AutoGenFirewallDenied",
    "AutoGenFirewallError",
    "FirewallConfig",
    "SecureAutoGenTeam",
    "load_config",
]
