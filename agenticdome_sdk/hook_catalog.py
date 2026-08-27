"""Versioned integration-hook contracts shared by the SDK Harness and Copilot.

This module deliberately contains data, not runtime framework imports.  It is
included in the published Python SDK so local onboarding can use the same
certification envelope displayed by the administrative SDK Harness.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


CATALOG_SCHEMA = "agenticdome.hook-catalog.v1"
CATALOG_SNAPSHOT_SCHEMA = "agenticdome.catalog-snapshot.v1"


def _load_catalog_snapshot() -> Dict[str, Any]:
    path = Path(__file__).with_name("catalog_snapshot.json")
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("The installed SDK is missing its canonical hook-catalog snapshot.") from exc
    if not isinstance(snapshot, dict) or snapshot.get("schema") != CATALOG_SNAPSHOT_SCHEMA:
        raise RuntimeError("The installed SDK contains an unsupported hook-catalog snapshot.")
    if snapshot.get("catalog_schema") != CATALOG_SCHEMA:
        raise RuntimeError("The installed SDK hook-catalog snapshot uses the wrong catalog schema.")
    if not isinstance(snapshot.get("published_packages"), dict):
        raise RuntimeError("The installed SDK hook-catalog snapshot has no published package map.")
    return snapshot


_CATALOG_SNAPSHOT = _load_catalog_snapshot()
CATALOG_VERIFIED_AT = str(_CATALOG_SNAPSHOT["verified_at"])


_OPENCLAW_RUNTIME_MIN_VERSION = "2026.7.1-2"
_OPENCLAW_RUNTIME_MAX_VERSION = "2026.7.1-2"
_OPENCLAW_RUNTIME_VERSION = _OPENCLAW_RUNTIME_MAX_VERSION
_OPENCLAW_NODE_RANGE = ">=22.22.3 <23 || >=24.15.0 <25 || >=25.9.0"

PUBLISHED_AGENTICDOME_PACKAGES: Dict[str, Dict[str, str]] = {
    str(package): {str(key): str(value) for key, value in row.items()}
    for package, row in _CATALOG_SNAPSHOT["published_packages"].items()
    if isinstance(row, dict)
}


def _python_contract(
    label: str,
    adapter_module: str,
    adapter_class: str,
    methods: List[str],
    packages: Optional[Dict[str, Dict[str, str]]] = None,
    native_modules: Optional[List[Dict[str, Any]]] = None,
    adapter_attrs: Optional[List[Dict[str, Any]]] = None,
    native_smoke: Optional[Dict[str, str]] = None,
    docs: str = "",
) -> Dict[str, Any]:
    attrs = list(adapter_attrs or [])
    attrs.insert(0, {"module": adapter_module, "attrs": [adapter_class]})
    return {
        "label": label,
        "language": "python",
        "registry": "pypi",
        "agenticdome_package": "agenticdome-python-sdk",
        "packages": packages or {},
        "native_modules": native_modules or [],
        "adapter_module": adapter_module,
        "adapter_class": adapter_class,
        "adapter_attrs": attrs,
        "attachment_methods": methods,
        "native_smoke": native_smoke or {},
        "docs": docs,
        "harness_python": True,
    }


FRAMEWORK_HOOK_CATALOG: Dict[str, Dict[str, Any]] = {
    "crewai": _python_contract(
        "CrewAI",
        "agenticdome_sdk.integrations.crewai",
        "AgenticDomeCrewAIFirewall",
        ["attach", "secure_tool"],
        packages={"crewai": {"min":"1.15.5","max":"1.15.17"}},
        native_modules=[
            {
                "module": "crewai.hooks",
                "attrs": [
                    "register_before_tool_call_hook",
                    "register_after_tool_call_hook",
                    "register_before_llm_call_hook",
                    "register_after_llm_call_hook",
                ],
            }
        ],
        adapter_attrs=[
            {
                "module": "agenticdome_sdk.integrations.crewai",
                "attrs": [
                    "AgenticDomeCrewAIEventListener",
                    "install_crewai_firewall",
                    "secure_tool",
                ],
            }
        ],
        native_smoke={"module": "agenticdome_sdk.integrations.crewai", "call": "install_crewai_firewall"},
        docs="docs/frameworks/crewai.md",
    ),
    "pydanticai": _python_contract(
        "Pydantic AI",
        "agenticdome_sdk.integrations.pydanticai",
        "CyberSecFirewall",
        ["install_native_hooks", "secure_tool"],
        packages={"pydantic-ai": {"min":"2.16.0","max":"2.35.1"}},
        native_modules=[{"module": "pydantic_ai", "attrs": ["Agent", "RunContext"]}],
        adapter_attrs=[
            {
                "module": "agenticdome_sdk.integrations.pydanticai",
                "attrs": ["install_pydanticai_firewall", "secure_tool"],
            }
        ],
        native_smoke={"module": "agenticdome_sdk.integrations.pydanticai", "call": "install_pydanticai_firewall"},
        docs="docs/frameworks/pydanticai.md",
    ),
    "langgraph": _python_contract(
        "LangGraph / LangChain",
        "agenticdome_sdk.integrations.langgraph",
        "AgenticDomeLangGraphFirewall",
        ["input_node", "transition_node", "output_node", "as_langchain_middleware"],
        packages={
            "langgraph": {"min": "1.2.9", "max": "1.2.11"},
            "langchain-core": {"min":"1.5.0","max":"1.6.0"},
        },
        native_modules=[
            {"module": "langgraph.graph", "attrs": ["StateGraph"]},
            {"module": "langchain.agents.middleware", "attrs": ["AgentMiddleware"]},
        ],
        adapter_attrs=[
            {
                "module": "agenticdome_sdk.integrations.langgraph",
                "attrs": ["AgenticDomeLangChainMiddleware", "secure_tool_node"],
            }
        ],
        native_smoke={"module": "agenticdome_sdk.integrations.langgraph", "call": "as_langchain_middleware"},
        docs="docs/frameworks/langgraph.md",
    ),
    "microsoft-agent": _python_contract(
        "Microsoft Agent Framework",
        "agenticdome_sdk.integrations.microsoft_agent_framework",
        "AgenticDomeMicrosoftAgentFirewall",
        ["install_on_agent", "wrap_tool_handler", "run_agent_securely"],
        native_smoke={"module": "agenticdome_sdk.integrations.microsoft_agent_framework", "call": "install_on_agent"},
        docs="docs/frameworks/microsoft-agent-framework.md",
    ),
    "autogen": _python_contract(
        "Microsoft AutoGen",
        "agenticdome_sdk.integrations.autogen",
        "AgenticDomeAutoGenFirewall",
        ["wrap_team", "create_intervention_handler", "wrap_tool_handler"],
        packages={"autogen-agentchat": {"exact": "0.7.5"}},
        native_modules=[
            {"module": "autogen_agentchat.agents", "attrs": ["AssistantAgent"]},
            {"module": "autogen_agentchat.teams", "attrs": ["RoundRobinGroupChat"]},
        ],
        native_smoke={"module": "agenticdome_sdk.integrations.autogen", "call": "wrap_team"},
        docs="docs/frameworks/autogen.md",
    ),
    "foundry": _python_contract(
        "Microsoft AI Foundry",
        "agenticdome_sdk.integrations.microsoft_ai_foundry",
        "AgenticDomeMicrosoftAIFoundryFirewall",
        ["install_on_client", "wrap_tool_executor", "run_secure"],
        packages={
            "azure-ai-projects": {"min":"2.3.0","max":"2.5.0"},
            "azure-identity": {"exact": "1.25.3"},
        },
        native_modules=[
            {"module": "azure.ai.projects", "attrs": ["AIProjectClient"]},
            {"module": "azure.identity", "attrs": ["DefaultAzureCredential"]},
        ],
        native_smoke={"module": "agenticdome_sdk.integrations.microsoft_ai_foundry", "call": "install_on_client"},
        docs="docs/frameworks/microsoft-ai-foundry.md",
    ),
    "openai-agents": _python_contract(
        "OpenAI Agents SDK",
        "agenticdome_sdk.integrations.openai_agents",
        "AgenticDomeOpenAIAgentsFirewall",
        ["run_agent_securely", "wrap_tool_handler", "create_input_guardrail"],
        packages={"openai-agents": {"min":"0.18.3","max":"0.22.0"}},
        native_modules=[{"module": "agents", "attrs": ["Agent", "Runner", "function_tool"]}],
        native_smoke={"module": "agenticdome_sdk.integrations.openai_agents", "call": "create_input_guardrail"},
        docs="docs/frameworks/openai-agents.md",
    ),
    "claude": _python_contract(
        "Claude Agent SDK",
        "agenticdome_sdk.integrations.claude",
        "AgenticDomeClaudeFirewall",
        ["install_on_options", "secure_query", "run_client_securely", "secure_sdk_tool"],
        packages={"claude-agent-sdk": {"min":"0.2.126","max":"0.2.145"}},
        native_modules=[
            {
                "module": "claude_agent_sdk",
                "attrs": ["ClaudeAgentOptions", "ClaudeSDKClient", "HookMatcher", "query", "tool"],
            }
        ],
        native_smoke={"module": "agenticdome_sdk.integrations.claude", "call": "install_on_options"},
        docs="docs/frameworks/claude-agent-sdk.md",
    ),
    "smolagents": _python_contract(
        "Hugging Face smolagents",
        "agenticdome_sdk.integrations.smolagents",
        "AgenticDomeSmolagentsFirewall",
        ["attach_firewall", "run_agent_securely", "wrap_tool"],
        packages={"smolagents": {"exact": "1.26.0"}},
        native_modules=[{"module": "smolagents", "attrs": ["CodeAgent", "ToolCallingAgent"]}],
        native_smoke={"module": "agenticdome_sdk.integrations.smolagents", "call": "attach_firewall"},
        docs="docs/frameworks/smolagents.md",
    ),
    "agno": _python_contract(
        "Agno",
        "agenticdome_sdk.integrations.agno",
        "AgenticDomeAgnoFirewall",
        ["attach_firewall", "secure_tool", "create_hook_bundle"],
        packages={"agno": {"min":"2.8.0","max":"3.0.1"}},
        native_modules=[{"module": "agno.agent", "attrs": ["Agent"]}],
        native_smoke={"module": "agenticdome_sdk.integrations.agno", "call": "attach_firewall"},
        docs="docs/frameworks/agno.md",
    ),
    "google-adk": _python_contract(
        "Google ADK",
        "agenticdome_sdk.integrations.google_adk",
        "AgenticDomeGoogleADKFirewall",
        ["build_callback_kwargs", "install_on_agent", "wrap_tool_handler"],
        packages={"google-adk": {"min":"2.5.0","max":"2.8.0"}},
        native_modules=[
            {"module": "google.adk.agents", "attrs": ["Agent"]},
            {"module": "google.adk.tools", "attrs": ["FunctionTool"]},
        ],
        native_smoke={"module": "agenticdome_sdk.integrations.google_adk", "call": "build_callback_kwargs"},
        docs="docs/frameworks/google-adk.md",
    ),
    "llamaindex": _python_contract(
        "LlamaIndex",
        "agenticdome_sdk.integrations.llamaindex",
        "AgenticDomeLlamaIndexFirewall",
        ["to_function_tool", "wrap_query_engine", "run_query_securely"],
        packages={"llama-index": {"min":"0.14.23","max":"0.14.24"}},
        native_modules=[
            {"module": "llama_index.core.tools", "attrs": ["FunctionTool"]},
            {"module": "llama_index.core.agent.workflow", "attrs": ["FunctionAgent"]},
        ],
        native_smoke={"module": "agenticdome_sdk.integrations.llamaindex", "call": "to_function_tool"},
        docs="docs/frameworks/llamaindex.md",
    ),
    "bedrock": _python_contract(
        "AWS Bedrock Agents",
        "agenticdome_sdk.integrations.aws_bedrock",
        "AgenticDomeAWSBedrockFirewall",
        ["converse_securely", "wrap_tool_handler", "wrap_action_group_lambda"],
        packages={"boto3": {"min":"1.43.54","max":"1.43.81"}},
        native_modules=[{"module": "boto3", "attrs": ["client"]}],
        native_smoke={"module": "agenticdome_sdk.integrations.aws_bedrock", "call": "wrap_tool_handler"},
        docs="docs/frameworks/aws-bedrock.md",
    ),
    "mcp": _python_contract(
        "MCP Host / Gateway Firewall (Python)",
        "agenticdome_sdk.integrations.mcp",
        "AgenticDomeMCPFirewall",
        [
            "screen_upstream_prompt",
            "authorize_mcp_tool_call",
            "authorize_mcp_method",
            "sanitize_text",
            "sanitize_mcp_result",
            "review_forwarded_response",
            "forward_with_firewall",
        ],
        packages={"mcp": {"min": "1.26.0", "max": "1.28.1"}},
        native_modules=[
            {"module": "mcp.server.fastmcp", "attrs": ["FastMCP"]},
            {"module": "mcp.client.session", "attrs": ["ClientSession"]},
        ],
        native_smoke={"module": "agenticdome_sdk.integrations.mcp", "call": "authorize_mcp_tool_call"},
        docs="docs/mcp-integration.md",
    ),
    "custom-python": _python_contract(
        "Custom Python",
        "agenticdome_sdk",
        "AgenticDomeClient",
        ["guardrail_validate", "mesh_validate"],
        docs="docs/frameworks/custom-python.md",
    ),
    "typescript": {
        "label": "TypeScript / Node.js",
        "language": "typescript",
        "registry": "npm",
        "agenticdome_package": "agenticdome-sdk",
        "packages": {"agenticdome-sdk": {"exact": PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-sdk"]["version"]}},
        "runtime": {"node": ">=18"},
        "adapter_module": "agenticdome-sdk",
        "adapter_class": "AgenticDomeClient",
        "attachment_methods": ["guardrailValidate", "meshValidate"],
        "native_hooks": [],
        "docs": "agenticdome-sdk package README",
    },
    "openclaw": {
        "label": "OpenClaw (TypeScript)",
        "language": "typescript",
        "registry": "npm",
        "agenticdome_package": "agenticdome-openclaw-security",
        "packages": {
            "agenticdome-openclaw-security": {"exact": PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-openclaw-security"]["version"]},
            "agenticdome-sdk": {"exact": PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-sdk"]["version"]},
            "openclaw": {
                "min": _OPENCLAW_RUNTIME_MIN_VERSION,
                "max": _OPENCLAW_RUNTIME_MAX_VERSION,
            },
        },
        "runtime": {"node": _OPENCLAW_NODE_RANGE},
        "adapter_module": "agenticdome-openclaw-security",
        "adapter_class": "OpenClawFirewall",
        "attachment_methods": ["protectedExecute", "sanitizeOutput"],
        "native_hooks": ["before_agent_run", "before_tool_call", "tool_result_persist"],
        "docs": "agenticdome-openclaw-security package README",
    },
    "mcp-ts": {
        "label": "MCP Host / Gateway Firewall (TypeScript)",
        "language": "typescript",
        "registry": "npm",
        "agenticdome_package": "agenticdome-sdk",
        "packages": {"agenticdome-sdk": {"exact": PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-sdk"]["version"]}},
        "runtime": {"node": ">=18"},
        "adapter_module": "agenticdome-sdk",
        "adapter_class": "AgenticDomeMCPGateway",
        "attachment_methods": ["forward", "preflight", "mcpToolCall", "mcpGuardrailValidate", "mcpListTools"],
        "native_hooks": [],
        "protocol_methods": ["tools/call", "tools/list"],
        "integration_scope": "transport_neutral_host_gateway",
        "external_sdk": {
            "package": "@modelcontextprotocol/sdk",
            "relationship": "not_a_dependency",
            "certification": "not_applicable",
            "note": "AgenticDomeMCPGateway wraps an injected customer MCP transport without depending on it; customer transports may use @modelcontextprotocol/sdk independently.",
        },
        "docs": "agenticdome-sdk package README (MCP section)",
    },
}

# Exact machine checks used by the Admin SDK Harness.  These remain separate
# from attachment_methods because a customer-facing integration surface and a
# harness's lower-level smoke probes are related, but not interchangeable.
_HARNESS_VERIFICATION: Dict[str, Dict[str, Any]] = {
    "crewai": {
        "native_modules": {"crewai.hooks": ["register_after_tool_call_hook", "register_before_llm_call_hook", "register_before_tool_call_hook"]},
        "adapter_attrs": ["agenticdome_before_tool_call", "agenticdome_after_tool_call", "agenticdome_before_llm_call", "AgenticDomeCrewAIFirewall", "attach_firewall"],
    },
    "pydanticai": {
        "native_modules": {"pydantic_ai.capabilities": ["Hooks"]},
        "adapter_attrs": ["CyberSecFirewall"],
        "firewall_methods": ["create_hooks", "install_native_hooks", "sanitize_text"],
        "native_smoke": ["create_hooks"],
    },
    "langgraph": {
        "adapter_attrs": ["AgenticDomeLangGraphFirewall", "AgenticDomeLangChainMiddleware"],
        "firewall_methods": ["screen_input", "authorize_transition", "sanitize_output", "wrap_agent_node", "wrap_tool_node"],
        "native_smoke": ["langchain_middleware"],
    },
    "microsoft-agent": {
        "adapter_attrs": ["AgenticDomeMicrosoftAgentFirewall"],
        "firewall_methods": ["create_middleware", "install_on_agent", "before_agent_run", "after_agent_run", "before_tool_call", "after_tool_call"],
        "native_smoke": ["create_middleware", "install_on_agent"],
    },
    "autogen": {
        "native_modules": {
            "autogen_agentchat.teams": ["RoundRobinGroupChat", "SelectorGroupChat"],
            "autogen_core": ["DefaultInterventionHandler", "SingleThreadedAgentRuntime", "FunctionCall"],
        },
        "adapter_attrs": ["AgenticDomeAutoGenFirewall", "SecureAutoGenTeam"],
        "firewall_methods": ["wrap_team", "attach_agentchat_agent", "attach_conversable_agent", "create_intervention_handler", "create_termination_condition", "inspect_message", "freeze_session", "wrap_tool_handler"],
        "native_smoke": ["create_intervention_handler"],
    },
    "foundry": {
        "adapter_attrs": ["AgenticDomeMicrosoftAIFoundryFirewall"],
        "firewall_methods": ["create_middleware", "install_on_client", "before_run", "after_run", "before_tool_call", "after_tool_call"],
        "native_smoke": ["create_middleware", "install_on_client"],
    },
    "openai-agents": {
        "adapter_attrs": ["AgenticDomeOpenAIAgentsFirewall"],
        "firewall_methods": ["create_input_guardrail", "create_output_guardrail", "wrap_tool_handler", "wrap_delegated_tool_handler"],
        "native_smoke": ["create_input_guardrail", "create_output_guardrail"],
    },
    "claude": {
        "native_modules": {"claude_agent_sdk": ["ClaudeAgentOptions", "HookMatcher", "ClaudeSDKClient", "query", "tool"]},
        "adapter_attrs": ["AgenticDomeClaudeFirewall"],
        "firewall_methods": ["create_hooks", "create_hook_matchers", "install_on_options", "secure_query", "run_client_securely", "wrap_tool_handler"],
        "native_smoke": ["create_hook_matchers"],
    },
    "smolagents": {
        "native_modules": {"smolagents": ["Tool", "CodeAgent", "ToolCallingAgent", "ActionStep"]},
        "adapter_attrs": ["AgenticDomeSmolagentsFirewall", "SecureSmolTool", "SecurePythonExecutor", "attach_firewall"],
        "firewall_methods": ["wrap_tool", "attach_firewall", "create_step_callback", "run_agent_securely", "run_agent_stream_securely"],
        "native_smoke": ["wrap_tool"],
    },
    "agno": {
        "adapter_attrs": ["AgenticDomeAgnoFirewall", "attach_firewall"],
        "firewall_methods": ["create_hook_bundle", "create_middleware", "create_plugin", "attach_firewall"],
        "native_smoke": ["create_hook_bundle", "create_middleware", "attach_firewall"],
    },
    "google-adk": {
        "adapter_attrs": ["AgenticDomeGoogleADKFirewall"],
        "firewall_methods": ["build_callback_kwargs", "create_plugin", "install_on_agent", "before_agent", "before_model", "before_tool"],
        "native_smoke": ["create_plugin", "install_on_agent"],
    },
    "llamaindex": {
        "native_modules": {"llama_index.core.callbacks.base": ["BaseCallbackHandler"]},
        "adapter_attrs": ["AgenticDomeLlamaIndexFirewall"],
        "firewall_methods": ["wrap_tool_function", "wrap_query_engine", "wrap_retriever", "create_node_postprocessor", "create_callback_handler"],
        "native_smoke": ["create_callback_handler"],
    },
    "bedrock": {
        "adapter_attrs": ["AgenticDomeAWSBedrockFirewall"],
        "firewall_methods": ["screen_prompt", "authorize_tool_call", "sanitize_text", "wrap_tool_handler", "wrap_action_group_lambda"],
        "native_smoke": ["wrap_tool_handler"],
    },
    "mcp": {
        "adapter_attrs": ["AgenticDomeMCPHostFirewall"],
        "firewall_methods": ["screen_upstream_prompt", "authorize_mcp_tool_call", "authorize_mcp_method", "sanitize_text", "sanitize_mcp_result", "review_forwarded_response", "forward_with_firewall"],
        "low_code_gateway": {
            "module": "agenticdome_sdk.mcp_http_gateway",
            "transport": "streamable_http",
            "response_modes": ["application/json", "text/event-stream"],
            "legacy_standalone_sse": "requires_reviewed_local_adapter",
        },
    },
    "custom-python": {
        "adapter_attrs": ["AgenticDomeClient"],
        "firewall_methods": ["guardrail_validate", "mesh_validate"],
    },
}

_PACKAGE_CERTIFICATION_DATES: Dict[str, Dict[str, str]] = {
    "crewai": {"crewai":"2026-08-20"},
    "pydanticai": {"pydantic-ai": "2026-08-27"},
    "langgraph": {"langgraph": "2026-08-12", "langchain-core": "2026-08-20"},
    "autogen": {"autogen-agentchat": "2026-07-26"},
    "foundry": {"azure-ai-projects": "2026-08-22", "azure-identity": "2026-07-10"},
    "openai-agents": {"openai-agents": "2026-08-22"},
    "claude": {"claude-agent-sdk": "2026-08-27"},
    "smolagents": {"smolagents": "2026-07-23"},
    "agno": {"agno": "2026-08-27"},
    "google-adk": {"google-adk": "2026-08-27"},
    "llamaindex": {"llama-index": "2026-08-20"},
    "bedrock": {"boto3": "2026-08-27"},
    "mcp": {"mcp": "2026-07-10"},
}

_PACKAGE_CERTIFICATION_NOTES: Dict[str, Dict[str, str]] = {
    "mcp": {
        "mcp": "CrewAI 1.15.x combined installs currently constrain mcp to the 1.28.x line; certify newer MCP releases in an isolated MCP runtime before extending this range.",
    },
}

_SDK_ADAPTER_MODULES = {
    "crewai": "agenticdome_sdk.crewai",
    "pydanticai": "agenticdome_sdk.pydantic",
    "langgraph": "agenticdome_sdk.langgraph",
    "microsoft-agent": "agenticdome_sdk.microsoft_agent_framework",
    "autogen": "agenticdome_sdk.autogen",
    "foundry": "agenticdome_sdk.microsoft_ai_foundry",
    "openai-agents": "agenticdome_sdk.openai_agents",
    "claude": "agenticdome_sdk.claude",
    "smolagents": "agenticdome_sdk.smolagents",
    "agno": "agenticdome_sdk.agno",
    "google-adk": "agenticdome_sdk.google_adk",
    "llamaindex": "agenticdome_sdk.llamaindex",
    "bedrock": "agenticdome_sdk.aws_bedrock",
    "mcp": "agenticdome_sdk.mcp_host",
    "custom-python": "agenticdome_sdk.client",
}

for _framework_key, _module_name in _SDK_ADAPTER_MODULES.items():
    FRAMEWORK_HOOK_CATALOG[_framework_key]["adapter_module"] = _module_name

# The public adapter is named "Host" because it protects the process consuming
# MCP servers, while the shorter catalog key remains `mcp` for project detection.
FRAMEWORK_HOOK_CATALOG["mcp"]["adapter_class"] = "AgenticDomeMCPHostFirewall"
FRAMEWORK_HOOK_CATALOG["mcp"].update({
    "integration_scope": "external_sdk_host_gateway",
    "external_sdk": {
        "package": "mcp",
        "relationship": "certified_dependency",
        "certification": "version_range",
        "note": "The Python harness installs and verifies the external PyPI mcp package, its native imports, and the AgenticDome host/gateway firewall adapter.",
    },
})


FRAMEWORK_ALIASES = {
    "microsoft_agent_framework": "microsoft-agent",
    "microsoft-agent-framework": "microsoft-agent",
    "microsoft_ai_foundry": "foundry",
    "microsoft-ai-foundry": "foundry",
    "openai_agents": "openai-agents",
    "claude_agent_sdk": "claude",
    "google_adk": "google-adk",
    "aws_bedrock": "bedrock",
    "custom_python": "custom-python",
    "typescript_core": "typescript",
    "openclaw_ts": "openclaw",
    "mcp_typescript": "mcp-ts",
}


def normalize_framework_key(key: str, language: Optional[str] = None) -> str:
    normalized = str(key or "").strip().lower().replace(" ", "-")
    normalized = FRAMEWORK_ALIASES.get(normalized, normalized)
    if normalized == "mcp" and str(language or "").lower() in {"typescript", "javascript", "node", "nodejs"}:
        return "mcp-ts"
    return normalized


def framework_contract(key: str, language: Optional[str] = None) -> Optional[Dict[str, Any]]:
    contract = FRAMEWORK_HOOK_CATALOG.get(normalize_framework_key(key, language))
    return copy.deepcopy(contract) if contract else None


def catalog_digest() -> str:
    # Package versions are signed in the binding and excluded from this
    # semantic Python hook-contract digest. npm/OpenClaw releases therefore
    # cannot invalidate an already published Python wheel.
    frameworks = copy.deepcopy(FRAMEWORK_HOOK_CATALOG)
    for contract in frameworks.values():
        for package in list((contract.get("packages") or {}).keys()):
            if package in PUBLISHED_AGENTICDOME_PACKAGES:
                contract["packages"][package] = {"binding": "signed_catalog"}
    payload = {
        "schema": CATALOG_SCHEMA,
        "verified_at": CATALOG_VERIFIED_AT,
        "frameworks": frameworks,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def harness_compatibility_manifest() -> Dict[str, Dict[str, Any]]:
    manifest: Dict[str, Dict[str, Any]] = {}
    for public_key, contract in FRAMEWORK_HOOK_CATALOG.items():
        if not contract.get("harness_python"):
            continue
        harness_key = {
            "microsoft-agent": "microsoft_agent_framework",
            "foundry": "microsoft_ai_foundry",
            "openai-agents": "openai_agents",
            "google-adk": "google_adk",
            "bedrock": "aws_bedrock",
            "custom-python": "custom_python",
        }.get(public_key, public_key)
        checks = _HARNESS_VERIFICATION.get(public_key, {})
        certified_packages: Dict[str, Dict[str, str]] = {}
        for package, certification in contract.get("packages", {}).items():
            row = {
                "certified_by": "AgenticDome SDK Harness",
                "certified_at": _PACKAGE_CERTIFICATION_DATES.get(public_key, {}).get(package),
            }
            note = _PACKAGE_CERTIFICATION_NOTES.get(public_key, {}).get(package)
            if note:
                row["compatibility_note"] = note
            if certification.get("exact"):
                row["certified_exact_version"] = certification["exact"]
            if certification.get("min"):
                row["certified_min_version"] = certification["min"]
            if certification.get("max"):
                row["certified_max_version"] = certification["max"]
            certified_packages[package] = row
        manifest[harness_key] = {
            "label": contract["label"],
            "integration_scope": contract.get("integration_scope"),
            "external_sdk": copy.deepcopy(contract.get("external_sdk") or {}),
            "packages": list(contract.get("packages", {}).keys()),
            "certified_packages": certified_packages,
            "native_modules": copy.deepcopy(checks.get("native_modules", {})),
            "adapter_attrs": list(checks.get("adapter_attrs", [])),
            "firewall_methods": list(checks.get("firewall_methods", [])),
            "native_smoke": list(checks.get("native_smoke", [])),
            "catalog_schema": CATALOG_SCHEMA,
            "catalog_digest": catalog_digest(),
            "catalog_verified_at": CATALOG_VERIFIED_AT,
        }
    return manifest


def harness_firewall_classes() -> Dict[str, str]:
    classes: Dict[str, str] = {}
    for public_key, contract in FRAMEWORK_HOOK_CATALOG.items():
        if not contract.get("harness_python") or not _HARNESS_VERIFICATION.get(public_key, {}).get("firewall_methods"):
            continue
        harness_key = {
            "microsoft-agent": "microsoft_agent_framework",
            "foundry": "microsoft_ai_foundry",
            "openai-agents": "openai_agents",
            "google-adk": "google_adk",
            "bedrock": "aws_bedrock",
            "custom-python": "custom_python",
        }.get(public_key, public_key)
        classes[harness_key] = contract["adapter_class"]
    return classes


def _version_parts(version: str) -> List[int]:
    return [int(part) for part in re.findall(r"\d+", str(version or "").split("+")[0])]


def version_satisfies_certification(version: str, certification: Dict[str, str]) -> Optional[bool]:
    """Return True/False for a known version, or None when it cannot be compared."""
    parts = _version_parts(version)
    if not parts:
        return None
    if certification.get("exact"):
        return parts == _version_parts(certification["exact"])
    if certification.get("min") and parts < _version_parts(certification["min"]):
        return False
    if certification.get("max") and parts > _version_parts(certification["max"]):
        return False
    return True


def certification_label(certification: Dict[str, str]) -> str:
    if certification.get("exact"):
        return certification["exact"]
    lower = certification.get("min", "unbounded")
    upper = certification.get("max", "unbounded")
    return "%s - %s" % (lower, upper)
