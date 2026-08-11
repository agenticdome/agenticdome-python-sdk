"""Contract checks for the public framework launch guides."""

from __future__ import annotations

import ast
import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest


SDK_ROOT = Path(__file__).resolve().parents[1]
GUIDE_ROOT = SDK_ROOT / "docs" / "frameworks"

GUIDES = {
    "crewai.md": ("agenticdome_sdk.crewai", "AgenticDomeCrewAIFirewall", ("attach", "secure_tool")),
    "pydanticai.md": ("agenticdome_sdk.pydantic", "CyberSecFirewall", ("install_native_hooks", "secure_tool")),
    "langgraph.md": (
        "agenticdome_sdk.langgraph",
        "AgenticDomeLangGraphFirewall",
        ("input_node", "transition_node", "output_node", "as_langchain_middleware"),
    ),
    "microsoft-agent-framework.md": (
        "agenticdome_sdk.microsoft_agent_framework",
        "AgenticDomeMicrosoftAgentFirewall",
        ("install_on_agent", "wrap_tool_handler", "run_agent_securely"),
    ),
    "autogen.md": (
        "agenticdome_sdk.autogen",
        "AgenticDomeAutoGenFirewall",
        ("wrap_team", "create_intervention_handler", "wrap_tool_handler"),
    ),
    "microsoft-ai-foundry.md": (
        "agenticdome_sdk.microsoft_ai_foundry",
        "AgenticDomeMicrosoftAIFoundryFirewall",
        ("install_on_client", "wrap_tool_executor", "run_secure"),
    ),
    "openai-agents.md": (
        "agenticdome_sdk.openai_agents",
        "AgenticDomeOpenAIAgentsFirewall",
        ("run_agent_securely", "wrap_tool_handler", "create_input_guardrail"),
    ),
    "claude-agent-sdk.md": (
        "agenticdome_sdk.claude",
        "AgenticDomeClaudeFirewall",
        ("install_on_options", "secure_query", "run_client_securely", "secure_sdk_tool"),
    ),
    "smolagents.md": (
        "agenticdome_sdk.smolagents",
        "AgenticDomeSmolagentsFirewall",
        ("attach_firewall", "run_agent_securely", "wrap_tool"),
    ),
    "agno.md": (
        "agenticdome_sdk.agno",
        "AgenticDomeAgnoFirewall",
        ("attach_firewall", "secure_tool", "create_hook_bundle"),
    ),
    "google-adk.md": (
        "agenticdome_sdk.google_adk",
        "AgenticDomeGoogleADKFirewall",
        ("build_callback_kwargs", "install_on_agent", "wrap_tool_handler"),
    ),
    "llamaindex.md": (
        "agenticdome_sdk.llamaindex",
        "AgenticDomeLlamaIndexFirewall",
        ("to_function_tool", "wrap_query_engine", "run_query_securely"),
    ),
    "aws-bedrock.md": (
        "agenticdome_sdk.aws_bedrock",
        "AgenticDomeAWSBedrockFirewall",
        ("converse_securely", "wrap_tool_handler", "wrap_action_group_lambda"),
    ),
    "custom-python.md": ("agenticdome_sdk.client", "AgentGuardClient", ("guardrail_validate", "mesh_validate")),
}


def _production_python(guide: Path) -> str:
    text = guide.read_text(encoding="utf-8")
    section = text.split("## Attach in production", 1)[1].split("## Launch checks", 1)[0]
    blocks = re.findall(r"```python\n(.*?)```", section, flags=re.DOTALL)
    assert blocks, f"{guide.name}: missing production Python block"
    return "\n\n".join(blocks)


def test_every_supported_non_mcp_integration_has_a_launch_guide() -> None:
    index = (GUIDE_ROOT / "README.md").read_text(encoding="utf-8")
    for filename in GUIDES:
        guide = GUIDE_ROOT / filename
        assert guide.is_file(), filename
        text = guide.read_text(encoding="utf-8")
        assert filename in index
        assert "AGENTICDOME_MODE=local_sim" in text
        assert "## Attach in production" in text
        assert "## Launch checks" in text
        assert "../../README.md#" in text


def test_documented_attachment_methods_exist_on_public_adapter_classes() -> None:
    for filename, (module_name, class_name, methods) in GUIDES.items():
        module = importlib.import_module(module_name)
        adapter = getattr(module, class_name)
        guide = (GUIDE_ROOT / filename).read_text(encoding="utf-8")
        for method in methods:
            assert hasattr(adapter, method), f"{filename}: missing {class_name}.{method}"
            assert method in guide, f"{filename}: public method {method} is not documented"


@pytest.mark.parametrize("filename", sorted(GUIDES))
def test_production_snippets_compile_without_undefined_names_or_top_level_await(filename: str, tmp_path: Path) -> None:
    source = _production_python(GUIDE_ROOT / filename)
    tree = ast.parse(source, filename=filename)
    compile(tree, filename, "exec")
    assert not any(isinstance(node, (ast.Await, ast.AsyncFor)) for node in tree.body), (
        f"{filename}: await/async-for must be inside an async integration function"
    )

    snippet = tmp_path / filename.replace(".md", ".py")
    snippet.write_text(source, encoding="utf-8")
    lint = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--select", "F821", "--output-format", "concise", str(snippet)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert lint.returncode == 0, f"{filename}: production snippet has undefined names\n{lint.stdout}{lint.stderr}"


@pytest.mark.parametrize("filename", sorted(GUIDES))
def test_each_framework_guide_is_self_contained_about_live_runtime_configuration(filename: str) -> None:
    text = (GUIDE_ROOT / filename).read_text(encoding="utf-8")
    for variable in ("AGENTICDOME_API_BASE", "AGENTICDOME_API_KEY", "AGENTICDOME_TENANT_ID"):
        assert variable in text, f"{filename}: missing {variable} production configuration"
    assert "application-owned" in text.lower(), f"{filename}: application-owned inputs are not explained"


def test_local_markdown_links_in_launch_documentation_resolve() -> None:
    documents = [
        *GUIDE_ROOT.glob("*.md"),
        SDK_ROOT / "docs" / "mcp-integration.md",
        SDK_ROOT / "docs" / "performance-evidence.md",
        SDK_ROOT / "examples" / "README.md",
        SDK_ROOT / "examples" / "PRODUCTION_INTEGRATION.md",
    ]
    for document in documents:
        text = document.read_text(encoding="utf-8")
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_text = target.split("#", 1)[0]
            if not path_text:
                continue
            resolved = (document.parent / path_text).resolve()
            assert resolved.exists(), f"{document.relative_to(SDK_ROOT)} -> {target}"


def test_mcp_guide_keeps_performance_methodology_out_of_the_integration_flow() -> None:
    mcp = (SDK_ROOT / "docs" / "mcp-integration.md").read_text(encoding="utf-8")
    performance = (SDK_ROOT / "docs" / "performance-evidence.md").read_text(encoding="utf-8")
    assert "## Performance claims" not in mcp
    assert "[performance evidence guide](performance-evidence.md)" in mcp
    assert "p50, p95 and p99" in performance
    assert "Do not assign fixed latency bands" in performance
