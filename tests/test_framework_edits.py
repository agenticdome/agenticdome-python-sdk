import ast

import pytest

from agenticdome_sdk.framework_edits import propose_framework_edits


@pytest.mark.parametrize("framework,source,expected", [
    ("crewai", "from crewai import Crew\ncrew = Crew(agents=[])\n", "import agenticdome_sdk.crewai"),
    ("pydanticai", "from pydantic_ai import Agent\nagent = Agent(\n    'model',\n)\n", "capabilities=[CyberSecFirewall().create_hooks()]"),
    ("langgraph", "from langchain.agents import create_agent\nagent = create_agent(model='x', tools=[])\n", "middleware=[AgenticDomeLangGraphFirewall().as_langchain_middleware()]"),
    ("google-adk", "from google.adk.agents import LlmAgent\nagent = LlmAgent(name='x')\n", "**AgenticDomeGoogleADKFirewall().build_callback_kwargs()"),
    ("claude", "from claude_agent_sdk import ClaudeAgentOptions\noptions = ClaudeAgentOptions()\n", "AgenticDomeClaudeFirewall().install_on_options(ClaudeAgentOptions())"),
    ("agno", "from agno.agent import Agent\nagent = Agent(name='x')\n", "AgenticDomeAgnoFirewall().attach_firewall(agent)"),
    ("llamaindex", "from llama_index.core.tools import FunctionTool\ntool = FunctionTool.from_defaults(fn=lookup, name='lookup')\n", "async_fn=AgenticDomeLlamaIndexFirewall().wrap_tool_function(lookup, tool_name='lookup')"),
    ("openai-agents", "from agents import FunctionTool\ntool = FunctionTool(name='lookup', description='x', params_json_schema={}, on_invoke_tool=lookup)\n", "on_invoke_tool=AgenticDomeOpenAIAgentsFirewall().wrap_tool_handler(tool_name='lookup', handler=lookup, handler_args_format='json')"),
    ("custom-python", "def execute_tool(tool_name, tool_args, agent_id, session_id):\n    return registry[tool_name](**tool_args)\n", "@guarded_tool_executor\ndef execute_tool"),
    ("custom-python", "class Tools:\n    def dispatch_tool(self, tool_name, tool_args, agent_id, session_id):\n        return self.registry[tool_name](**tool_args)\n", "    @guarded_tool_executor\n    def dispatch_tool"),
])
def test_supported_framework_construction_gets_exact_parseable_edit(framework, source, expected):
    updated, edits = propose_framework_edits(source, [framework])
    assert updated is not None
    assert expected in updated
    assert len(edits) == 1
    ast.parse(updated)
    assert propose_framework_edits(updated, [framework]) == (None, [])


def test_existing_literal_middleware_is_extended_without_overwriting_it():
    source = "from langchain.agents import create_agent\nagent = create_agent('x', middleware=[existing])\n"
    updated, edits = propose_framework_edits(source, ["langgraph"])
    assert edits and "middleware=[existing, AgenticDomeLangGraphFirewall().as_langchain_middleware()]" in updated


@pytest.mark.parametrize("framework,source", [
    ("pydanticai", "from pydantic_ai import Agent\nagent = Agent('x', **settings)\n"),
    ("pydanticai", "from pydantic_ai import Agent\nagent = Agent('x', capabilities=provided)\n"),
    ("langgraph", "from langchain.agents import create_agent\nagent = create_agent('x', middleware=provided)\n"),
    ("google-adk", "from google.adk.agents import Agent\nagent = Agent(name='x', before_tool_callback=own)\n"),
    ("crewai", "from crewai import Crew\nCrew = own_factory\ncrew = Crew(agents=[])\n"),
    ("claude", "from claude_agent_sdk import ClaudeAgentOptions\noptions = ClaudeAgentOptions(**settings)\n"),
    ("agno", "from agno.agent import Agent\na = Agent(name='a')\nb = Agent(name='b')\n"),
    ("llamaindex", "from llama_index.core.tools import FunctionTool\ntool = FunctionTool.from_defaults(fn=lookup, async_fn=alookup)\n"),
    ("llamaindex", "from llama_index.core.tools import FunctionTool\ntool = FunctionTool.from_defaults(fn=lookup, name=dynamic_name())\n"),
    ("openai-agents", "from agents import FunctionTool\ntool = FunctionTool(name='x', description='x', params_json_schema={}, on_invoke_tool=lambda ctx, args: None)\n"),
    ("openai-agents", "from agents import FunctionTool\ntool = FunctionTool(name=dynamic_name(), description='x', params_json_schema={}, on_invoke_tool=run)\n"),
    ("custom-python", "def execute_tool(tool_name, tool_args):\n    return registry[tool_name](**tool_args)\n"),
    ("custom-python", "@existing_gate\ndef execute_tool(tool_name, tool_args, agent_id, session_id):\n    return registry[tool_name](**tool_args)\n"),
])
def test_ambiguous_or_customer_managed_attachment_is_not_rewritten(framework, source):
    assert propose_framework_edits(source, [framework]) == (None, [])


def test_multiple_frameworks_in_one_file_are_reparsed_and_keep_future_import_first():
    source = (
        '"""Application."""\nfrom __future__ import annotations\n'
        "from pydantic_ai import Agent\nfrom langchain.agents import create_agent\n"
        "p = Agent('x')\nl = create_agent('x', tools=[])\n"
    )
    updated, edits = propose_framework_edits(source, ["pydanticai", "langgraph"])
    assert updated is not None and len(edits) == 2
    ast.parse(updated)
    assert updated.index("from __future__ import annotations") < updated.index("from agenticdome_sdk")


def test_multiple_direct_openai_function_tools_are_wrapped_once():
    source = (
        "from agents import FunctionTool\n"
        "a = FunctionTool(name='a', description='a', params_json_schema={}, on_invoke_tool=run_a)\n"
        "b = FunctionTool(name='b', description='b', params_json_schema={}, on_invoke_tool=run_b)\n"
    )
    updated, edits = propose_framework_edits(source, ["openai-agents"])
    assert updated is not None and len(edits) == 2
    assert updated.count("wrap_tool_handler(") == 2
    assert propose_framework_edits(updated, ["openai-agents"]) == (None, [])
