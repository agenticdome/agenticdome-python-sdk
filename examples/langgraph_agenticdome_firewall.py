#!/usr/bin/env python3
"""Complete LangGraph topology with AgenticDome at every owned boundary.

Run without an account:
    AGENTICDOME_MODE=local_sim python examples/langgraph_agenticdome_firewall.py

For live enforcement, set AGENTICDOME_MODE=live and configure the assigned
runtime sidecar URL, Runtime / SDK API key, and tenant ID.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from langgraph.graph import END, START, StateGraph

from agenticdome_sdk.langgraph import AgentState, AgenticDomeLangGraphFirewall


if "AGENTICDOME_MODE" not in os.environ:
    live_values = (
        os.getenv("AGENTICDOME_API_BASE"),
        os.getenv("AGENTICDOME_API_KEY"),
        os.getenv("AGENTICDOME_TENANT_ID"),
    )
    os.environ["AGENTICDOME_MODE"] = "live" if all(live_values) else "local_sim"


async def agent_node(state: AgentState) -> AgentState:
    """Replace with the application's normal model/agent node."""
    return state


async def tool_node(state: AgentState) -> AgentState:
    """Replace with the application's real tool executor."""
    return state


def build_graph() -> Any:
    firewall = AgenticDomeLangGraphFirewall()
    graph = StateGraph(AgentState)
    graph.add_node("input_firewall", firewall.input_node(agent_id="support_orchestrator"))
    graph.add_node("agent", agent_node)
    graph.add_node("transition_firewall", firewall.transition_node(agent_id="support_orchestrator"))
    graph.add_node("tools", tool_node)
    graph.add_node("output_firewall", firewall.output_node(agent_id="support_orchestrator"))

    graph.add_edge(START, "input_firewall")
    graph.add_edge("input_firewall", "agent")
    graph.add_edge("agent", "transition_firewall")
    graph.add_edge("transition_firewall", "tools")
    graph.add_edge("tools", "output_firewall")
    graph.add_edge("output_firewall", END)
    return graph.compile()


async def run() -> dict[str, Any]:
    compiled = build_graph()
    return await compiled.ainvoke(
        {
            "session_id": "sdk-local-sim-001",
            "agent_id": "support_orchestrator",
            "messages": [{"role": "user", "content": "Check customer case 123."}],
        }
    )


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run()), indent=2, default=str))
