# LangGraph and LangChain integration

LangGraph is graph-native: make security nodes or wrappers part of the graph
before compilation. For LangChain `create_agent`, install AgenticDome as
middleware and secure any local side-effecting tools separately.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[langgraph]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework langgraph --scenario both
```

## Attach in production

```python
from langgraph.graph import START, StateGraph
from agenticdome_sdk.langgraph import AgentState, AgenticDomeLangGraphFirewall

firewall = AgenticDomeLangGraphFirewall()
graph = StateGraph(AgentState)
graph.add_node("input_security", firewall.input_node(agent_id="support"))
graph.add_node("agent", agent_node)
graph.add_node("tool_security", firewall.transition_node(agent_id="support"))
graph.add_node("tools", tool_node)
graph.add_node("output_security", firewall.output_node(agent_id="support"))
graph.add_edge(START, "input_security")
# Connect input_security -> agent -> tool_security -> tools -> output_security.
compiled = graph.compile()
```

Alternatively use `wrap_agent_node()`, `wrap_tool_node()`, or
`as_langchain_middleware(...)`. Blocked state must route to a non-executing
security node; it must never fall through to the tool node.

See the [LangGraph API guide](../../README.md#langgraph) for complete graph
topology, middleware, handoff, retrieval and streaming examples.

## Launch checks

- Security nodes/wrappers are present before `compile()` returns.
- Every path to a tool node crosses an authorization boundary.
- Blocked routes terminate without invoking the raw tool.
- Retrieval is sanitized before it becomes model context.
- Streaming and final output use the documented output boundary.
- A delegated specialist verifies the handoff before its tool executes.

An edge or node that calls a raw executor directly is outside SDK coverage.
