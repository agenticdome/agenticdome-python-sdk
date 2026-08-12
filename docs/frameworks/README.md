# AgenticDome Python framework integration guides

Choose the runtime that owns your agent, graph, tool or gateway boundary. Each
guide uses the same production contract: configure the SDK, attach it in code,
authorize immediately before local execution, review returned content, and
prove both an allowed and blocked path.

| Integration | Guide | Primary protected boundary |
| --- | --- | --- |
| CrewAI | [CrewAI](crewai.md) | Crew bootstrap, LLM/tool hooks and local tools |
| PydanticAI | [PydanticAI](pydanticai.md) | Agent hooks and decorated tools |
| LangGraph / LangChain | [LangGraph](langgraph.md) | Graph nodes, transitions and tool nodes |
| Microsoft Agent Framework | [Microsoft Agent Framework](microsoft-agent-framework.md) | Agent run, middleware and function tools |
| Microsoft AutoGen | [AutoGen](autogen.md) | Team/Core message and tool execution |
| Microsoft AI Foundry | [Microsoft AI Foundry](microsoft-ai-foundry.md) | Client/run boundary and local tool executor |
| OpenAI Agents SDK | [OpenAI Agents SDK](openai-agents.md) | Runner guardrails and function tools |
| Anthropic Claude Agent SDK | [Claude Agent SDK](claude-agent-sdk.md) | Options hooks, query/client and SDK tools |
| Hugging Face smolagents | [smolagents](smolagents.md) | Agent run, generated code and native tools |
| Agno | [Agno](agno.md) | Agent/Team hooks, tools and returned content |
| Google ADK | [Google ADK](google-adk.md) | Agent callbacks and local tools |
| LlamaIndex | [LlamaIndex](llamaindex.md) | Query, retrieval and FunctionTool boundaries |
| AWS Bedrock | [AWS Bedrock](aws-bedrock.md) | boto3 calls, tool use and action groups |
| MCP host / gateway | [MCP](../mcp-integration.md) | JSON-RPC forwarding and returned content |
| Custom Python | [Custom Python](custom-python.md) | Application-owned prompt/tool/output boundary |

## Shared five-step path

1. Install the matching package extra.
2. Run `AGENTICDOME_MODE=local_sim` with one allowed and one blocked scenario.
3. Obtain the assigned runtime sidecar URL, Runtime/SDK key and tenant ID.
4. Attach the adapter in the application construction path and remove raw
   execution routes that bypass it.
5. Prove safe, blocked, redacted and sidecar-unavailable behavior before
   production, then run SDK Assurance and Performance Smoke.

For managed service, AgenticDome assigns the runtime in the customer's selected
supported geographic region, subject to availability. Under a Sovereign
deployment, the runtime is placed inside the contracted customer-controlled
VPC, cloud, or on-premises boundary. Normal SDK use does not require customers
to install Redis; Redis is optional only for Python delegation state that must
cross application processes, workers, or pods. See
[Runtime location and Redis responsibilities](../runtime-deployment.md).

The offline simulator proves SDK control flow, not tenant enforcement. The
public SDK does not expose AgenticDome policy algorithms, private threat
signatures, decision-token formats or control-plane internals.

Use the [production integration playbook](../../examples/PRODUCTION_INTEGRATION.md)
for the cross-framework handoff checklist and the
[performance evidence guide](../performance-evidence.md) when publishing
latency or throughput results.
