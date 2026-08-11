# AgenticDome Python SDK examples

Try AgenticDome before creating an account or connecting a runtime sidecar. The local simulator is deterministic, makes no network requests, needs no API key, and never executes the example tools.

## Five-minute developer trial

### 1. Install

```bash
pip install agenticdome-python-sdk
```

### 2. Enable offline simulation

```bash
export AGENTICDOME_MODE=local_sim
```

### 3. See allowed and blocked outcomes

```bash
agenticdome-demo --framework langgraph --scenario both
```

The example does not execute a real tool. It prints:

- `ALLOWED — TOOL WOULD EXECUTE` for the normal CRM lookup.
- `BLOCKED — TOOL WOULD NOT EXECUTE` for the prompt-injected refund.

### 4. Choose your framework

```bash
agenticdome-demo --list-frameworks
agenticdome-demo --framework all --scenario both
```

Use the framework gallery below for an individual runnable example matching your stack.

Before changing production code, select the matching [framework integration guide](../docs/frameworks/README.md), then use the [production integration playbook](PRODUCTION_INTEGRATION.md) for the shared attachment and proof checklist.

### 5. Move to live tenant enforcement

Remove offline mode, obtain the customer's assigned runtime sidecar URL, Runtime/SDK API key and tenant ID, then run the same proof against that sidecar:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example"
export AGENTICDOME_API_KEY="your_runtime_sdk_key"
export AGENTICDOME_TENANT_ID="your_tenant_id"
agenticdome-demo --framework langgraph --scenario both --live
```

Offline mode demonstrates SDK behaviour using a bundled baseline. Only live mode applies the customer's policy, topology, telemetry, signed decisions and runtime enforcement.

## Running examples from a cloned repository

You can also clone this repository and run:

```bash
python examples/local_simulation_gallery.py
python examples/frameworks/langgraph.py
python examples/frameworks/crewai.py
```

## Framework gallery

Every entry runs the same allowed/blocked pair without importing the third-party framework. This proves the AgenticDome package, framework identity, configuration path, and decision contract before you install a larger framework dependency. The production link identifies exactly where and how to attach the public SDK in the real framework.

| Integration | Install for production | Offline example | Production guide |
| :--- | :--- | :--- | :--- |
| CrewAI | `pip install "agenticdome-python-sdk[crewai]"` | [`frameworks/crewai.py`](frameworks/crewai.py) | [CrewAI launch guide](../docs/frameworks/crewai.md) |
| PydanticAI | `pip install "agenticdome-python-sdk[pydanticai]"` | [`frameworks/pydanticai.py`](frameworks/pydanticai.py) | [PydanticAI launch guide](../docs/frameworks/pydanticai.md) |
| LangGraph / LangChain | `pip install "agenticdome-python-sdk[langgraph]"` | [`frameworks/langgraph.py`](frameworks/langgraph.py) | [LangGraph launch guide](../docs/frameworks/langgraph.md) |
| Microsoft Agent Framework | `pip install "agenticdome-python-sdk[microsoft]"` | [`frameworks/microsoft_agent_framework.py`](frameworks/microsoft_agent_framework.py) | [Microsoft Agent Framework launch guide](../docs/frameworks/microsoft-agent-framework.md) |
| Microsoft AutoGen | `pip install "agenticdome-python-sdk[autogen]"` | [`frameworks/autogen.py`](frameworks/autogen.py) | [AutoGen launch guide](../docs/frameworks/autogen.md) |
| Microsoft AI Foundry | `pip install "agenticdome-python-sdk[foundry]"` | [`frameworks/microsoft_ai_foundry.py`](frameworks/microsoft_ai_foundry.py) | [Foundry launch guide](../docs/frameworks/microsoft-ai-foundry.md) |
| OpenAI Agents SDK | `pip install "agenticdome-python-sdk[openai-agents]"` | [`frameworks/openai_agents.py`](frameworks/openai_agents.py) | [OpenAI Agents launch guide](../docs/frameworks/openai-agents.md) |
| Anthropic Claude Agent SDK | `pip install "agenticdome-python-sdk[claude]"` | [`frameworks/claude_agent_sdk.py`](frameworks/claude_agent_sdk.py) | [Claude Agent SDK launch guide](../docs/frameworks/claude-agent-sdk.md) |
| Hugging Face smolagents | `pip install "agenticdome-python-sdk[smolagents]"` | [`frameworks/smolagents.py`](frameworks/smolagents.py) | [smolagents launch guide](../docs/frameworks/smolagents.md) |
| Agno | `pip install "agenticdome-python-sdk[agno]"` | [`frameworks/agno.py`](frameworks/agno.py) | [Agno launch guide](../docs/frameworks/agno.md) |
| Google ADK | `pip install "agenticdome-python-sdk[google-adk]"` | [`frameworks/google_adk.py`](frameworks/google_adk.py) | [Google ADK launch guide](../docs/frameworks/google-adk.md) |
| LlamaIndex | `pip install "agenticdome-python-sdk[llamaindex]"` | [`frameworks/llamaindex.py`](frameworks/llamaindex.py) | [LlamaIndex launch guide](../docs/frameworks/llamaindex.md) |
| AWS Bedrock | `pip install "agenticdome-python-sdk[bedrock]"` | [`frameworks/aws_bedrock.py`](frameworks/aws_bedrock.py) | [AWS Bedrock launch guide](../docs/frameworks/aws-bedrock.md) |
| MCP host / gateway | `pip install "agenticdome-python-sdk[mcp]"` | [`frameworks/mcp.py`](frameworks/mcp.py) · [`mcp_gateway_action_firewall.py`](mcp_gateway_action_firewall.py) | [MCP Action Firewall guide](../docs/mcp-integration.md) · [API reference](../README.md#mcp-host--gateway) |
| Custom Python | `pip install agenticdome-python-sdk` | [`frameworks/custom_python.py`](frameworks/custom_python.py) | [Custom Python launch guide](../docs/frameworks/custom-python.md) |

## What the simulator proves

It proves that your SDK attachment can call the public AgenticDome decision contract and react correctly to `ALLOWED`, `BLOCKED`, and `REDACTED`. Blocked and redacted decisions are logged to the local terminal using safe metadata only; raw prompts, tool arguments, keys, and secrets are not logged.

It does **not** load your tenant policy, contact AgenticDome, issue a signed decision or execution receipt, write telemetry, discover topology, or certify production protection. Local simulation is refused when `AGENTICDOME_PRODUCTION_MODE=true`. Connect the same integration to your assigned runtime sidecar for real enforcement.

## Live transition

Remove `AGENTICDOME_MODE=local_sim`, attach the integration at the real prompt/tool/output boundary, and configure:

```bash
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example"
export AGENTICDOME_API_KEY="your_runtime_sdk_key"
export AGENTICDOME_TENANT_ID="your_tenant_id"
```

Then run a live proof, for example:

```bash
agenticdome-demo --framework langgraph --scenario both --live
```
