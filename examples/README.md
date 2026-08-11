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

Before changing production code, open the [production integration playbook](PRODUCTION_INTEGRATION.md). It identifies the exact construction file, public SDK attachment call, protected execution boundary and full tested guide for every framework.

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
| CrewAI | `pip install "agenticdome-python-sdk[crewai]"` | [`frameworks/crewai.py`](frameworks/crewai.py) | [Attach before `Crew` construction](../README.md#crewai) |
| PydanticAI | `pip install "agenticdome-python-sdk[pydanticai]"` | [`frameworks/pydanticai.py`](frameworks/pydanticai.py) | [Install agent hooks and secure tools](../README.md#pydanticai) |
| LangGraph / LangChain | `pip install "agenticdome-python-sdk[langgraph]"` | [`frameworks/langgraph.py`](frameworks/langgraph.py) | [Add nodes, wrappers or middleware](../README.md#langgraph) |
| Microsoft Agent Framework | `pip install "agenticdome-python-sdk[microsoft]"` | [`frameworks/microsoft_agent_framework.py`](frameworks/microsoft_agent_framework.py) | [Install agent/run and tool boundaries](../README.md#microsoft-agent-framework) |
| Microsoft AutoGen | `pip install "agenticdome-python-sdk[autogen]"` | [`frameworks/autogen.py`](frameworks/autogen.py) | [Wrap team/Core execution](../README.md#microsoft-autogen) |
| Microsoft AI Foundry | `pip install "agenticdome-python-sdk[foundry]"` | [`frameworks/microsoft_ai_foundry.py`](frameworks/microsoft_ai_foundry.py) | [Wrap runs and local tool executors](../README.md#microsoft-ai-foundry) |
| OpenAI Agents SDK | `pip install "agenticdome-python-sdk[openai-agents]"` | [`frameworks/openai_agents.py`](frameworks/openai_agents.py) | [Secure Runner and function tools](../README.md#openai-agents-sdk) |
| Anthropic Claude Agent SDK | `pip install "agenticdome-python-sdk[claude]"` | [`frameworks/claude_agent_sdk.py`](frameworks/claude_agent_sdk.py) | [Install options hooks and secure query/client](../README.md#claude-agent-sdk) |
| Hugging Face smolagents | `pip install "agenticdome-python-sdk[smolagents]"` | [`frameworks/smolagents.py`](frameworks/smolagents.py) | [Attach agent/tool/executor boundaries](../README.md#hugging-face-smolagents) |
| Agno | `pip install "agenticdome-python-sdk[agno]"` | [`frameworks/agno.py`](frameworks/agno.py) | [Attach Agent/Team hooks](../README.md#agno) |
| Google ADK | `pip install "agenticdome-python-sdk[google-adk]"` | [`frameworks/google_adk.py`](frameworks/google_adk.py) | [Register callbacks or plugin](../README.md#google-adk) |
| LlamaIndex | `pip install "agenticdome-python-sdk[llamaindex]"` | [`frameworks/llamaindex.py`](frameworks/llamaindex.py) | [Wrap tools, query and retrieval](../README.md#llamaindex) |
| AWS Bedrock | `pip install "agenticdome-python-sdk[bedrock]"` | [`frameworks/aws_bedrock.py`](frameworks/aws_bedrock.py) | [Replace direct runtime calls with secure methods](../README.md#aws-bedrock) |
| MCP host / gateway | `pip install "agenticdome-python-sdk[mcp]"` | [`frameworks/mcp.py`](frameworks/mcp.py) | [Wrap the JSON-RPC forwarder](../README.md#mcp-host--gateway) |
| Custom Python | `pip install agenticdome-python-sdk` | [`frameworks/custom_python.py`](frameworks/custom_python.py) | [Check before execution and review output](../README.md#core-sdk-client-custom-runtimes) |

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
