# Production integration playbook

This guide answers one practical question: **where does AgenticDome go in my application?**

It documents only stable public SDK attachment points. It intentionally does not publish AgenticDome policy algorithms, threat signatures, decision-token formats, private endpoints, detection thresholds, or internal runtime implementation.

## The integration contract

Environment variables configure the SDK; they do not intercept a framework by themselves. A production integration must attach AgenticDome in the code path that owns the action:

```text
user input
    ↓  screen at the framework/run boundary
agent or graph
    ↓  authorize immediately before a local tool or MCP request
tool / function / external request
    ↓  review returned tool data before it re-enters the agent
agent output
    ↓  review before returning, storing or streaming it
customer / downstream system
```

For multi-agent delegation, authorize the manager-to-specialist handoff and verify the resulting decision at the specialist's execution boundary. Do not catch a denied decision and retry the same operation through an unwrapped function.

## Before copying a framework recipe

1. Run the framework's offline example and confirm one `ALLOWED` and one `BLOCKED` result.
2. Install the matching SDK extra.
3. Put the attachment in the module that constructs the agent, graph, runner, tool registry or gateway—not in an unrelated configuration file.
4. Wrap every side-effecting local tool, even when the framework also has run-level guardrails.
5. Use a stable `session_id`, `run_id`, `trace_id` or equivalent across the whole interaction.
6. In multi-worker deployments, configure the documented shared token store.
7. Test the live path against the tenant's assigned runtime sidecar before enabling production traffic.

## Framework attachment map

The “first public call” column is the minimum attachment point. Follow the full guide for tool wrappers, streaming, delegation and output handling.

| Framework | Put AgenticDome here | First public call | What must not bypass it | Full guide |
| :--- | :--- | :--- | :--- | :--- |
| CrewAI | Application bootstrap, before any `Crew` is constructed | `import agenticdome_sdk.crewai` or `AgenticDomeCrewAIFirewall().attach(crew)` | Crew prompts and every sensitive local tool | [CrewAI](../docs/frameworks/crewai.md) |
| PydanticAI | Module that constructs each `Agent` and registers its tools | `firewall.install_native_hooks(agent)` plus `@firewall.secure_tool(...)` | Direct calls to the undecorated tool implementation | [PydanticAI](../docs/frameworks/pydanticai.md) |
| LangGraph / LangChain | Graph/agent builder before `compile()` or `create_agent()` returns | Firewall nodes/wrappers or `firewall.as_langchain_middleware(...)` | Graph edges or tool nodes that skip the secured transition | [LangGraph](../docs/frameworks/langgraph.md) |
| Microsoft Agent Framework | Agent/workflow factory and tool registration module | `firewall.install_on_agent(agent)` or `firewall.run_agent_securely(...)` | Raw tool handlers and direct runs outside the middleware | [Microsoft Agent Framework](../docs/frameworks/microsoft-agent-framework.md) |
| Microsoft AutoGen | AgentChat team/Core runtime construction | `firewall.wrap_team(team, session_id=...)` or the documented intervention handler | Direct `team.run()` calls and uninspected Core tool events | [Microsoft AutoGen](../docs/frameworks/autogen.md) |
| Microsoft AI Foundry | Foundry client/run and local tool-executor construction | `firewall.install_on_client(client)`, `run_secure(...)` or `wrap_tool_executor(...)` | Local function execution outside the secured executor | [Microsoft AI Foundry](../docs/frameworks/microsoft-ai-foundry.md) |
| OpenAI Agents SDK | Module constructing `Agent`, `Runner` and `@function_tool` functions | `firewall.run_agent_securely(...)` and `firewall.wrap_tool_handler(...)` | Calling `Runner` or raw side-effecting functions directly | [OpenAI Agents SDK](../docs/frameworks/openai-agents.md) |
| Claude Agent SDK | Module constructing `ClaudeAgentOptions`, client or SDK MCP tools | `firewall.install_on_options(options)` plus `run_client_securely(...)` or `secure_query(...)` | A client/query path using options without the installed hooks | [Claude Agent SDK](../docs/frameworks/claude-agent-sdk.md) |
| Hugging Face smolagents | Module constructing `CodeAgent`/`ToolCallingAgent` and native tools | `firewall.run_agent_securely(...)` or `firewall.attach_firewall(...)` | Direct executors, tools or managed agents outside the attached agent | [smolagents](../docs/frameworks/smolagents.md) |
| Agno | Agent, Team, Workflow or AgentOS component factory | `firewall.attach_firewall(agent_or_team)` | Components created after bootstrap without hooks; raw high-risk tools | [Agno](../docs/frameworks/agno.md) |
| Google ADK | `LlmAgent` construction or central plugin registration | `**firewall.build_callback_kwargs()` or `firewall.install_on_agent(agent)` | Tools not exposed through the secured callbacks/wrappers | [Google ADK](../docs/frameworks/google-adk.md) |
| LlamaIndex | Tool, query engine, retriever and callback assembly module | `to_function_tool(...)`, `wrap_query_engine(...)` or `run_query_securely(...)` | Direct query/retrieval/tool paths outside the selected wrapper | [LlamaIndex](../docs/frameworks/llamaindex.md) |
| AWS Bedrock | Code that calls boto3 runtime/agent clients and action-group handlers | `converse_securely(...)`, `invoke_model_securely(...)` or the matching wrapper | Direct boto3 calls and unwrapped action-group/local tool handlers | [AWS Bedrock](../docs/frameworks/aws-bedrock.md) |
| MCP host / gateway | The single JSON-RPC forwarding function | `firewall.forward_with_firewall(...)` or `preflight_request(...)` | Any alternate route that forwards `tools/call` directly | [MCP host / gateway](../docs/mcp-integration.md) |
| Custom Python | Your prompt handler, tool executor, delegation router and response boundary | `guardrail_validate()` before execution and `mesh_validate()` before return | Calling the real function before checking the verdict | [Custom Python](../docs/frameworks/custom-python.md) |

## Framework-specific operating notes

### CrewAI

- Import the CrewAI module during process bootstrap, before crews and agents are created.
- Use scoped `attach()` only when a process intentionally needs isolated firewall instances.
- Explicitly decorate high-impact tools so local side effects remain protected even if orchestration changes.

### PydanticAI

- Install native hooks on every constructed agent; do not assume one agent's hooks cover another agent.
- Keep `secure_tool` on sensitive tools because lifecycle APIs vary between supported PydanticAI versions.
- Execute the sanitized arguments supplied by the wrapper rather than retaining the original values elsewhere.

### LangGraph / LangChain

- Add firewall nodes and secured transitions before graph compilation, or install middleware during agent construction.
- Ensure conditional edges route blocked state to a non-executing security node.
- Wrap retrieval and streaming paths when their output can re-enter the model or reach a customer.

### Microsoft Agent Framework

- Install middleware where the agent is built and wrap local tool handlers where they are registered.
- Use the secure run wrapper when the application directly controls invocation.
- Protect manager and specialist boundaries separately for delegated actions.

### Microsoft AutoGen

- Call the secured team proxy rather than the original team when the application owns `run()`.
- For Core runtimes, register the documented intervention handler at runtime construction.
- Treat session freeze/denial as a terminal security result until an authorized operator resolves it.

### Microsoft AI Foundry

- Foundry-hosted orchestration does not automatically protect local functions; wrap the local executor.
- Attach middleware to each client/run path the application uses.
- Keep bearer-auth threat analysis optional unless the tenant has deliberately enabled it; normal runtime policy still requires the Runtime/SDK key.

### OpenAI Agents SDK

- Use run-level guardrails for input/output and function-tool wrappers for local side effects.
- Register the secured function, not the raw implementation, with `@function_tool`.
- Use the documented delegated-tool wrapper when a handoff can execute a sensitive function.

### Claude Agent SDK

- Install hooks on the exact `ClaudeAgentOptions` instance supplied to the client/query.
- Consume messages from `run_client_securely()` or `secure_query()` so final output review is not skipped.
- Compose local SDK MCP tools through `secure_sdk_tool()`.

### Hugging Face smolagents

- Prefer `run_agent_securely()` because it covers input and final output in addition to attached tool/executor boundaries.
- Keep generated-code scanning enabled, but use an OS/container/WASM sandbox as a separate execution control.
- Create a fresh attached agent for a new strict session rather than reusing a differently scoped instance.

### Agno

- Attach after constructing the Agent/Team and before the first run.
- Register the hook bundle, middleware or plugin once at the central construction layer.
- Decorate tools that read sensitive data, mutate state or call external services.

### Google ADK

- Supply callback keyword arguments when constructing `LlmAgent`, or install them on every existing agent.
- Use async callbacks in async ADK runtimes and the documented synchronous variants only in synchronous configurations.
- Preserve stable ADK context identifiers so policy evidence is correlated correctly.

### LlamaIndex

- Wrap both the query/retrieval path and every local `FunctionTool` with side effects.
- Sanitize retrieved nodes before they are inserted into a prompt.
- Use callbacks for visibility; retain wrappers as the hard execution boundary.

### AWS Bedrock

- Replace direct boto3 runtime calls with the matching secure method for the API you use.
- Wrap action-group Lambda handlers and local tool-use implementations separately.
- AgenticDome protects the application-controlled request/response boundary, not code inside AWS-managed services.

### MCP host / gateway

- Put the firewall around the one function that forwards JSON-RPC to third-party servers.
- Forward the request returned by preflight, because it may contain sanitized business arguments.
- Do not expose a second unguarded forwarding route; remote MCP server internals are outside the local boundary.

### Custom Python

- Check the returned verdict before calling the real tool.
- Use sanitized text/arguments when supplied by the public response contract.
- Review output before returning, storing, streaming or feeding it back to another agent.

## Production proof checklist

A framework integration is ready only when all of the following are true:

- The offline allowed and blocked scenarios both behave as expected.
- The framework's actual construction path contains the documented attachment.
- A safe live tool is allowed through the tenant's assigned sidecar.
- A deliberately hostile test is blocked before the real handler is called.
- Redacted output uses the returned sanitized value.
- Direct calls to raw sensitive handlers are absent from production routes.
- Stable session/trace identity is visible across prompt, tool and output events.
- Multi-worker delegation uses the documented shared store and specialist verification.
- Fail-closed behavior has been tested for the customer's chosen production policy.
- The SDK Harness and performance smoke test pass against the same tenant/sidecar assignment.

## What AgenticDome does not claim

An SDK attachment protects boundaries visible to that process. It does not automatically intercept a remote service, an alternate network route, an unwrapped function, or code executing outside the application boundary. Use the AgenticDome gateway, workload identity, host controls and sandbox integrations where the customer's threat model requires protection beyond the application SDK.
