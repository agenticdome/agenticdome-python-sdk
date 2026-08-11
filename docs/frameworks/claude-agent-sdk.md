# Anthropic Claude Agent SDK integration

Install hooks on the exact `ClaudeAgentOptions` instance passed to the SDK,
then consume the secured query/client iterator so returned messages cannot
bypass output review. Secure locally exposed SDK tools separately.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[claude]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework claude --scenario both
```

## Attach in production

```python
from agenticdome_sdk.claude import AgenticDomeClaudeFirewall

firewall = AgenticDomeClaudeFirewall()
options = firewall.install_on_options(options)

async for message in firewall.secure_query(
    prompt=user_prompt,
    options=options,
    session_id="stable-session-id",
    agent_id="support-agent",
):
    consume(message)
```

Use `run_client_securely(...)` for a constructed SDK client and
`secure_sdk_tool(...)` for local SDK MCP tools. Every query/client path must use
the options object containing the installed hooks.

See the [Claude Agent SDK API guide](../../README.md#claude-agent-sdk) for hook
composition, query/client, tool output, delegation and streaming behavior.

## Launch checks

- The secured options instance is the one supplied to every production client.
- Pre-tool denials prevent the SDK tool implementation from running.
- Tool results and final messages pass through the secured iterator.
- Decision context is bound and consumed at delegated local execution.
- Alternate query/client construction paths are removed or equivalently wrapped.

Hooks cannot intercept an unrelated client created with different options.
