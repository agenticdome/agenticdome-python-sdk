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

Configure the assigned runtime first:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

For managed service, the API base is assigned in the selected supported
geographic region, subject to availability. A contracted Sovereign runtime is
inside the customer-controlled environment. Normal SDK calls do not require
customer-managed Redis; see [runtime location and Redis responsibilities](../runtime-deployment.md).

Pass the application-owned options and message consumer explicitly. Keeping
the async iterator inside a function makes the example valid Python:

```python
from typing import Any, Callable

from agenticdome_sdk.claude import AgenticDomeClaudeFirewall

async def run_secured_query(
    *,
    options: Any,
    user_prompt: str,
    consume: Callable[[Any], None],
) -> None:
    firewall = AgenticDomeClaudeFirewall()
    secured_options = firewall.install_on_options(options)

    async for message in firewall.secure_query(
        prompt=user_prompt,
        options=secured_options,
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
