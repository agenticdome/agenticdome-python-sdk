# OpenAI Agents SDK integration

Combine run-level input/output protection with secured function tools. Runner
guardrails protect the agent loop; the function wrapper is the hard boundary
immediately before a local side effect.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[openai-agents]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework openai-agents --scenario both
```

## Attach in production

Configure the assigned runtime first:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

Pass the application-owned runner, agent and raw handler into an async boundary.
Register only `secure_lookup` with the framework's function-tool mechanism:

```python
from typing import Any, Callable, Tuple

from agenticdome_sdk.openai_agents import AgenticDomeOpenAIAgentsFirewall

async def run_secured_agent(
    *,
    runner: Any,
    agent: Any,
    user_prompt: str,
    raw_lookup: Callable[..., Any],
) -> Tuple[Any, Callable[..., Any]]:
    firewall = AgenticDomeOpenAIAgentsFirewall()
    secure_lookup = firewall.wrap_tool_handler(
        tool_name="crm.customer.read",
        tool_platform="crm",
        handler=raw_lookup,
    )
    result = await firewall.run_agent_securely(
        runner=runner,
        agent=agent,
        input_text=user_prompt,
        session_id="stable-session-id",
    )
    return result, secure_lookup
```

Register `secure_lookup` with `@function_tool`; do not register `raw_lookup`.
Use `create_input_guardrail()` and `create_output_guardrail()` when composing
with an existing Runner configuration, and the delegated wrapper for a
specialist tool.

See the [OpenAI Agents API guide](../../README.md#openai-agents-sdk) for exact
Runner, function-tool, handoff, schema, streaming and shared-state patterns.

## Launch checks

- No production path calls `Runner` outside the selected secured run boundary.
- Function tools invoke secured handlers with sanitized arguments.
- Handoffs do not imply permission to execute a specialist's sensitive tool.
- Streamed and final output are reviewed before delivery.
- Stable session and actor identity is carried through the entire run.

Remote hosted tools are protected only where the local application can gate
their request or response.
