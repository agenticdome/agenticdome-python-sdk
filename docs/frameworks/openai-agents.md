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

```python
from agenticdome_sdk.openai_agents import AgenticDomeOpenAIAgentsFirewall

firewall = AgenticDomeOpenAIAgentsFirewall()
secure_lookup = firewall.wrap_tool_handler(
    tool_name="crm.customer.read",
    tool_platform="crm",
    handler=raw_lookup,
)

result = await firewall.run_agent_securely(
    runner=Runner,
    agent=agent,
    input_text=user_prompt,
    session_id="stable-session-id",
)
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
