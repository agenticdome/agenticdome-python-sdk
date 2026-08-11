# Hugging Face smolagents integration

Attach AgenticDome to the agent and native tools, then invoke through the secure
run wrapper. Code scanning is an application control; retain a real OS,
container or WASM sandbox for generated-code execution.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[smolagents]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework smolagents --scenario both
```

## Attach in production

```python
from agenticdome_sdk.smolagents import AgenticDomeSmolagentsFirewall

firewall = AgenticDomeSmolagentsFirewall()
agent = firewall.attach_firewall(agent, session_id="stable-session-id")

result = firewall.run_agent_securely(
    agent,
    user_prompt,
    session_id="stable-session-id",
    agent_id="support-agent",
)
```

Wrap sensitive native tools with `wrap_tool(...)`. Use
`run_agent_stream_securely(...)` for streaming and create a freshly attached
agent when strict session scope changes.

See the [smolagents API guide](../../README.md#hugging-face-smolagents) for
native Tool, CodeAgent, managed-agent, token and output examples.

## Launch checks

- Application code invokes the secure run wrapper, not the raw agent run.
- Native tools registered with the agent are wrapped before registration.
- Generated code is policy-screened and executes inside a separate sandbox.
- Managed-agent handoffs are verified before delegated tools execute.
- Streamed and final results are reviewed before reuse.

AgenticDome policy is not a replacement for isolation of executable code.
