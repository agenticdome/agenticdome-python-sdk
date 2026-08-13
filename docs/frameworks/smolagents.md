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

**Demo scope:** this command evaluates two fixed inputs with a deterministic,
bundled public baseline. It does not contact AgenticDome, load tenant policy,
execute tools, or instantiate smolagents. The framework option is a label and
guide selector, not a smolagents integration test.

## Attach in production

Configure the assigned runtime first:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

Run `agenticdome-demo --framework smolagents --scenario both --live` to obtain
real tenant-engine decisions for those fixed inputs. That checks the assigned
sidecar, not smolagents attachment; the code below attaches the adapter to the
real application boundary.

For managed service, the API base is assigned in the selected supported
geographic region, subject to availability. A contracted Sovereign runtime is
inside the customer-controlled environment. Normal SDK calls do not require
customer-managed Redis; see [runtime location and Redis responsibilities](../runtime-deployment.md).

Pass the application-owned agent and prompt into the execution boundary:

```python
from typing import Any

from agenticdome_sdk.smolagents import AgenticDomeSmolagentsFirewall

def run_secured_agent(*, agent: Any, user_prompt: str) -> Any:
    firewall = AgenticDomeSmolagentsFirewall()
    secured_agent = firewall.attach_firewall(agent, session_id="stable-session-id")
    return firewall.run_agent_securely(
        secured_agent,
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
