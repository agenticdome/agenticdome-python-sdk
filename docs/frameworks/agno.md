# Agno integration

Attach AgenticDome centrally after constructing an Agno Agent or Team and
before its first run. Secure local tools explicitly, especially tools that
read protected data, mutate state or call an external service.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[agno]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework agno --scenario both
```

## Attach in production

Configure the assigned runtime, and make sure simulation is not inherited by
the production process:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

This factory receives the application-owned model and CRM operation explicitly,
defines the secured tool before registration, then attaches hooks before the
agent's first run:

```python
from typing import Any, Callable, Tuple

from agno.agent import Agent
from agenticdome_sdk.agno import AgenticDomeAgnoFirewall

def build_secured_agent(
    *,
    model: Any,
    crm_lookup: Callable[[str], Any],
) -> Tuple[Any, AgenticDomeAgnoFirewall]:
    firewall = AgenticDomeAgnoFirewall()

    @firewall.secure_tool(
        tool_name="crm.customer.read",
        tool_platform="crm",
    )
    def read_customer(agent_context: Any, customer_id: str) -> Any:
        return crm_lookup(customer_id)

    agent = Agent(name="support-agent", model=model, tools=[read_customer])
    firewall.attach_firewall(agent)
    return agent, firewall
```

Use `create_hook_bundle()`, `create_middleware()` or `create_plugin()` when the
selected Agno assembly style expects those objects. Ensure components created
later by factories receive the same attachment.

See the [Agno API guide](../../README.md#agno) for Agent/Team hooks, plugins,
secured tools, delegation, retrieval and streaming examples.

## Launch checks

- The central Agent/Team/Workflow factory performs the attachment once.
- Components dynamically created after startup are also attached.
- Tool hooks execute sanitized arguments and review returned values.
- Retrieved content is sanitized before it enters model context.
- Specialist delegation is verified at the specialist's execution boundary.

An unattached component or raw tool remains outside SDK protection.
