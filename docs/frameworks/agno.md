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

```python
from agenticdome_sdk.agno import AgenticDomeAgnoFirewall

firewall = AgenticDomeAgnoFirewall()
agent = firewall.attach_firewall(agent)

@firewall.secure_tool(
    tool_name="crm.customer.read",
    tool_platform="crm",
)
def read_customer(agent, customer_id: str):
    return crm.read_customer(customer_id)
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
