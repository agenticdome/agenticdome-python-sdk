# Microsoft Agent Framework integration

Install AgenticDome where agents, workflows and function tools are assembled.
Protect both the agent run and the local function that performs the real
action; human approval settings do not replace runtime policy enforcement.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[microsoft]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework microsoft-agent --scenario both
```

**Demo scope:** this command evaluates two fixed inputs with a deterministic,
bundled public baseline. It does not contact AgenticDome, load tenant policy,
execute tools, or instantiate Microsoft Agent Framework. The framework option
is a label and guide selector, not a framework integration test.

Install the Microsoft packages used by your application separately.

## Attach in production

Configure the assigned runtime first:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

Run `agenticdome-demo --framework microsoft-agent --scenario both --live` to
obtain real tenant-engine decisions for those fixed inputs. That checks the
assigned sidecar, not Microsoft Agent Framework attachment; the code below
attaches the adapter to the real application boundary.

For managed service, the API base is assigned in the selected supported
geographic region, subject to availability. A contracted Sovereign runtime is
inside the customer-controlled environment. Normal SDK calls do not require
customer-managed Redis; see [runtime location and Redis responsibilities](../runtime-deployment.md).

Pass the application-owned agent and real tool handler into the assembly
function, then register only the returned secured handler:

```python
from typing import Any, Callable, Tuple

from agenticdome_sdk.microsoft_agent_framework import AgenticDomeMicrosoftAgentFirewall

def secure_agent_and_tool(
    *,
    agent: Any,
    raw_lookup: Callable[..., Any],
) -> Tuple[Any, Callable[..., Any]]:
    firewall = AgenticDomeMicrosoftAgentFirewall()
    secured_agent = firewall.install_on_agent(agent)
    secure_lookup = firewall.wrap_tool_handler(
        tool_name="crm.customer.read",
        tool_platform="crm",
        handler=raw_lookup,
    )
    return secured_agent, secure_lookup
```

Applications that own invocation should call `run_agent_securely(...)`. Use
`create_middleware()` when the selected runtime exposes middleware callbacks,
and `wrap_delegated_tool_handler(...)` for specialist execution.

See the [Microsoft Agent Framework API guide](../../README.md#microsoft-agent-framework)
for complete run, middleware, function-tool, delegation and streaming examples.

## Launch checks

- Middleware is installed in the agent/workflow factory.
- Registered tools call the secured handler, not `raw_lookup`.
- Stable Entra/workload, agent, session, run and trace identity is propagated.
- Hosted/remote tools are gated at the local request and response boundary.
- Delegated execution is separately verified by the specialist.

The adapter does not monkey-patch every Microsoft provider or hosted tool.
