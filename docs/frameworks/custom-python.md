# Custom Python integration

Use the core client when your application owns the runtime loop: API handlers,
Celery workers, routers, bespoke agents, tool executors or custom gateways.
Make the policy check part of the same function that owns execution.

## Try it without an account

```bash
pip install agenticdome-python-sdk
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework custom-python --scenario both
```

## Attach in production

Configure the assigned runtime first. The executor remains application-owned:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

```python
from typing import Any, Callable, Dict

from agenticdome_sdk import AgentGuardClient

def secured_customer_lookup(
    *,
    customer_id: str,
    execute_customer_lookup: Callable[[str], Any],
) -> Dict[str, Any]:
    client = AgentGuardClient()
    decision = client.guardrail_validate(
        text="Support agent requests a customer lookup.",
        agent_id="support-agent",
        session_id="stable-session-id",
        direction="outbound",
        platform="python",
        tool_name="crm.customer.read",
        tool_args={"customer_id": customer_id},
    )

    if decision.get("verdict") == "BLOCKED":
        raise PermissionError(decision.get("reason", "Action blocked"))

    effective_args = decision.get("sanitized_tool_args") or {"customer_id": customer_id}
    raw_output = execute_customer_lookup(str(effective_args["customer_id"]))
    return client.mesh_validate(
        agent_id="support-agent",
        session_id="stable-session-id",
        direction="output",
        platform="python",
        text=str(raw_output),
    )
```

Use the A2A authorization and verification methods when a manager delegates a
sensitive tool to another agent. For high-impact outbound HTTP execution, use
the documented broker receipt and enforcement headers at the last responsible
moment.

See the [core client API guide](../../README.md#core-sdk-client-custom-runtimes)
for prompt, tool, A2A, DLP, incident and brokered-execution examples.

## Launch checks

- The real function is unreachable before an allowed decision.
- Sanitized arguments/text replace originals when returned.
- Output is reviewed before return, storage, logging or planner reuse.
- Delegation authorization is verified at the target execution boundary.
- Fail-closed behavior is tested against an unavailable sidecar.

A check performed in an unrelated helper does not protect another raw executor
path. Keep the decision and execution boundary structurally adjacent.
