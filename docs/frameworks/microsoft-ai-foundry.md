# Microsoft AI Foundry integration

Use this adapter around the Foundry client/run boundary and every local tool
executor that handles a function call from a hosted agent. Hosted orchestration
does not automatically secure code executing in your application.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[foundry]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework foundry --scenario both
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

Pass the application-owned Foundry client and executor into the assembly
function, then publish only the secured executor to the dispatch table:

```python
from typing import Any, Callable, Tuple

from agenticdome_sdk.microsoft_ai_foundry import AgenticDomeMicrosoftAIFoundryFirewall

def secure_foundry_client(
    *,
    client: Any,
    raw_refund_executor: Callable[..., Any],
) -> Tuple[Any, Callable[..., Any]]:
    firewall = AgenticDomeMicrosoftAIFoundryFirewall()
    secured_client = firewall.install_on_client(client)
    secure_executor = firewall.wrap_tool_executor(
        tool_name="payments.refund.create",
        tool_platform="payments",
        handler=raw_refund_executor,
    )
    return secured_client, secure_executor
```

Call `run_secure(...)` when the application controls the complete run. Register
`secure_executor`, never the raw executor, in the function-call dispatch table.
Foundry bearer-token tool analysis is an optional capability; normal runtime
policy still uses the tenant Runtime/SDK key.

See the [Microsoft AI Foundry API guide](../../README.md#microsoft-ai-foundry)
for payload contracts, middleware, secure runs, local executors, delegation and
streaming patterns.

## Launch checks

- Every client/run path used in production has the middleware or secure wrapper.
- All locally executed Foundry function calls use a secured executor.
- Tenant identity and optional Microsoft bearer credentials are not confused.
- Remote outputs are reviewed before planner reuse or customer delivery.
- The documented Foundry exception is recorded when bearer analysis is omitted.

AgenticDome cannot instrument code running solely inside a hosted provider;
protect the request/response and local execution boundaries you control.
