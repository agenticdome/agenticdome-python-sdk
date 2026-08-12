# PydanticAI integration

Use this integration where PydanticAI `Agent` objects and their tools are
constructed. Install lifecycle hooks for prompt/output coverage and retain a
secured wrapper on every tool that can read data or cause a side effect.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[pydanticai]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework pydanticai --scenario both
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

Pass the application-owned agent and CRM coroutine into the same factory that
registers tools; no undeclared globals are required:

```python
from typing import Any, Awaitable, Callable

from agenticdome_sdk.pydantic import CyberSecFirewall

def attach_secured_tools(
    *,
    agent: Any,
    crm_lookup: Callable[[str], Awaitable[Any]],
) -> CyberSecFirewall:
    firewall = CyberSecFirewall()
    firewall.install_native_hooks(agent)

    @agent.tool
    @firewall.secure_tool(
        tool_name="crm.customer.read",
        tool_platform="crm",
    )
    async def read_customer(ctx: Any, customer_id: str) -> Any:
        return await crm_lookup(customer_id)

    return firewall
```

Create the firewall after configuring the assigned sidecar URL, Runtime/SDK
key and tenant ID. Install hooks on every agent instance; one agent's hooks do
not cover another. `attach_to_agent()` remains the compatibility path for
supported legacy lifecycle APIs. Register the decorated function and never a
saved reference to the undecorated implementation.

See the [PydanticAI API guide](../../README.md#pydanticai) for `FirewallConfig`,
native capabilities, schema validation, delegation, structured output and
streaming examples.

## Launch checks

- Hooks are installed in the agent factory, not only in a request handler.
- Sensitive tools remain decorated even when lifecycle APIs change.
- Sanitized arguments replace the model-provided arguments before execution.
- Output policy is applied before results are returned or streamed.
- Stable session identity and multi-worker state are configured where needed.

Environment variables configure this adapter but do not attach it. Remote
provider tools remain protectable only at the local request/response boundary.
