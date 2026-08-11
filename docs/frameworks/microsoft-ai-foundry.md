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

```python
from agenticdome_sdk.microsoft_ai_foundry import AgenticDomeMicrosoftAIFoundryFirewall

firewall = AgenticDomeMicrosoftAIFoundryFirewall()
client = firewall.install_on_client(client)

secure_executor = firewall.wrap_tool_executor(
    tool_name="payments.refund.create",
    tool_platform="payments",
    handler=raw_refund_executor,
)
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
