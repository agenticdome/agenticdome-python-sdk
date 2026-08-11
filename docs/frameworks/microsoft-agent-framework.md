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

Install the Microsoft packages used by your application separately.

## Attach in production

```python
from agenticdome_sdk.microsoft_agent_framework import AgenticDomeMicrosoftAgentFirewall

firewall = AgenticDomeMicrosoftAgentFirewall()
agent = firewall.install_on_agent(agent)

secure_lookup = firewall.wrap_tool_handler(
    tool_name="crm.customer.read",
    tool_platform="crm",
    handler=raw_lookup,
)
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
