# Microsoft AutoGen integration

AgenticDome supports current AgentChat/Core applications and documented legacy
`ConversableAgent` deployments. For new Microsoft projects, evaluate Microsoft
Agent Framework while retaining this integration for existing AutoGen estates.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[autogen]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework autogen --scenario both
```

**Demo scope:** this command evaluates two fixed inputs with a deterministic,
bundled public baseline. It does not contact AgenticDome, load tenant policy,
execute tools, or instantiate AutoGen. The framework option is a label and
guide selector, not an AutoGen integration test.

## Attach in production

Configure the assigned runtime first:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

Run `agenticdome-demo --framework autogen --scenario both --live` to obtain
real tenant-engine decisions for those fixed inputs. That checks the assigned
sidecar, not AutoGen attachment; the code below attaches the adapter to the
real application boundary.

For managed service, the API base is assigned in the selected supported
geographic region, subject to availability. A contracted Sovereign runtime is
inside the customer-controlled environment. Normal SDK calls do not require
customer-managed Redis; see [runtime location and Redis responsibilities](../runtime-deployment.md).

Pass the application-owned team and task into an async boundary rather than
copying a top-level `await` statement:

```python
from typing import Any

from agenticdome_sdk.autogen import AgenticDomeAutoGenFirewall

async def run_secured_team(*, team: Any, user_prompt: str) -> Any:
    firewall = AgenticDomeAutoGenFirewall()
    secure_team = firewall.wrap_team(
        team,
        session_id="stable-session-id",
        agent_id="operations-team",
    )
    return await secure_team.run(task=user_prompt)
```

For AutoGen Core, install `create_intervention_handler(...)` when constructing
the runtime. For legacy deployments, use `attach_conversable_agent(...)` and
the dependency-light base SDK. In every variant, wrap local side-effecting
handlers with `wrap_tool_handler(...)`.

See the [AutoGen API guide](../../README.md#microsoft-autogen) for AgentChat,
Core intervention, termination/freeze, legacy and tool examples.

## Launch checks

- Application code invokes the secured team proxy, not the original team.
- Core runtimes include the intervention handler before startup.
- Session freeze/denial is terminal until an authorized resolution.
- Local tools cannot be reached through an unwrapped registration path.
- The selected AutoGen generation is inside its certified dependency range.

Conversation screening alone does not authorize the eventual tool execution.
