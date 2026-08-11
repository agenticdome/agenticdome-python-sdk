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

## Attach in production

```python
from agenticdome_sdk.autogen import AgenticDomeAutoGenFirewall

firewall = AgenticDomeAutoGenFirewall()
secure_team = firewall.wrap_team(
    team,
    session_id="stable-session-id",
    agent_id="operations-team",
)
result = await secure_team.run(task=user_prompt)
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
