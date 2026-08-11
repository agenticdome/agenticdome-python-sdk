# CrewAI integration

Use this integration when CrewAI owns the agent/crew lifecycle and local tool
execution. AgenticDome screens model input, authorizes tool and delegation
boundaries, and reviews tool/final output routed through the installed hooks.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[crewai]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework crewai --scenario both
```

This prints one allowed and one blocked decision without importing CrewAI,
contacting a sidecar or executing either demonstration tool.

## Attach in production

Configure the assigned runtime sidecar URL, Runtime/SDK key and matching tenant
ID, then import the adapter in application bootstrap **before** constructing
agents or crews:

```python
import agenticdome_sdk.crewai  # registers the process-wide hooks

from crewai import Agent, Crew, Task

# Construct agents, tasks and crews only after the security hooks are loaded.
```

For explicit lifecycle control, instantiate `AgenticDomeCrewAIFirewall` and
call `attach(crew)`. Protect every high-impact local tool with
`@firewall.secure_tool(...)`; register the wrapped callable rather than its raw
implementation. Use the sanitized arguments supplied by the wrapper.

The complete, tested code patterns for scoped attachment, secured tools,
delegation, streaming output and multi-worker state are in the
[CrewAI API guide](../../README.md#crewai).

## Launch checks

- Hooks load before any `Crew` executes.
- A blocked tool never reaches its function body.
- Allowed and sanitized arguments are the values the real function receives.
- Manager-to-specialist execution is verified at the specialist boundary.
- Every worker uses stable session identity; shared delegation uses Redis.
- A sidecar outage produces the deliberately selected fail posture.

AgenticDome cannot protect a raw tool or alternate execution route that bypasses
the hooks/wrapper. Offline simulation is not tenant assurance.
