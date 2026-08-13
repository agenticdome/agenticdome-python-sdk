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

**Demo scope:** this command evaluates two fixed inputs with a deterministic,
bundled public baseline. It does not contact AgenticDome, load tenant policy,
execute tools, or instantiate CrewAI. The framework option is a label and guide
selector, not a CrewAI integration test.

## Attach in production

Configure the assigned runtime sidecar URL, Runtime/SDK key and matching tenant
ID, and make sure simulation is not inherited by the production process:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

Run `agenticdome-demo --framework crewai --scenario both --live` to obtain real
tenant-engine decisions for those fixed inputs. That checks the assigned
sidecar, not CrewAI attachment; the code below attaches the adapter to the real
application boundary.

For managed service, the API base is assigned in the selected supported
geographic region, subject to availability. A contracted Sovereign runtime is
inside the customer-controlled environment. Normal SDK calls do not require
customer-managed Redis; see [runtime location and Redis responsibilities](../runtime-deployment.md).

Then import the adapter in application bootstrap **before** constructing the
application-owned agents or crews:

```python
import agenticdome_sdk.crewai  # registers the process-wide hooks

from crewai import Crew

def build_secured_crew(*, agents: list, tasks: list) -> Crew:
    # Agents and tasks are constructed by the application after hooks load.
    return Crew(agents=agents, tasks=tasks)
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
- Every worker uses stable session identity; configure Redis only if delegation
  state must cross application processes, workers, or pods.
- A sidecar outage produces the deliberately selected fail posture.

AgenticDome cannot protect a raw tool or alternate execution route that bypasses
the hooks/wrapper. Offline simulation is not tenant assurance.
