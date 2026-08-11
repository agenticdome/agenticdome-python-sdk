# Google ADK integration

Register AgenticDome callbacks when constructing each `LlmAgent`, attach them to
an existing agent, or register the plugin helper centrally. Explicitly secure
local tools that can cause a side effect.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[google-adk]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework google-adk --scenario both
```

## Attach in production

Configure the assigned runtime first:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

Pass the application-owned model into the same factory that constructs every
protected ADK agent:

```python
from typing import Any

from google.adk.agents import LlmAgent
from agenticdome_sdk.google_adk import AgenticDomeGoogleADKFirewall

def build_secured_agent(*, model: Any) -> LlmAgent:
    firewall = AgenticDomeGoogleADKFirewall()
    return LlmAgent(
        name="support-agent",
        model=model,
        instruction="Help support users safely.",
        **firewall.build_callback_kwargs(),
    )
```

Use `install_on_agent(...)` for an existing agent, `create_plugin()` for
central registration and `wrap_tool_handler(...)`/`secure_tool(...)` for local
tools. Prefer async callbacks in async ADK runtimes.

See the [Google ADK API guide](../../README.md#google-adk) for callbacks,
plugins, tools, handoffs, schema validation and streaming examples.

## Launch checks

- Every production agent receives callbacks from the central factory.
- Tool handlers use sanitized arguments before local execution.
- Stable ADK session/run/trace identifiers are available to every callback.
- Google Cloud principal and project context is passed when authenticated.
- Delegation across workers uses shared, one-time verification state.

Configuration alone does not register ADK callbacks, and remote tools remain
outside the local process boundary.
