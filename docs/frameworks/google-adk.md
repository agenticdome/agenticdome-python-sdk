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

```python
from google.adk.agents import LlmAgent
from agenticdome_sdk.google_adk import AgenticDomeGoogleADKFirewall

firewall = AgenticDomeGoogleADKFirewall()
agent = LlmAgent(
    name="support-agent",
    model="gemini-2.5-flash",
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
