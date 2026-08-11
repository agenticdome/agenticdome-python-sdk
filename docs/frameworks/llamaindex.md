# LlamaIndex integration

Protect both sides of a RAG application: query/tool execution and the retrieved
or synthesized content that is inserted into model context or returned to a
caller.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[llamaindex]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework llamaindex --scenario both
```

## Attach in production

```python
from agenticdome_sdk.llamaindex import AgenticDomeLlamaIndexFirewall

firewall = AgenticDomeLlamaIndexFirewall()
secure_lookup = firewall.to_function_tool(
    lookup_customer,
    tool_name="crm.customer.read",
    tool_platform="crm",
    agent_id="support-agent",
    session_id="stable-session-id",
)

secure_query_engine = firewall.wrap_query_engine(
    query_engine,
    agent_id="support-agent",
    session_id="stable-session-id",
)
```

Also wrap retrievers or install the node postprocessor before retrieved text is
placed into a prompt. Callback handlers add visibility but do not replace hard
tool/query wrappers.

See the [LlamaIndex API guide](../../README.md#llamaindex) for FunctionTool,
query, retrieval, node postprocessor, callback and delegation examples.

## Launch checks

- Every side-effecting FunctionTool is created from a secured callable.
- Query engines invoked directly are wrapped or called through `run_query_securely()`.
- Retrieved nodes are sanitized before model-context assembly.
- Final synthesized output is reviewed before return or storage.
- Callback visibility is not treated as the sole execution control.

Provider-native and remote tools require protection at their local request and
response boundary.
