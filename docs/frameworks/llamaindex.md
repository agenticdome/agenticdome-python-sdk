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

Configure the assigned runtime first:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

Pass the application-owned lookup function and query engine into the assembly
function instead of relying on undeclared example globals:

```python
from typing import Any, Callable, Tuple

from agenticdome_sdk.llamaindex import AgenticDomeLlamaIndexFirewall

def build_secured_rag(
    *,
    lookup_customer: Callable[..., Any],
    query_engine: Any,
) -> Tuple[Any, Any]:
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
    return secure_lookup, secure_query_engine
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
