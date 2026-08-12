# AWS Bedrock integration

Replace direct application-owned Bedrock Runtime/Agent calls with the matching
secure method. Separately wrap local tool-use handlers, action-group Lambda
handlers and knowledge-base retrieval results.

## Try it without an account

```bash
pip install "agenticdome-python-sdk[bedrock]"
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework bedrock --scenario both
```

## Attach in production

Configure the assigned runtime first:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example.com"
export AGENTICDOME_API_KEY="your-runtime-sdk-key"
export AGENTICDOME_TENANT_ID="your-tenant-id"
```

For managed service, the API base is assigned in the selected supported
geographic region, subject to availability. A contracted Sovereign runtime is
inside the customer-controlled environment. Normal SDK calls do not require
customer-managed Redis; see [runtime location and Redis responsibilities](../runtime-deployment.md).

Create the application-owned boto3 client in your AWS bootstrap, then pass it
and the real request into this async boundary:

```python
from typing import Any, Dict, List

from agenticdome_sdk.aws_bedrock import AgenticDomeAWSBedrockFirewall

async def converse_with_policy(
    *,
    bedrock_runtime_client: Any,
    model_id: str,
    messages: List[Dict[str, Any]],
) -> Any:
    firewall = AgenticDomeAWSBedrockFirewall()
    return await firewall.converse_securely(
        bedrock_runtime_client=bedrock_runtime_client,
        model_id=model_id,
        messages=messages,
        agent_id="support-agent",
        session_id="stable-session-id",
    )
```

Use the corresponding secure methods for streaming, `InvokeModel` and Bedrock
Agents. Use `wrap_tool_handler(...)`, `secure_tool(...)`, and
`wrap_action_group_lambda(...)` at local execution boundaries.

See the [AWS Bedrock API guide](../../README.md#aws-bedrock) for Converse,
InvokeModel, streaming, Agents, action groups, tools, retrieval and handoffs.

## Launch checks

- No production path calls boto3 directly for a protected model operation.
- Local tool-use and action-group handlers are independently authorized.
- Streamed events and final responses are reviewed before delivery.
- AWS principal, account, region and resource identifiers are propagated.
- Retrieved knowledge-base nodes are sanitized before planner reuse.

The SDK protects calls and content at the application boundary; it cannot
instrument execution occurring solely inside AWS-managed services.
