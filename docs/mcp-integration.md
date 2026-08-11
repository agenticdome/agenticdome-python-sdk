# MCP Host and Gateway Action Firewall

AgenticDome adds application-layer policy checks at the MCP boundary your
application controls: immediately before a host, gateway, proxy, or router
forwards a JSON-RPC request, and immediately after the MCP server returns a
result.

This complements MCP transport authorization. It does not replace OAuth,
user consent, MCP server authentication, operating-system isolation, or an
execution sandbox.

> **Commercial boundary:** the SDK client is Apache-2.0 open source. Live
> tenant policy, signed decisions, telemetry, and runtime enforcement require
> an AgenticDome tenant and assigned runtime sidecar.

## What the integration protects

```text
Human / workload identity
          |
          v
Agent or MCP host
          |
          |  JSON-RPC request
          v
AgenticDomeMCPHostFirewall
  1. screen available human/agent intent
  2. authorize the MCP method, tool and business arguments
  3. verify delegated execution context when supplied
          |
          |  allowed or sanitized request only
          v
Existing MCP transport -> MCP server -> tool
          |
          |  returned content
          v
AgenticDomeMCPHostFirewall
  4. filter discovery results and sanitize/block returned content
          |
          v
Planner, model, transcript or caller
```

The Python adapter currently understands these application-controlled
boundaries:

| MCP operation | Before forwarding | After response |
| --- | --- | --- |
| `tools/call` | Tool, arguments, intent and optional delegation verification | Structured/text result sanitization |
| `tools/list` | Method authorization | Policy-based tool-list filtering |
| `resources/read` | URI and request authorization | Resource-content sanitization |
| `resources/list` | Method authorization | Policy-based resource-list filtering |
| `prompts/get` | Prompt name and arguments authorization | Prompt-content sanitization |
| `prompts/list` | Method authorization | Policy-based prompt-list filtering |
| `sampling/createMessage` | Method and arguments authorization for compatible protocol versions | Result sanitization |
| Streaming results | — | Chunk-by-chunk sanitization where the transport exposes an iterator |

Other protocol messages pass through unchanged. Keep the MCP transport and SDK
versions current, and enforce a protocol-method allowlist at the gateway when
your threat model requires strict rejection of custom or unknown methods.

## Ten-minute, zero-account rehearsal

### 1. Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "agenticdome-python-sdk[mcp]"
```

### 2. Run one safe and one unsafe action

```bash
export AGENTICDOME_MODE=local_sim
agenticdome-demo --framework mcp --scenario both
```

This uses a small bundled demonstration policy. It does not contact
AgenticDome, execute either tool, load customer policy, or produce runtime
assurance evidence.

### 3. Exercise the real gateway interception shape

From a source checkout:

```bash
python examples/mcp_gateway_action_firewall.py
```

The network-free example proves three distinct paths:

- a normal tool request reaches the stand-in MCP transport;
- a remote-execution request is blocked before the transport is called;
- a poisoned tool result is replaced before it can re-enter the planner.

## Connect to live tenant policy

Obtain these values from the AgenticDome activation experience:

- the tenant's assigned **runtime sidecar URL**;
- a tenant-scoped **Runtime / SDK key**;
- the matching **tenant ID**.

Do not use the AgenticDome admin or control-plane website as the API base.

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example"
export AGENTICDOME_API_KEY="your_runtime_sdk_key"
export AGENTICDOME_TENANT_ID="your_tenant_id"
export AGENTICDOME_FAIL_CLOSED="true"
export AGENTICDOME_REQUIRE_SESSION_ID="true"
```

The API key and tenant ID must belong to the same tenant and must already be
replicated to the selected sidecar.

## Wrap the one forwarding boundary

Place the firewall around the function that already transports MCP JSON-RPC.
The example deliberately does not depend on a particular MCP client library or
transport:

```python
from agenticdome_sdk.mcp_host import AgenticDomeMCPHostFirewall

firewall = AgenticDomeMCPHostFirewall()

async def handle_mcp_request(request: dict, request_context: dict) -> dict:
    return await firewall.forward_with_firewall(
        mcp_request=request,
        context={
            "session_id": request_context["session_id"],
            "trace_id": request_context.get("trace_id"),
            "user_id": request_context.get("user_id"),
            "source_agent_id": request_context.get("source_agent_id"),
            "host_id": "enterprise_mcp_gateway",
            "host_app": "agent_workspace",
            "user_prompt": request_context.get("user_prompt", ""),
            "mcp_server_id": request_context["mcp_server_id"],
            "mcp_server_url": request_context.get("mcp_server_url"),
            "mcp_server_vendor": request_context.get("mcp_server_vendor"),
            "mcp_server_trust_level": request_context.get("mcp_server_trust_level"),
        },
        forward_to_third_party=forward_to_mcp_server,
    )
```

Always forward the request returned by AgenticDome. Policy may remove private
delegation metadata or return sanitized business arguments. Do not retain a
second route that calls the raw transport for sensitive MCP operations.

Call `firewall.close()` during application shutdown.

## If your gateway owns response handling

Use `preflight_request()` before the transport and
`sanitize_mcp_result()` before the result is returned, stored, logged, or fed
back to a model:

```python
gated = await firewall.preflight_request(
    mcp_request=request,
    context=context,
)

if "error" in gated:
    return gated

response = await forward_to_mcp_server(gated)
if "result" in response:
    response["result"] = await firewall.sanitize_mcp_result(
        tool_output=response["result"],
        context=context,
    )
return response
```

`forward_with_firewall()` is preferred because it keeps request authorization
and response handling together.

## Identity, lineage and automated workloads

Pass identity that your application has actually authenticated; do not invent
human identity for a scheduled job. Useful context includes:

- stable `session_id`, `run_id` and `trace_id` values;
- originating `user_id` when a human is present;
- `source_agent_id` and target/specialist identifiers for delegation;
- MCP server identity, URL, vendor and trust classification;
- business purpose and the upstream user request, where disclosure is allowed.

For a scheduler, webhook, or service account, pass the authenticated workload
principal and an explicit purpose through your normal policy context. Whether
that workload is allowed is a tenant policy decision. The public SDK does not
silently manufacture a special identity or bypass missing authorization.

Where a manager agent delegates MCP execution to a specialist, use
`authorize_manager_handoff()` before the handoff. The gateway verifies and
consumes the corresponding decision context before forwarding matching tool
arguments. Multi-process deployments should configure Redis for shared,
one-time handoff state.

## MCP OAuth and AgenticDome solve different problems

MCP authorization protects access to an MCP server and defines how an MCP
client obtains and presents tokens. AgenticDome evaluates the requested action:
which authenticated human or workload initiated it, which agent is acting,
which MCP server and tool are targeted, what arguments are proposed, and what
content is returning.

Use both:

1. implement MCP authorization and validate token issuer, audience/resource,
   expiry and scopes;
2. preserve user consent and human confirmation for consequential actions;
3. apply AgenticDome immediately before the application-controlled execution
   boundary;
4. sandbox tools and constrain filesystem, process and network access where
   untrusted code can execute.

See the official MCP documentation for [authorization](https://modelcontextprotocol.io/docs/tutorials/security/authorization),
[security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices),
and [client best practices](https://modelcontextprotocol.io/docs/develop/clients/client-best-practices).

## TypeScript gateway services

Install the TypeScript client when a Node.js gateway owns the tool boundary:

```bash
npm install agenticdome-sdk
```

Use `mcpGuardrailValidate()` immediately before the existing MCP transport,
check the returned JSON-RPC result, and use `meshValidate()` on returned text
before planner reuse. The application remains responsible for making the real
transport call only after an allowed decision. See the
[TypeScript SDK MCP guide](https://github.com/agenticdome/agenticdome-sdk-ts/blob/main/docs/mcp-integration.md)
for a complete example.

## Production configuration

```bash
export AGENTICDOME_PLATFORM="mcp"
export AGENTICDOME_MCP_HOST_ID="enterprise_mcp_gateway"
export AGENTICDOME_MCP_TOOL_PLATFORM="third_party_mcp_server"
export AGENTICDOME_SANITIZE_TOOL_OUTPUT="true"
export AGENTICDOME_SANITIZE_RESOURCE_OUTPUT="true"
export AGENTICDOME_SANITIZE_PROMPT_OUTPUT="true"
export AGENTICDOME_SANITIZE_STREAMING_OUTPUT="true"
export AGENTICDOME_VERIFY_DECISION_TOKENS="true"
export AGENTICDOME_SCREEN_UPSTREAM_PROMPT="true"
export AGENTICDOME_MCP_MAX_OUTPUT_CHARS="100000"
export AGENTICDOME_MCP_MAX_TOOL_ARG_CHARS="20000"
export AGENTICDOME_MCP_RATE_LIMIT_PER_MINUTE="0"

# Recommended when delegation crosses workers or pods:
export AGENTICDOME_REDIS_URL="redis://redis.internal:6379/0"
export AGENTICDOME_REDIS_KEY_PREFIX="AgenticDome:mcp:handoff"
```

Store keys in a secrets manager, never in source control. Use HTTPS for remote
MCP and sidecar traffic, and keep the sidecar close to the protected workload
when the deployment model permits it.

## Prove the integration before launch

1. Run the offline allowed, blocked, and poisoned-result rehearsal.
2. Confirm a blocked test never increments or reaches the real MCP forwarder.
3. Confirm safe live traffic is allowed against the assigned tenant sidecar.
4. Confirm returned secrets/PII are handled according to tenant policy.
5. Test sidecar unavailability with the selected fail-open/fail-closed posture.
6. Verify stable human/workload, agent, session, server and tool attribution in
   runtime evidence.
7. Run SDK Assurance, then Performance Smoke, against the same tenant and
   sidecar before heavier load testing.

## Performance claims

Do not reuse a latency number from another environment. End-to-end latency
depends on network placement, TLS and connection reuse, policy configuration,
payload size, selected controls and sidecar capacity. AgenticDome's performance
harness records the exact target, workload, request mix, error rate and
percentiles so results can be reproduced and dated.

Publish a benchmark only when its report identifies:

- test date and software/release versions;
- sidecar location and client-to-sidecar network path;
- profile duration, concurrency, scheduled/completed requests and request mix;
- p50, p95 and p99 end-to-end latency plus error rate;
- whether the measurement is full request latency or estimated AgenticDome
  overhead;
- the policy and capabilities exercised.

The public SDK does not assign fixed latency bands to particular policy paths
or promise a universal p95 latency or throughput for every deployment.

## Scope and limitations

- The adapter protects only traffic routed through the wrapped boundary.
- It cannot inspect code running inside a third-party MCP server you do not
  control.
- It does not automatically intercept alternate transports or direct tool
  calls that bypass your wrapper.
- Local simulation is not tenant enforcement, certification, or production
  assurance.
- Policy decisions do not replace safe tool design, input validation,
  authorization, human confirmation, isolation, backups, or incident response.

For integration questions, use the
[public issue tracker](https://github.com/agenticdome/agenticdome-python-sdk/issues).
Report suspected vulnerabilities privately as described in
[SECURITY.md](https://github.com/agenticdome/agenticdome-python-sdk/blob/main/SECURITY.md).
