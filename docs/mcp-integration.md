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

## Supported external MCP package range

The `agenticdome-python-sdk[mcp]` extra currently installs
`mcp>=1.26.0,<=1.28.1`. This is the certified range of the external PyPI `mcp`
package; it is not the AgenticDome SDK version. MCP 2.0 removed the certified
`mcp.server.fastmcp` import surface, while CrewAI 1.15.5 declares
`mcp~=1.28.1` for combined installations. The upper bound therefore remains
intentional until isolated MCP 2.x certification passes native imports,
AgenticDome adapter checks, the preserved 1.x floor, and package release gates.

The firewall accepts plain JSON-RPC dictionaries and does not need external MCP
types at runtime. A project may install the dependency-light base SDK beside a
separately managed transport, but that does not create a formal AgenticDome MCP
2.x support claim.

## Why use AgenticDome for MCP

MCP standardizes how applications expose tools, resources, prompts, and
sampling operations. Transport authentication and OAuth can establish who may
connect to a server. They do not, by themselves, decide whether this agent,
acting for this human or workload, should perform this specific action with
these arguments—or whether returned content is safe to place back into the
agent loop.

AgenticDome adds that application-layer decision at a forwarding boundary the
customer controls:

| Team | Common requirement | What AgenticDome contributes |
| --- | --- | --- |
| Enterprise platform | Govern internal and external MCP servers consistently | One wrapper for the supported MCP operations, carrying tenant, human/workload, agent, session, server, tool, purpose, and argument context to live policy |
| MCP server or connector vendor | Give enterprise reviewers a concrete integration and evidence path | An optional host/gateway integration pattern that can demonstrate pre-forward authorization and post-response review without claiming to replace the vendor's own authorization, validation, logging, or secure design |
| Central gateway team | Apply policy and collect evidence at a shared routing point | Method-specific decisions, discovery filtering, internal delegation-field removal from forwarded tool arguments, response sanitization, and consistent runtime telemetry for traffic routed through the wrapper |

This is valuable in several MCP-specific failure modes:

- **Poisoned tool or resource results:** supported results can be sanitized or
  blocked before planner reuse.
- **Misleading discovery:** `tools/list`, `resources/list`, and `prompts/list`
  results can be filtered according to tenant policy.
- **Delegated tool misuse:** a manager handoff can be authorized, bound to the
  tenant, session, target agent, tool, and argument fingerprint, then verified
  and consumed at the specialist boundary.
- **Sensitive resource or sampling paths:** `resources/read`, `prompts/get`,
  and `sampling/createMessage` receive their own method-level policy decisions
  and configured result review.
- **Framework fragmentation:** the MCP adapter uses the same tenant runtime
  policy and evidence model as the other supported AgenticDome Python
  integrations.

The guarantee is structural, not automatic: only requests routed through the
wrapped forwarding function are protected. AgenticDome does not certify an MCP
vendor, transfer legal liability, discover every unregistered server by
itself, or replace MCP authorization, user consent, secure tool design, and
workload isolation.

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

This uses two fixed inputs and a deterministic bundled public baseline. It does
not contact AgenticDome, execute either tool, load customer policy, instantiate
an MCP client/server, or produce runtime-assurance evidence. The `mcp`
framework option labels the demo payload and selects this guide; it is not an
MCP integration test. Add `--live` after configuring the assigned sidecar to
obtain real tenant-engine decisions for the same fixed inputs, then test the
host/gateway integration below on the application's actual forwarding path.

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
arguments. Redis is not required for normal MCP authorization or output review.
Configure customer-managed Redis only when this one-time handoff state must
cross application processes, workers, or pods. See
[Runtime location and Redis responsibilities](runtime-deployment.md).

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

## Sessions, stateless servers and application context

MCP Streamable HTTP does not force one universal state model. A server **may**
assign an `MCP-Session-Id` during initialization; if it does, the client must
handle that protocol session as specified. A server can also be implemented
without assigning a protocol session when its design does not require one.

Neither choice removes the need for action context:

- an MCP session secures and relates protocol interactions, but is not by
  itself a business authorization for every tool call;
- a stateless MCP server can scale without sticky application state, but an
  isolated request can still be one step in a larger delegated, exfiltration,
  loop, or resource-exhaustion sequence;
- pass stable application `session_id`, `run_id`, `trace_id`, human/workload,
  and agent identifiers whenever the tenant policy or behavioural controls
  need to correlate activity.

Normal AgenticDome prompt, MCP, tool, and output decisions do **not** require
the customer application to operate Redis. The assigned runtime sidecar owns
its runtime infrastructure. Customer-managed Redis is optional only for the
SDK's one-time delegation state when authorization and consumption occur in
different customer processes, workers, or pods.

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

# Optional: only when delegation state must cross processes, workers or pods.
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
   Request/preflight failures follow `AGENTICDOME_FAIL_CLOSED`. The current
   `forward_with_firewall()` convenience path returns the original response
   after an unexpected non-policy result-review error, so applications that
   require fail-closed output handling must catch and block that path explicitly.
6. Verify stable human/workload, agent, session, server and tool attribution in
   runtime evidence.
7. Run SDK Assurance, then Performance Smoke, against the same tenant and
   sidecar before heavier load testing.

## Performance validation

Latency depends on the deployed sidecar, network path, policy and workload.
Run Performance Smoke against the same tenant and sidecar used for assurance;
publish only the dated report produced for that environment. See the shared
[performance evidence guide](performance-evidence.md) for the benchmark fields
and interpretation rules.

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

## Architecture reading

- [MCP security is necessary; action governance is the next layer](https://www.agenticdome.io/research/mcp-protocol-security-action-governance)
- [MCP connects agents to tools; AgenticDome governs the action](https://www.agenticdome.io/research/mcp-action-governance)
- [Copilot Studio, MCP, and the pre-tool action decision](https://www.agenticdome.io/research/copilot-studio-mcp-action-governance)

For integration questions, use the
[public issue tracker](https://github.com/agenticdome/agenticdome-python-sdk/issues).
Report suspected vulnerabilities privately as described in
[SECURITY.md](https://github.com/agenticdome/agenticdome-python-sdk/blob/main/SECURITY.md).
