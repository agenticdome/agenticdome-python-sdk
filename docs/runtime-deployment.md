# Runtime location and Redis responsibilities

The AgenticDome SDK runs inside your application, but live policy decisions are
made by the runtime sidecar assigned to your tenant. Use that sidecar's HTTPS
origin as `AGENTICDOME_API_BASE`; do not use the management-console or
control-plane website URL.

## Where the assigned sidecar runs

The deployment model is agreed during onboarding:

- **Managed regional service:** AgenticDome assigns a managed sidecar in the
  selected supported geographic region, subject to service availability and
  the customer's plan or contract.
- **Sovereign deployment:** the AgenticDome runtime is deployed within the
  contracted customer-controlled boundary, such as a dedicated VPC, the
  customer's cloud environment, or on-premises infrastructure.

The SDK does not select a region or move a runtime. It connects only to the API
base supplied for the tenant. Geographic or sovereign placement describes the
AgenticDome enforcement runtime; customers must separately assess the location
and data handling of their models, tools, identity providers, logs, and other
downstream services.

## Do SDK customers need Redis?

**No—not for normal prompt, tool, MCP, output, or other live policy checks.**

- A customer using an AgenticDome-managed sidecar installs the SDK and uses the
  assigned API base. AgenticDome operates the sidecar's backing services.
- A Sovereign deployment includes its runtime infrastructure as defined by the
  deployment agreement. The customer or its nominated operator manages that
  infrastructure; application developers do not add Redis merely to call the
  SDK.
- Python SDK adapters use an in-process token store by default. Customer-managed
  Redis is optional only when manager-to-specialist delegation is authorised in
  one application process, worker, or pod and the one-time handoff state must be
  consumed in another.

If that cross-process delegation pattern applies, install the Redis extra and
point it to a Redis service operated for the customer application:

```bash
pip install "agenticdome-python-sdk[redis]"
export AGENTICDOME_REDIS_URL="redis://redis.internal:6379/0"
export AGENTICDOME_REDIS_KEY_PREFIX="AgenticDome:runtime:handoff"
```

Use a secret manager for `AGENTICDOME_TOKEN_HMAC_SECRET`. Do not expose the
Redis endpoint publicly, and do not confuse this optional application token
store with the infrastructure behind an assigned AgenticDome sidecar.
