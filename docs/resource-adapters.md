# Shared action adapters: GraphQL and resource ownership

The sidecar interprets the proposed action and applies centrally governed policy.
A provider adapter checks the authenticated caller's rights against current
resource records immediately before execution. These checks complement each
other: an ownership match never overrides a policy block or an approval hold.

## GraphQL interpretation

The shared runtime uses the pinned `graphql-core` AST parser. Python and
TypeScript send the same prepared HTTP contract; neither has a second parser
with potentially different semantics. The interpreter selects `operationName`,
resolves variables/defaults and inline inputs, expands bounded fragments, handles
`@skip`/`@include`, and uses real field names rather than response aliases.

Only selected, executable root fields are considered actions. Unselected
mutations, comments, string literals and ordinary report prose are not actions.
Queries still pass identity, tool registry, data and destination controls.
Every selected mutation field must match a reviewed grant. All fields must pass
before the request can execute; one approval covers the exact whole request.
Resource limits apply across repeated fields and aliases, and reviewer groups
must satisfy all matching grants. Unknown mutations receive no automatic grant.

The interpreter recognizes GraphQL HTTP envelopes, including GET query parameters
and JSON POST requests. The SDK helpers use JSON POST. Ambiguous operation names,
duplicate arguments, cyclic fragments, conflicting aliases and transport
parameter smuggling are rejected. Documents, inputs and fragment expansion have
explicit byte, token, depth and field limits. Only parsed syntax is cached;
variables, decisions and ownership facts are not cached.

This is an operation interpreter, not a replacement GraphQL server or schema
validator. Provider-specific side effects, custom scalars, implicit resource
defaults and business rules must be handled by reviewed adapters. Resource IDs
used in permissions must be explicit strings. Persisted queries must first be
resolved through a trusted local catalog into the exact document sent. HTTP
batches, subscriptions, multipart uploads and custom directives/extensions are
rejected until an adapter can review and enforce their entire execution contract.
The interpreter does not fetch schemas or persisted documents from request URLs.

## Global permissions and tenant narrowing

SuperSaaSAdmin owns Global Policy. Add `graphql_field` to a normal mutation grant:

```yaml
mutation_permissions:
  - id: staging-volume-review
    enabled: true
    agents: [maintenance-agent]
    tools: [cloud.graphql]
    workloads: ['runtime-key:REVIEWED_KEY_ID']
    principals: ['runtime-key:REVIEWED_KEY_ID']
    registry_assets: [REVIEWED_CLOUD_API_ASSET]
    origins: ['https://cloud.example.com']
    paths: ['/graphql']
    methods: [POST]
    purposes: [staging_maintenance]
    graphql_field: Mutation.volumeDelete
    operation: delete
    resource_argument: volumeId
    resource_ids: [REVIEWED_STAGING_VOLUME_ID]
    max_resources: 1
    mode: approval
    approval_groups: [infrastructure-approvers]
```

`resource_argument` is relative to the actual field arguments, including inline
literals and resolved variables; it is not relative to `body.variables`.
For REST grants it remains relative to the prepared HTTP arguments, e.g. `body.id`.
Aliases never change `graphql_field`. A generic REST grant cannot authorize
GraphQL. Tenant policy can narrow or disable grants but cannot change their field,
operation or argument binding. An explicit grant remains subject to SQL, audit,
data, identity and all other hard controls. Use a separate grant for each field.
The approval drawer shows the reviewed fields and resources without storing raw
GraphQL input values as review evidence.

## Reusable ownership and entitlement resolvers

`OwnershipGuard` is available in both SDKs and works across resource types such as
reservations, customer records, documents and cloud resources. Rules specify an
exact tool, resource type, argument path, operation, relationship and batch limit.
For creation, resolve rights on the parent resource (e.g. project or class).

Two provider-owned callbacks supply authority:

1. `resolve_subject` / `resolveSubject`: obtain tenant and principal from the
   authenticated server request scope. Do not use agent-provided owner/user fields.
2. `resolve_resource` / `resolveResource`: fetch the requested resource in that
   tenant and return its type, ID, owner or explicitly entitled principals, and
   the operations the provider permits. The callback receives a copy of the final
   action arguments so it can apply additional business constraints.

The authenticated subject's tenant must match the configured enforcement tenant.
Every fact must match tenant, type and exact resource ID. Ownership alone is
insufficient without permission for the proposed operation. Unknown tools are
denied by default when a guard is attached. Missing facts, lookup failures,
excessive resource counts, denied operations and changed ownership block dispatch.
The guard never treats request metadata or an agent's assertion as provider facts.

```python
from agenticdome_sdk import AgenticDomeClient, OwnershipGuard, ResourceRule

# server_session and records are your existing authenticated provider interfaces.
def subject():
    return {"tenant_id": server_session.tenant_id,
            "principal_id": server_session.require_principal_id()}

def resource(request):
    row = records.get_in_tenant(request["tenant_id"], request["resource_id"])
    return {"tenant_id": row.tenant_id, "resource_type": "record",
            "resource_id": row.id, "owner_id": row.owner_id,
            "allowed_operations": records.allowed_operations(server_session, row)}

guard = OwnershipGuard({
    "records.cancel": ResourceRule("record", "body.id", "cancel"),
    "records.graphql#Mutation.cancelRecord": ResourceRule("record", "id", "cancel"),
}, resolve_subject=subject, resolve_resource=resource)
client = AgenticDomeClient(ownership_guard=guard)  # Existing API/tenant env settings.
client.execute_graphql(url="https://records.example.com/graphql",
    query="mutation Cancel($id:ID!){cancelRecord(id:$id)}",
    variables={"id": "record-123"}, agent_id="service", tool_name="records.graphql",
    request_purpose="customer_support")
```

```typescript
import AgenticDomeClient, { OwnershipGuard } from 'agenticdome-sdk';

const ownershipGuard = new OwnershipGuard({
  'records.graphql#Mutation.cancelRecord': {
    resourceType: 'record', resourceArgument: 'id', operation: 'cancel',
  },
}, {
  resolveSubject: () => ({ tenantId: serverSession.tenantId,
    principalId: serverSession.requirePrincipalId() }),
  resolveResource: async request => {
    const row = await records.getInTenant(request.tenantId, request.resourceId);
    return { tenantId: row.tenantId, resourceType: 'record', resourceId: row.id,
      ownerId: row.ownerId, allowedOperations: await records.allowedOperations(serverSession, row) };
  },
});
const client = new AgenticDomeClient(process.env.AGENTICDOME_API_BASE, { ownershipGuard });
await client.executeGraphql({url: 'https://records.example.com/graphql',
  query: 'mutation Cancel($id:ID!){cancelRecord(id:$id)}', variables: {id: 'record-123'},
  agentId: 'service', toolName: 'records.graphql', requestPurpose: 'customer_support'});
```

For delegated/shared resources use `relationship='entitled'` / `'entitled'` and
return `entitled_principals` / `entitledPrincipals`. A read entitlement does not
grant cancellation or deletion. Do not enumerate every tenant user; return only
principals whose entitlement the provider has verified for the requested action.

GraphQL ownership uses `tool#Mutation.field` (or `tool#Query.field`) and sidecar
interpreted field arguments. It never trusts an unused variable claiming a
different resource. The helpers refuse legacy runtimes without GraphQL evidence.

Attach the same guard to `AgenticDomeMCPHostFirewall(ownership_guard=guard)` or
`AgenticDomeMCPGateway(..., {ownershipGuard})` for ordinary resource tools. Checks
use final sanitized arguments. Configured ownership checks cannot inherit a
fail-open MCP setting. MCP `resources/read` and `prompts/get` also use the guard:
map `mcp.resources/read` to a `uri` argument rule and `mcp.prompts/get` to a `name`
argument rule. Unmapped reads are denied by default when a guard is attached;
listing capabilities continues through existing policy checks.
Existing opt-in booking callbacks remain compatible;
new integrations should use the generic guard for ownership and retain a trusted
provider check for domain rules such as booking horizons. MCP tools forwarding
arbitrary GraphQL must use the exact HTTP GraphQL helper at the actual provider
boundary; a rule checking a caller-supplied variable is insufficient.

## Execution boundary and recovery

Instantiate adapters in a trusted gateway or provider process, with request-scoped
authentication. Agent-editable application code is not an independent enforcement
boundary. Sidecar policy evidence and provider ownership verification are distinct:
the SDK's callback does not become a signed central ownership assertion.
Provider ownership checks run immediately before HTTP dispatch and run again on
approval resume. No successful lookup is reusable permission. The destination
must still enforce permissions atomically and use version preconditions to close
the interval between lookup and mutation. A grant can be consumed even if the
subsequent provider check fails; request fresh approval after correcting access.

Resolver callbacks must be read-only and bound their own network requests.
Asynchronous lookup waits have a timeout; synchronous Python callbacks must set
provider/network timeouts themselves (late results are rejected). There is no
automatic remote resolver URL, credential forwarding or LLM call. Block alternate
egress and filesystem/shell paths as appropriate to the workload. HTTP enforcement
does not independently prevent local file deletion.

## Release and evidence

Deploy the sidecar image containing `graphql-core` and the updated SDKs through
the existing manifest/package process. GraphQL grant activation checks downstream
readiness for `agenticdome.graphql-actions.v1`. No publication, manifest push,
customer grant or routing change is performed by this source change. Downstream
control planes do not need an SDK Harness page; central release evidence and
runtime readiness remain the deployment gates. Reissue pre-upgrade approvals.

Admin SDK Harness includes paired allowed/denied resource scenarios in both SDKs;
the TypeScript package gate checks ESM and CommonJS. Real runtime tests cover
GraphQL approval, changed request rejection, replay, tenant/resource scope and
preservation of hard blocks. Synthetic facts and transport are explicitly labelled
as SDK contract evidence, not a live customer ownership integration. The isolated
performance benchmark adds cached GraphQL interpretation and synthetic ownership
resolution; these figures exclude real provider lookup/network/human latency.
