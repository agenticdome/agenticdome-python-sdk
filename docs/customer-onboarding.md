# Customer onboarding: a simple path from code to protected runtime

Start in **Customer Control Panel → Activate Action Firewall → Core
Config**. Core Config confirms the common foundation—subscription, assigned
runtime and Runtime/SDK key—then asks which outcomes you want:

- **Developer Integration** for Python, TypeScript, MCP, agent-framework or
  custom application code;
- **Microsoft Discovery Scan** for Microsoft estate discovery; and/or
- **Copilot Studio External Protection** for Microsoft's external runtime
  protection path.

The Microsoft paths are optional and independent. Developer Integration is
required only for workloads where you need to attach the AgenticDome SDK or
middleware to code you control.

The Integration Assistant deliberately separates customer source code,
customer tenant configuration and AgenticDome runtime operations. No single
screen or operator silently controls all three.

## Ownership

| Surface | Owner | What belongs there |
|---|---|---|
| Customer repository and CI | Customer developer | Local source parsing, framework discovery, source-free IR generation, generated patch review and application tests. Source is not uploaded by the CLI. |
| Customer Control Panel | Customer tenant administrator | Core Config pathway choice, business purpose, sensitive-tool inventory, managed-region or sovereign request, secret-free inspection evidence and tenant-scoped runtime verification. |
| AgenticDome Admin | AgenticDome platform operator | Managed sidecar allocation, sovereign provisioning coordination, configuration propagation, fleet health and operational exceptions. |
| SDK Harness | AgenticDome release operator | Full SDK/framework release certification and package publication. This is not exposed as a customer deployment control. |
| Assigned sidecar and private Copilot Core | AgenticDome security boundary | Tenant/scoped-key proof, rate limiting, signed hook-catalog binding, private flow/dominance/bypass reasoning and signed-plan verification. The reasoning code is not shipped in the public SDK or sidecar image. |

Customers cannot change tenant-to-sidecar assignments from onboarding. An
AgenticDome operator fulfils a managed-region request in Runtime Sidecars. For
a sovereign deployment, the customer infrastructure team supplies the agreed
customer environment and AgenticDome records and verifies the provisioned
runtime before activation.

## What is required

For a Developer Integration:

1. **Required — initialise locally.** Discover frameworks and likely prompt,
   tool, delegation, retrieval and output boundaries without uploading source.
2. **Required — confirm workload intent.** Record business purpose, sensitive
   actions and deployment preference in the Customer Control Panel.
3. **Optional helper — generate a scaffold.** Review a suggested patch, or use
   the framework guide and integrate manually.
4. **Required — verify before production.** Recheck coverage, run application
   tests, import the evidence and prove exact tenant/runtime binding.

The same discovery logic feeds planning, the optional scaffold and final
verification. It does not silently apply code changes.

The thin local Integration Assistant collects generic structure and renders a
reviewable scaffold. Authenticated `plan` sends only source-free structural IR
through the assigned sidecar to the private Integration Copilot Core, which
performs the protected flow and placement reasoning. `verify` is the required
evidence gate rather than a code generator. The Customer Control Panel explains
and records the journey; it does not inspect the repository.

## Step 1: start the local Integration Assistant

Run these commands from the root of **one deployable workload**:

```bash
cd /path/to/one-deployable-agent-workload
python -m pip install agenticdome-python-sdk
agenticdome init
agenticdome inspect --output agenticdome-inspection.json
agenticdome verify --run-tests --output .agenticdome/verification.json
```

Upload `agenticdome-inspection.json` in Step 1 of the Control Panel. The JSON
printed to the terminal by `agenticdome init` and the local
`.agenticdome/config.json` are not upload evidence.

The workload root is the directory built, tested and deployed as one
application. It normally contains that service's `pyproject.toml`,
`requirements.txt`, `package.json` or `Dockerfile`. In a monorepo, run the
assistant separately inside each independently deployed agent service; do not
scan the top-level monorepo unless it genuinely represents one deployment.
Each workload keeps its own `.agenticdome` evidence beside its own CI tests.

`agenticdome init` creates `.agenticdome/config.json` and
`.agenticdome/inspection.json`. The scanner:

- reads supported Python and TypeScript/JavaScript project files locally;
- excludes `.env` and secret- or credential-named files;
- reports relative file paths, line numbers and candidate boundary categories;
- never includes source snippets, environment values or absolute paths; and
- marks the output with `source_upload: false` and an integrity digest.

Importing `agenticdome-inspection.json` automatically adds detected frameworks to the
Control Panel workload. It does not overwrite business purpose, sensitive
actions or deployment choice: those are organisational decisions that source
inspection cannot determine reliably.

The offline verification uses fixed allowed and blocked examples and runs
detected `pytest` and `npm test` suites when `--run-tests` is supplied. Test
output and source are not placed in the evidence JSON. The fixed decisions do
not instantiate the selected framework; the application tests remain the
evidence for the customer's actual attachment points.

## Step 2: confirm the workload

In **Customer Control Panel → Activate Action Firewall → Developer
Integration**, the tenant administrator records:

- every agent framework in the workload;
- the business purpose;
- sensitive tools and state-changing actions; and
- either a managed geographic preference or a sovereign/customer-hosted
  deployment request.

Managed customers normally receive an appropriate regional sidecar as part of
tenant provisioning. The customer does not deploy or reassign that managed
sidecar. If assignment is pending, it is an AgenticDome operational task. For
a sovereign deployment, provisioning is coordinated inside the customer's
agreed environment.

The Control Panel returns the assigned API base when provisioning is complete.
Runtime/SDK API keys remain in the key-management path and secret managers;
they are never included in the downloadable onboarding configuration.

## Step 3: obtain a private plan and optionally generate a reviewable scaffold

```bash
python -m pip install --upgrade agenticdome-python-sdk
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example"
export AGENTICDOME_TENANT_ID="your_tenant_id"
export AGENTICDOME_COPILOT_API_KEY="your_dedicated_copilot_key"
agenticdome plan
agenticdome scaffold
git apply --stat .agenticdome/scaffold/agenticdome.patch
```

Create the dedicated Integration Copilot key from the tenant API Keys page.
It has a single purpose and is rejected by ordinary sidecar runtime APIs.
The local collector sends only relative structural metadata through the
assigned sidecar. The sidecar proves tenant and key scope, rate-limits the
request, supplies its signed SDK Harness catalog, and verifies the private
Core's signed response. The CLI rejects a catalog digest that differs from its
installed SDK and binds cached results to the tenant, sidecar origin and IR.

Scaffolding is an optional accelerator. It writes `integration-plan.json`, a review README, a secret-free
environment example, Python and/or TypeScript wrapper code, and
`agenticdome.patch` under `.agenticdome/scaffold`. The patch represents those
review files; it does not edit application source. Copy or adapt the wrapper at
the real prompt ingress, final tool executor, receiving delegation boundary,
retrieval boundary and output/stream egress appropriate to the framework.

The separate Control Panel download, `agenticdome-onboarding.json`, is a tenant
connection reference. It contains confirmed Step 2 choices, tenant ID,
assigned API base and environment-variable names. It contains no key, source
or executable patch and is not consumed automatically by the CLI. Store the
real Runtime/SDK key separately in an environment variable or secret manager.

Import `.agenticdome/inspection.json` and the generated
`.agenticdome/verification.json` into Developer Integration. These contain
bounded metadata and pass/fail evidence only; they do not upload the
repository, include test output or apply the patch.

## Step 4: verify before production

Verification has four distinct evidence classes:

1. Static discovery finds the required prompt, tool and output categories.
2. Customer application tests exercise the real framework attachment points.
3. Customer tenant verification proves the hidden managed Runtime/SDK key is
   bound to the exact tenant and checks fixed allowed/blocked decisions on the
   assigned sidecar without executing either tool.
4. AgenticDome Admin confirms allocation, configuration synchronisation and
   runtime readiness. A sovereign operator also provides the agreed
   customer-environment evidence.

The local command consumes the workload's configuration, a fresh static scan
and any detected `pytest`/`npm test` suite. It writes
`.agenticdome/verification.json` with fixed decision outcomes, boundary gaps,
test runner exit status, readiness and a digest; source and test output are not
included. After that file is imported, the Control Panel calls
`/tools/mesh/topology` and `/tools/guardrail/validate` on the assigned sidecar
to prove exact tenant binding and one allowed/redacted plus one blocked result.
It does not execute a customer tool or instantiate the selected framework.

This onboarding gate does **not** depend on the central AgenticDome Workforce
sandbox. Local tests run on the customer machine or CI, and tenant proof calls
the sidecar assigned by the current control plane. The same flow works on a
regional control plane once the onboarding release and migration are deployed,
the sidecar is reachable, a tenant Runtime/SDK key exists and desired/applied
runtime configuration matches. Sovereign tenants use the recorded
customer-hosted endpoint after provisioning is ready.

For a developer-side live check after credentials have been placed in the
customer secret manager:

```bash
unset AGENTICDOME_MODE
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example"
export AGENTICDOME_API_KEY="your_runtime_sdk_key"
export AGENTICDOME_TENANT_ID="your_tenant_id"
agenticdome verify --live
```

`agenticdome verify --live` uses fixed policy payloads. It complements—rather
than replaces—the customer application's own test suite and the platform's
full release certification.
