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

For a Developer Integration using the AgenticDome Onboarding Pilot:

1. **Required — initialise locally.** Discover frameworks and likely prompt,
   tool, delegation, retrieval and output boundaries without uploading source.
2. **Required — confirm workload intent.** Record business purpose, sensitive
   actions and deployment preference in the Customer Control Panel.
3. **Required signed Copilot preview; optional guided apply.** Run
   `agenticdome integrate preview` with the tenant-bound Copilot key. Review
   the exact local diff and manual-review items. Apply only a supported,
   approved edit; attach all other boundaries manually.
4. **Required — verify before production.** Recheck coverage, run application
   tests, import the evidence and prove exact tenant/runtime binding.

The same discovery logic feeds the guided preview, optional advanced scaffold
and final verification. It does not silently apply code changes.

### Already integrated with your coding assistant?

The alternative AI Instruction path does not require repeating `init`,
`integrate preview` or guided apply. From the root of the one deployable
application workload, create and review the canonical
`AgenticDome_Integration.md` with all eight interception categories and an
explicit `Workload scope:`. Import it under Onboarding > Discover. Its counts
are displayed as **AI-reported**, not independently verified. Then set the
assigned `AGENTICDOME_API_BASE`, `AGENTICDOME_TENANT_ID` and dedicated
`AGENTICDOME_COPILOT_API_KEY` in your local shell and run:

```bash
agenticdome validate-report --report AgenticDome_Integration.md
```

This does not edit the application. It checks current source-free structure,
requests the tenant-bound semantic assessment and runs detected workload tests.
Import both generated files, `agenticdome-inspection.json` and
`.agenticdome/verification.json`, together in the same onboarding workload.
Their hashes bind them to the exact Markdown report. A changed report requires
rerunning validation. The portal then performs its separate assigned-runtime
check; test the actual customer action path before activation. MCP and
OpenClaw workloads use their specialist onboarding journeys rather than this
application shortcut. The validation command cannot turn an AI report or a
fixed synthetic decision into proof that real customer traffic is intercepted.

The local Integration Assistant collects source-free structure and prepares a
reviewable local diff. Guided `integrate preview` obtains a signed, tenant-bound
plan through the assigned sidecar; only source-free structural IR reaches the
private Integration Copilot Core. `verify` is the required evidence gate rather
than a code generator. The Customer Control Panel explains and records the
journey; it does not inspect the repository.

## Step 1: start the local Integration Assistant

Run these commands from the root of **one deployable workload**:

```bash
cd /path/to/one-deployable-agent-workload
python -m pip install --upgrade agenticdome-python-sdk
agenticdome init
agenticdome inspect --output agenticdome-inspection.json
```

Keep this initial inspection local and continue to the tenant-bound plan below.
Upload the refreshed `agenticdome-inspection.json` produced after that plan.
The JSON printed to the terminal by `agenticdome init` and the local
`.agenticdome/config.json` are not upload evidence.

The workload root is the directory built, tested and deployed as one
application. It normally contains that service's `pyproject.toml`,
`requirements.txt`, `package.json` or `Dockerfile`. In a monorepo, run the
assistant separately inside each independently deployed agent service; do not
scan the top-level monorepo unless it genuinely represents one deployment.
Each workload keeps its own `.agenticdome` evidence beside its own CI tests.
Run verification only after Step 3 has produced a tenant-bound, catalog-checked
Integration Copilot plan and the application attachment tests exist.

For large repositories, choose the deployable subdirectory with `--path` or
run the commands from that subdirectory. The local scan skips known generated
caches and dependency folders, including `.harness_runtime_ts`, `node_modules`
and virtual environments. The inspection records a scope fingerprint and
whether the selected scope was fully collected. If the file or symbol limit is
reached, planning stops and asks you to narrow the workload; unexamined code
is never labelled protected. The exported inspection is compact: the full
source-free call graph stays local rather than being included in portal upload
evidence. For a large but complete structural graph, the SDK analyzes bounded
parts sequentially through the assigned sidecar. Completed parts are cached
locally and reused on retry, so a later failure does not restart the entire
analysis. Each part receives tenant-bound private analysis; the SDK merges the
results and inventories resolvable calls between parts. This does not prove
cross-part guard coverage, and the portal requires a documented review of
those paths and workload-specific tests before marking a split workload ready.
Source text is not uploaded. A plan remains a static proposal, not proof that
a customer action is intercepted. A single source file over 2 MB or a scope
that exceeds the collection limits remains an explicit gap; do not exclude a
required agent path merely to pass onboarding.

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

## Step 3: preview, review and approve integration changes

```bash
python -m pip install --upgrade agenticdome-python-sdk
export AGENTICDOME_API_BASE="https://your-assigned-sidecar.example"
export AGENTICDOME_TENANT_ID="your_tenant_id"
export AGENTICDOME_COPILOT_API_KEY="your_dedicated_copilot_key"
agenticdome integrate preview
# Review .agenticdome/scaffold/guided-integration.patch and
# .agenticdome/scaffold/proposed/AGENTICDOME-CHANGES.md
agenticdome integrate status
# Only after reviewing a supported proposed edit: agenticdome integrate apply
agenticdome inspect --output agenticdome-inspection.json
agenticdome verify --run-tests --output .agenticdome/verification.json
```

Create the dedicated Integration Copilot key from the tenant API Keys page.
It has a single purpose and is rejected by ordinary sidecar runtime APIs.
The local collector sends only relative structural metadata through the
assigned sidecar. The sidecar proves tenant and key scope, rate-limits the
request, supplies its signed SDK Harness catalog, and verifies the private
Core's signed response. The CLI rejects a catalog digest that differs from its
installed SDK and binds cached results to the tenant, sidecar origin and IR.

The tenant-bound plan is required for certified verification. Guided preview
writes the detected application/MCP path and any existing Python SDK call-site
candidates into its local summary. On mixed workloads it defaults to the
application path and points to `--target mcp` for a separate MCP-forwarder
review; an OpenClaw-only workload uses `agenticdome openclaw protect` instead.
Repeating `agenticdome init` keeps the existing config and prior inspection,
but reports current local detections rather than saying it created a new
configuration. `integrate preview` rescans the selected workload and includes
newly detected frameworks in the current hook plan without silently editing
that config; it also flags configured frameworks with no current scan evidence.
`integrate status` shows the saved recommended next path, and a fresh `inspect`
exports that path for the tenant onboarding page. A manually written SDK call is a candidate hook, not proof that
all action paths are guarded; the CLI does not overwrite a file where it finds
one of these hooks. Review the listed paths and semantic gaps, then test the
actual executor with allowed and blocked cases.

It also writes an exact local diff, file-by-file before/after hashes and manual-review
list under `.agenticdome/scaffold`; it does not edit application source or
send source to Copilot. Apply asks for the displayed approval code and requires
a Git working tree with no tracked workload changes. It creates a local review
branch, checks the source hashes again and edits only a catalog-qualified,
unambiguous attachment pattern: CrewAI bootstrap, PydanticAI `Agent(...)`,
LangChain `create_agent(...)`, Google ADK agent construction, Claude options,
Agno `Agent(...)`, direct LlamaIndex `FunctionTool.from_defaults(...)`, direct
OpenAI Agents `FunctionTool(...)` handlers, explicit custom-Python tool
dispatchers, or smolagents `agent.run(task)`
with an explicit `session_id`. It skips
ambiguous and already handwritten integration paths. Unrelated
tracked source edits must be committed or stashed first; preview-generated
`.agenticdome` artifacts do not count as a source conflict. It also
adds reviewed, secret-free integration files. The CLI does not commit, push
or deploy. For other frameworks or indirect paths, attach protection manually
at the real prompt ingress, final tool executor, receiving delegation,
retrieval and output/stream egress boundaries. If no safe existing-source edit
is found for an application target, apply refuses rather than presenting
generated files as protection. The explicit MCP target below can add review
files, but does not claim an existing forwarder was protected.
Before making later edits, `agenticdome integrate undo` can restore only the
unchanged files it applied; it refuses to overwrite subsequent customer work.
If you preview the workload again after an approved edit, the CLI archives the
earlier local record and preserves its backup. Use
`agenticdome integrate undo --revision <earlier-approval-code>` to target that
older revision; a newer edit touching the same file must be reviewed and
undone first.
The older `agenticdome plan` and `agenticdome scaffold` commands remain as
advanced, unapplied review-only options.

| Workload path | Current guided result |
| --- | --- |
| Bespoke Python tool dispatcher with explicit `tool_name`, `tool_args`, trusted `agent_id` and `session_id` | Exact decorator proposal; sync and async handlers supported. It gates that function only. |
| CrewAI, PydanticAI, LangChain `create_agent`, Google ADK, Claude, Agno, direct LlamaIndex `FunctionTool`, direct OpenAI Agents `FunctionTool`, exact smolagents run | Exact edit only where the local AST and signed catalog agree. Other paths in the same workload still need review. |
| Microsoft Agent Framework, AutoGen, Microsoft AI Foundry, AWS Bedrock | Framework-specific hook plan, but no generic source rewrite: registration and tool-executor contracts depend on the customer's wiring. |
| Python MCP hosts/gateways, TypeScript MCP, generic TypeScript | Review files and protocol-specific steps; the customer must route the actual forwarder or handler through the boundary. |
| OpenClaw | Use the native plugin installation, consent and runtime verification path, not a Python source edit. |

This table describes onboarding automation, **not** total SDK protocol support or
production protection. No static edit can certify that all raw tool routes,
delegation receivers, outputs and customer permissions are guarded.

### Prove one real action path

Use a safe test fixture, never a real payment, deletion, or production tool.
Install `ExecutionSpy` around the actual business handler **in your test
setup**, and invoke the normal application route. For example, if your app
allows its refund handler to be injected in a test:

```python
from agenticdome_sdk.action_path_proof import ExecutionSpy

def test_blocked_refund_reaches_firewall(app_factory, test_client):
    spy = ExecutionSpy("billing.refund")
    app = app_factory(refund_handler=spy.wrap(lambda **kwargs: None))
    response = test_client(app).post("/refund", json={"order_id": "fixture-only"})
    assert response.status_code == 403  # Adapt to your application's contract.
    spy.assert_calls(0)
```

The test must really reach the selected framework adapter and assigned
sidecar. Set the **Runtime / SDK** key, not the Copilot key, then run:

```bash
agenticdome verify-action --tool billing.refund --expect-verdict BLOCKED --expect-executed no -- pytest -q tests/test_blocked_refund.py
```

Run a separate allowed fixture with `--expect-verdict ALLOWED
--expect-executed yes` and `spy.assert_calls(1)`. The command emits no prompt,
arguments, test stdout, token or source. `passed` requires exactly one live-mode
SDK tool decision through a recognised adapter and a matching assertion from
the handler spy. A direct SDK call, missing spy, failed test, mismatched
verdict or multiple matching calls reports `incomplete`. This is
customer-operated integration evidence, not proof that *every* production
route is covered; confirm the corresponding retained sidecar decision and
repeat for consequential routes, A2A/MCP delegation and output boundaries.

### MCP: same review flow, different attachment boundary

From one deployable MCP workload, run `agenticdome mcp protect`, then
`agenticdome integrate preview --target mcp`. Review the exact local patch and
`AGENTICDOME-CHANGES.md`. After explicit approval, `agenticdome integrate
apply` creates a Git branch and adds only missing MCP registry, wrapper and
review files; it does not edit an existing client/server forwarder. If no new
MCP review file remains, apply refuses. Use `agenticdome integrate undo` only
before changing those files yourself; it will not remove changed customer work.

Manually connect the reviewed wrapper to the real MCP request and response
forwarder, provide authenticated identity and genuine purpose, route clients
through it, and test allowed and blocked calls. Then run `agenticdome inspect
--output agenticdome-inspection.json` and `agenticdome mcp verify`. Neither
the added files nor a passing packaged transport rehearsal alone prove that
every customer MCP path is intercepted.

### OpenClaw: native plugin rather than a source patch

OpenClaw protection is installed and enabled through the official OpenClaw
plugin/config commands in its onboarding page. Those commands change the
active gateway configuration; plan a safe restart window. `agenticdome
openclaw protect` checks plugin registration, consent and hook contract in a
separate CLI process, while `agenticdome openclaw verify` adds workload and
SDK-to-sidecar decision evidence. Check the serving Gateway with
`openclaw gateway status --require-rpc`, then exercise a safe tool call
through it and inspect the corresponding AgenticDome runtime decision. CLI-local
registration and sidecar probes alone do not prove a Gateway hook fired.
`agenticdome integrate apply` does not install, configure or undo the active
OpenClaw plugin. Native hooks need no source rewrite; custom skill paths that
bypass them require a reviewed `protectedExecute()` attachment and tests.

The separate Control Panel download, `agenticdome-onboarding.json`, is a tenant
connection reference. It contains confirmed Step 2 choices, tenant ID,
assigned API base and environment-variable names. It contains no key, source
or executable patch and is not consumed automatically by the CLI. Store the
real Runtime/SDK key separately in an environment variable or secret manager.

Import the refreshed `agenticdome-inspection.json` and the generated
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
