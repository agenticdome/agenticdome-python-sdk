# Docker Agent: Gateway and mandatory local-tool guard

**Demo scope:** `agenticdome-demo --framework custom-python --scenario both`
evaluates two fixed inputs with the bundled offline baseline. It does not start
Docker Agent, install a hook, or execute a native tool. With `--live`, those same
inputs receive tenant-engine decisions from the configured sidecar; this still
does not verify Docker Agent attachment. Use the onboarding and native-runtime
checks below to verify the mandatory tool guard.

Start in **Action Gateway → Onboarding** on your control plane. AgenticDome fills
the Gateway URL and tenant from your assigned sidecar. Keep your existing service
URLs. There is no per-agent or per-tool registration requirement for direct
Gateway traffic inside your approved destination boundary.

Remote MCP/API/A2A requests use Docker Agent's native clients with Gateway headers.
Native shell, file and local MCP tools use the mandatory `tool_guard` integration.
The guard adapter is introduced in AgenticDome Python SDK 1.2.50. Its global
`hooks.d` integration is tested with Docker Agent v1.156.2's native runtime.
An older or experimental runtime must demonstrate the same mandatory tool phases
before it can be considered covered.

Download `50-agenticdome.yaml` from the assigned Gateway's Onboarding tab and
install it in Docker Agent's configured `hooks.d` directory. The generated file
uses your actual Gateway and tenant. Load the Runtime API key and either your
approved managed-deployment credentials or your existing provider's workload
and delegated user tokens through the workload secret manager. SDK header names
use `AGENTICDOME_WORKLOAD_TOKEN` and `AGENTICDOME_USER_TOKEN`; managed identity
uses the generated Identity connection settings. Do not infer a human identity
from the operating-system username or portal viewer.

Run `agenticdome-docker-guard --check` from that workload environment. This probes
the authenticated Gateway readiness endpoint, verifies that the updated native
guard exists, and executes no tool. Confirm the hook was loaded using Docker's
configuration diagnostics; readiness alone does not prove hook installation.

The mandatory phase runs after input transforms and before approval, including
auto-approved calls. A denial, missing decision, malformed response, request-hash
mismatch, unsupported capability, timeout or transport failure prevents execution.
The adapter never retries through a direct tool path. An allow decision remains
subject to Docker's own permissions. The hook cannot rewrite arguments; an
AgenticDome redaction or outstanding approval remains denied until resolved.
Policies that require a broker cannot be satisfied by claiming a native hook is
a broker. Native decisions are labelled `pre_execution_policy_only` and never
claim tool execution or destination-attested effects.

Keep the hook and adapter outside agent-writable mounts. Retain container,
filesystem, process and egress restrictions; these constrain the tool's actual
execution. The SDK hook is a policy integration, not an operating-system sandbox.
Model requests and internal delegation have their own lifecycle and are not
automatically covered by routing remote tool traffic through the Gateway.

Schema validators and identity keys are cached where safe. Each native action
receives a fresh policy check; allow decisions and permits are not reused across
tool invocations. Hook latency includes adapter process startup and local HTTP;
MCP schema microbenchmarks do not measure that complete path.
