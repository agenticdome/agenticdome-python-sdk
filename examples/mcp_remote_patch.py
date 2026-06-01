from agentguard_sdk import AgentGuardClient
from agentguard_sdk.scenarios import ScenarioLibrary

client = AgentGuardClient(
    api_base="https://x6pxvrqjym.ap-southeast-2.awsapprunner.com",
    api_key="YOUR_API_KEY",
    tenant_id="YOUR_PLATFORM_PROVIDED_TENANT_ID"
)

payload = ScenarioLibrary.mcp_remote_patch_execution()
result = client.mcp_guardrail_validate(**payload)
print(result)