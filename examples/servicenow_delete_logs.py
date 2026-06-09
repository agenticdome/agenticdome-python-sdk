from agenticdome_sdk import AgentGuardClient
from agenticdome_sdk.scenarios import ScenarioLibrary

client = AgentGuardClient(
    api_base="https://x6pxvrqjym.ap-southeast-2.awsapprunner.com",
    api_key="YOUR_API_KEY",
    tenant_id="YOUR_PLATFORM_PROVIDED_TENANT_ID"
)

payload = ScenarioLibrary.servicenow_delete_logs(
    agent_id="SNOW_Agent_1",
    source_agent_id="SNOW_Agent_1"
)

result = client.guardrail_validate(**payload)
print(result)