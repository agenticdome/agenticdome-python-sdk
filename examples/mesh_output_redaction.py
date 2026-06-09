from agenticdome_sdk import AgentGuardClient
from agenticdome_sdk.scenarios import ScenarioLibrary

client = AgentGuardClient(
    api_base="https://x6pxvrqjym.ap-southeast-2.awsapprunner.com",
    api_key="YOUR_API_KEY",
    tenant_id="YOUR_PLATFORM_PROVIDED_TENANT_ID"
)

payload = ScenarioLibrary.mesh_output_redaction()
result = client.mesh_validate(
    agent_id=payload["agent_id"],
    session_id=payload["session_id"],
    direction=payload["direction"],
    text=payload["text"],
    policy_context=payload["policy_context"],
)
print(result)