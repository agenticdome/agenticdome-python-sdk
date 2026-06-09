from agenticdome_sdk import AgentGuardClient
from agenticdome_sdk.scenarios import ScenarioLibrary

client = AgentGuardClient(
    api_base="https://x6pxvrqjym.ap-southeast-2.awsapprunner.com",
    api_key="YOUR_API_KEY",
    tenant_id="YOUR_PLATFORM_PROVIDED_TENANT_ID"
)

payload = ScenarioLibrary.crewai_lateral_refund()
result = client.a2a_authorize_tool(
    text=payload["text"],
    agent_id=payload["agent_id"],
    platform=payload["platform"],
    source_platform=payload["source_platform"],
    tool_platform=payload["tool_platform"],
    tool_name=payload["tool_name"],
    tool_args=payload["tool_args"],
    policy_context=payload["policy_context"],
    session_id=payload["session_id"],
    direction=payload["direction"],
)
print(result)