from agenticdome_sdk import AgentGuardClient
from agenticdome_sdk.scenarios import ScenarioLibrary


client = AgentGuardClient(
    api_base="https://x6pxvrqjym.ap-southeast-2.awsapprunner.com",
    bearer_token="YOUR_MICROSOFT_TOKEN"
)

payload = ScenarioLibrary.ai_foundry_callback_export()
result = client.copilot_analyze_tool_execution(payload)
print(result)