import os

from agenticdome_sdk import AgentGuardClient
from agenticdome_sdk.scenarios import ScenarioLibrary


client = AgentGuardClient(
    api_base=os.environ["AGENTICDOME_API_BASE"],
    api_key=os.environ["AGENTICDOME_API_KEY"],
    tenant_id=os.environ["AGENTICDOME_TENANT_ID"],
    bearer_token=os.environ["AGENTICDOME_BEARER_TOKEN"],
)

payload = ScenarioLibrary.ai_foundry_callback_export()
result = client.copilot_analyze_tool_execution(payload)
print(result)
