import os

from agenticdome_sdk import AgentGuardClient
from agenticdome_sdk.scenarios import ScenarioLibrary

client = AgentGuardClient(
    api_base=os.environ["AGENTICDOME_API_BASE"],
    api_key=os.environ["AGENTICDOME_API_KEY"],
    tenant_id=os.environ["AGENTICDOME_TENANT_ID"],
)

payload = ScenarioLibrary.mcp_remote_patch_execution()
result = client.mcp_guardrail_validate(**payload)
print(result)
