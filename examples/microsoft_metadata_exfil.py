import os

from agenticdome_sdk import AgentGuardClient
from agenticdome_sdk.scenarios import ScenarioLibrary

client = AgentGuardClient(
    api_base=os.environ["AGENTICDOME_API_BASE"],
    api_key=os.environ["AGENTICDOME_API_KEY"],
    tenant_id=os.environ["AGENTICDOME_TENANT_ID"],
)

payload = ScenarioLibrary.microsoft_metadata_exfil(
    agent_id="TOOLS_Agent_MS_Exfil_1",
    source_agent_id="TOOLS_Agent_MS_Exfil_1"
)
result = client.guardrail_validate(**payload)
print(result)
