import os

from agenticdome_sdk import AgentGuardClient
from agenticdome_sdk.scenarios import ScenarioLibrary

client = AgentGuardClient(
    api_base=os.environ["AGENTICDOME_API_BASE"],
    api_key=os.environ["AGENTICDOME_API_KEY"],
    tenant_id=os.environ["AGENTICDOME_TENANT_ID"],
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
