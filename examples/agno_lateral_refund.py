import os

from agenticdome_sdk import AgentGuardClient
from agenticdome_sdk.scenarios import ScenarioLibrary

client = AgentGuardClient(
    api_base=os.environ["AGENTICDOME_API_BASE"],
    api_key=os.environ["AGENTICDOME_API_KEY"],
    tenant_id=os.environ["AGENTICDOME_TENANT_ID"],
)

payload = ScenarioLibrary.agno_lateral_refund()
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
