"""
CrewAI AgenticDome firewall example.

Install:

    pip install agenticdome-python-sdk[crewai]

Configure:

    export AGENTICDOME_API_BASE="https://au.agenticdome.io"
    export AGENTICDOME_API_KEY="your_api_key"
    export AGENTICDOME_TENANT_ID="your_tenant_id"

Then import this module before running your CrewAI crew so the hooks register.
"""

import agenticdome_sdk.crewai  # noqa: F401

print("AgenticDome CrewAI hooks registered.")
