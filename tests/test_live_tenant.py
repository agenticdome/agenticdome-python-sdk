import os

import pytest

from agenticdome_sdk.client import AgentGuardClient


pytestmark = pytest.mark.skipif(
    os.getenv("AGENTICDOME_LIVE_TENANT_TEST") != "1",
    reason="Set AGENTICDOME_LIVE_TENANT_TEST=1 with real tenant credentials to run live checks.",
)


def live_client():
    return AgentGuardClient(
        api_base=os.getenv("AGENTICDOME_API_BASE", "").rstrip("/"),
        api_key=os.getenv("AGENTICDOME_API_KEY", ""),
        tenant_id=os.getenv("AGENTICDOME_TENANT_ID", ""),
        timeout=20,
        max_retries=1,
    )


def verdict_from(response):
    if "verdict" in response:
        return str(response.get("verdict") or "").upper()
    result = response.get("result") if isinstance(response, dict) else None
    if isinstance(result, dict):
        return str(result.get("verdict") or "").upper()
    return ""


def test_live_guardrail_allows_benign_prompt():
    client = live_client()

    response = client.guardrail_validate(
        text="Summarize the public product documentation for a customer support agent.",
        agent_id="python-sdk-live-smoke",
        direction="inbound",
        platform="python",
        session_id="python-sdk-live-smoke-session",
        policy_context={"test_case": "benign_prompt"},
    )

    verdict = verdict_from(response)
    assert verdict not in {"BLOCKED", "DENIED"}, response


def test_live_mesh_sanitizes_or_allows_output():
    client = live_client()

    response = client.mesh_validate(
        text="Support response for alice@example.com with token=sk_live_example1234567890",
        agent_id="python-sdk-live-smoke",
        direction="output",
        platform="python",
        session_id="python-sdk-live-smoke-session",
        redact_pii=True,
        redact_secrets=True,
        policy_context={"test_case": "mesh_output"},
    )

    verdict = verdict_from(response)
    assert verdict in {"", "ALLOWED", "REDACTED", "BLOCKED", "DENIED"}, response

    if os.getenv("AGENTICDOME_LIVE_EXPECT_STRICT") == "1":
        assert verdict in {"REDACTED", "BLOCKED", "DENIED"}, response
