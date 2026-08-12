import asyncio
import runpy
from pathlib import Path


def test_public_mcp_gateway_example_is_network_free_and_fail_closed():
    example = Path(__file__).resolve().parents[1] / "examples" / "mcp_gateway_action_firewall.py"
    namespace = runpy.run_path(str(example), run_name="agenticdome_mcp_launch_example")

    result = asyncio.run(namespace["run_demo"]())

    assert result["allowed"]["result"]["content"][0]["text"].startswith("Case 123")
    assert result["blocked"]["error"]["code"] == -32000
    assert "system.execute_remote_patch" not in result["forwarded_tools"]
    assert result["poisoned_result"]["result"]["content"][0]["text"] == "[OUTPUT BLOCKED BY AgenticDome]"
    assert result["forwarded_tools"] == ["crm.case.lookup", "web.search.poisoned"]


def test_public_mcp_guide_explains_value_without_overclaiming():
    guide = (
        Path(__file__).resolve().parents[1] / "docs" / "mcp-integration.md"
    ).read_text(encoding="utf-8")
    normalized = guide.lower()

    assert "## Why use AgenticDome for MCP" in guide
    assert "Other protocol messages pass through unchanged" in guide
    assert "only requests routed through the" in normalized
    assert "does not certify an mcp" in normalized
    assert "transfer legal liability" in normalized
    assert "every method mcp defines" not in normalized
    assert "shifts liability" not in normalized
