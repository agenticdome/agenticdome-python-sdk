import json
import re
from pathlib import Path

from agenticdome_sdk.hook_catalog import (
    CATALOG_SCHEMA,
    FRAMEWORK_HOOK_CATALOG,
    PUBLISHED_AGENTICDOME_PACKAGES,
    catalog_digest,
    framework_contract,
    harness_compatibility_manifest,
    version_satisfies_certification,
)
from agenticdome_sdk.onboarding_cli import FRAMEWORK_MARKERS


def test_every_detectable_framework_has_a_versioned_hook_contract() -> None:
    assert CATALOG_SCHEMA == "agenticdome.hook-catalog.v1"
    missing = set(FRAMEWORK_MARKERS) - set(FRAMEWORK_HOOK_CATALOG)
    assert missing == set()
    for key in FRAMEWORK_MARKERS:
        contract = framework_contract(key)
        assert contract is not None
        assert contract["adapter_module"]
        assert contract["attachment_methods"]


def test_harness_manifest_is_derived_for_every_python_contract() -> None:
    manifest = harness_compatibility_manifest()
    assert len(manifest) == 15
    crewai_source = FRAMEWORK_HOOK_CATALOG["crewai"]["packages"]["crewai"]
    crewai_certification = manifest["crewai"]["certified_packages"]["crewai"]
    assert crewai_certification["certified_by"] == "AgenticDome SDK Harness"
    assert crewai_certification["certified_at"]
    assert crewai_certification["certified_min_version"] == crewai_source["min"]
    assert crewai_certification["certified_max_version"] == crewai_source["max"]
    assert manifest["mcp"]["firewall_methods"] == [
        "screen_upstream_prompt",
        "authorize_mcp_tool_call",
        "authorize_mcp_method",
        "sanitize_text",
        "sanitize_mcp_result",
    ]
    assert all(
        certification["certified_at"]
        for row in manifest.values()
        for certification in row["certified_packages"].values()
    )
    assert "CrewAI 1.15.x" in manifest["mcp"]["certified_packages"]["mcp"]["compatibility_note"]
    assert FRAMEWORK_HOOK_CATALOG["mcp"]["label"] == "MCP Host / Gateway Firewall (Python)"
    assert FRAMEWORK_HOOK_CATALOG["mcp"]["integration_scope"] == "external_sdk_host_gateway"
    assert FRAMEWORK_HOOK_CATALOG["mcp"]["external_sdk"]["relationship"] == "certified_dependency"
    assert all(row["catalog_digest"] == catalog_digest() for row in manifest.values())


def test_published_typescript_openclaw_and_mcp_contracts_are_versioned() -> None:
    sdk_root = Path(__file__).resolve().parents[2]
    pyproject = (sdk_root / "python" / "pyproject.toml").read_text(encoding="utf-8")
    python_version = re.search(r"(?m)^version\s*=\s*\"([^\"]+)\"", pyproject).group(1)
    typescript_version = json.loads(
        (sdk_root / "js" / "agentguard_sdk" / "src" / "package.json").read_text(encoding="utf-8")
    )["version"]
    openclaw_version = json.loads(
        (sdk_root / "openclaw" / "ts" / "openclaw-agenticdome-security" / "package.json").read_text(encoding="utf-8")
    )["version"]

    assert PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-python-sdk"]["version"] == python_version
    assert PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-sdk"]["version"] == typescript_version
    assert PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-openclaw-security"]["version"] == openclaw_version
    for package, metadata in PUBLISHED_AGENTICDOME_PACKAGES.items():
        assert metadata["version"] in metadata["url"], package

    openclaw = framework_contract("openclaw")
    assert openclaw["packages"]["agenticdome-sdk"]["exact"] == typescript_version
    assert openclaw["packages"]["agenticdome-openclaw-security"]["exact"] == openclaw_version
    assert openclaw["packages"]["openclaw"]["min"] == PUBLISHED_AGENTICDOME_PACKAGES["openclaw"]["version"]
    assert openclaw["packages"]["openclaw"]["max"] == PUBLISHED_AGENTICDOME_PACKAGES["openclaw"]["version"]
    assert openclaw["native_hooks"] == ["before_agent_run", "before_tool_call", "tool_result_persist"]
    assert openclaw["runtime"]["node"] == ">=22.22.3 <23 || >=24.15.0 <25 || >=25.9.0"
    mcp_ts = framework_contract("mcp", "typescript")
    assert mcp_ts["packages"]["agenticdome-sdk"]["exact"] == typescript_version
    assert mcp_ts["adapter_class"] == "AgenticDomeClient"
    assert mcp_ts["attachment_methods"] == ["mcpToolCall", "mcpGuardrailValidate", "mcpListTools"]
    assert mcp_ts["label"] == "MCP API Client Surface (TypeScript)"
    assert mcp_ts["native_hooks"] == []
    assert mcp_ts["protocol_methods"] == ["tools/call", "tools/list"]
    assert mcp_ts["external_sdk"] == {
        "package": "@modelcontextprotocol/sdk",
        "relationship": "not_a_dependency",
        "certification": "not_applicable",
        "note": "agenticdome-sdk sends MCP policy requests through its own transport-neutral client API; customer MCP transports may use @modelcontextprotocol/sdk independently.",
    }


def test_certification_bounds_fail_closed() -> None:
    certified = {"min": "1.2.0", "max": "1.4.0"}
    assert version_satisfies_certification("1.2.0", certified) is True
    assert version_satisfies_certification("1.4.0", certified) is True
    assert version_satisfies_certification("1.4.1", certified) is False
    assert version_satisfies_certification("unknown", certified) is None


def test_mcp_documentation_tracks_certified_range_and_language_specific_scope() -> None:
    sdk_root = Path(__file__).resolve().parents[2]
    mcp = FRAMEWORK_HOOK_CATALOG["mcp"]["packages"]["mcp"]
    range_text = f"mcp>={mcp['min']},<={mcp['max']}"
    python_readme = (sdk_root / "python" / "README.md").read_text(encoding="utf-8")
    python_guide = (sdk_root / "python" / "docs" / "mcp-integration.md").read_text(encoding="utf-8")
    typescript_readme = (sdk_root / "js" / "agentguard_sdk" / "src" / "README.md").read_text(encoding="utf-8")
    typescript_guide = (sdk_root / "js" / "agentguard_sdk" / "src" / "docs" / "mcp-integration.md").read_text(encoding="utf-8")

    assert range_text in python_readme
    assert range_text in python_guide
    assert "MCP 2.0 removed the certified `mcp.server.fastmcp` import surface" in python_readme
    assert "does not forward requests to a customer MCP server" in typescript_readme
    assert "does not depend\non or certify `@modelcontextprotocol/sdk`" in typescript_guide
