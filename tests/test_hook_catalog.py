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
    assert "CrewAI 1.15.2" in manifest["mcp"]["certified_packages"]["mcp"]["compatibility_note"]
    assert all(row["catalog_digest"] == catalog_digest() for row in manifest.values())


def test_published_typescript_openclaw_and_mcp_contracts_are_exact() -> None:
    assert PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-sdk"]["version"] == "0.5.2"
    assert PUBLISHED_AGENTICDOME_PACKAGES["agenticdome-openclaw-security"]["version"] == "1.0.0"
    openclaw = framework_contract("openclaw")
    assert openclaw["native_hooks"] == ["before_agent_run", "before_tool_call", "tool_result_persist"]
    assert openclaw["runtime"]["node"] == ">=22.19"
    mcp_ts = framework_contract("mcp", "typescript")
    assert mcp_ts["attachment_methods"] == ["mcpToolCall", "mcpGuardrailValidate", "mcpListTools"]


def test_certification_bounds_fail_closed() -> None:
    certified = {"min": "1.2.0", "max": "1.4.0"}
    assert version_satisfies_certification("1.2.0", certified) is True
    assert version_satisfies_certification("1.4.0", certified) is True
    assert version_satisfies_certification("1.4.1", certified) is False
    assert version_satisfies_certification("unknown", certified) is None
