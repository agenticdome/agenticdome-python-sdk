import pytest


pytest.importorskip("pydantic_ai")


def test_pydanticai_firewall_imports():
    from agenticdome_sdk.pydantic import CyberSecFirewall, FirewallConfig

    config = FirewallConfig(
        api_base="https://au.agenticdome.io",
        api_key="test-key",
        tenant_id="test-tenant",
        fail_closed=False,
    )

    firewall = CyberSecFirewall(config=config)

    assert firewall.config.api_base == "https://au.agenticdome.io"
    assert firewall.config.platform == "pydanticai"
    assert hasattr(firewall, "secure_tool")
    assert hasattr(firewall, "attach_to_agent")
