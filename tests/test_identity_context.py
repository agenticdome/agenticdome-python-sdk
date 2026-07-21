from agenticdome_sdk.identity import canonicalize_identity_context, enrich_policy_context


def test_cross_framework_identity_preserves_subject_and_actor_order():
    identity = canonicalize_identity_context(
        {
            "user_id": "human-1",
            "source_agent_id": "copilot-manager",
            "source_platform": "microsoft",
            "delegation_chain": [
                {"id": "copilot-manager", "framework": "microsoft", "verified": True},
                {"id": "python-worker", "framework": "pydanticai"},
            ],
        },
        platform="pydanticai",
        target_agent_id="python-worker",
    )

    assert identity["version"] == "agenticdome.identity.v1"
    assert identity["subject"]["id"] == "human-1"
    assert [actor["id"] for actor in identity["actors"]] == ["copilot-manager", "python-worker"]
    assert [actor["framework"] for actor in identity["actors"]] == ["microsoft", "pydanticai"]
    assert identity["actors"][0]["verified"] is False


def test_sdk_claims_are_assertions_not_verified_authority():
    context = enrich_policy_context({
        "verified_identity_claims": {
            "oid": "claimed-user",
            "roles": ["GlobalAdministrator"],
            "scp": "Directory.ReadWrite.All",
        },
    }, platform="agno", target_agent_id="agent-1")

    identity = context["agenticdome_identity"]
    assert identity["subject"]["id"] == "claimed-user"
    assert identity["subject"]["verified"] is False
    assert identity["subject"]["attributes"]["asserted_roles"] == ["GlobalAdministrator"]
    assert identity["provenance"]["client_claims_asserted"] is True
    assert identity["provenance"]["verified_claims_present"] is False
