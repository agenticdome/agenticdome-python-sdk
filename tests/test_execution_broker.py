from agenticdome_sdk.client import AgenticDomeClient, AgenticDomeError


def _client(mode="enforce"):
    return AgenticDomeClient(
        "https://sidecar.example",
        api_key="test-key",
        tenant_id="tenant-1",
        execution_broker_mode=mode,
        max_retries=0,
    )


def test_tool_authorization_uses_one_request_broker_and_requires_receipt(monkeypatch):
    client = _client()
    observed = {}

    def request(method, path, **kwargs):
        observed.update({"method": method, "path": path, **kwargs})
        return {
            "verdict": "ALLOWED",
            "execution_receipt": "signed-receipt",
            "broker": {"verified": True, "token_consumed": True},
        }

    monkeypatch.setattr(client, "_request", request)
    response = client.guardrail_validate(
        text="lookup customer",
        agent_id="support-agent",
        platform="custom_python",
        source_agent_id="support-manager",
        source_platform="microsoft",
        tool_name="crm.lookup",
        tool_args={"id": "123"},
        actor_chain=[
            {"id": "support-manager", "framework": "microsoft"},
            {"id": "support-agent", "framework": "custom_python"},
        ],
        scopes=["crm.customer.read"],
        permissions=["case.status.read"],
        parent_jti="parent-decision",
        root_jti="root-decision",
        policy_id="support-policy",
        policy_version="3",
        policy_hash="sha256:" + "a" * 64,
        proof_thumbprint="proof-thumbprint",
        execution_destination="https://crm.example.test/customers/123",
        execution_http_method="GET",
        workload_id="spiffe://customer.test/agent/support",
    )

    assert response["verdict"] == "ALLOWED"
    assert observed["path"] == "/tools/execution/authorize"
    assert observed["json_body"]["boundary_id"].startswith("sdk:")
    assert observed["json_body"]["actor_chain"][1]["id"] == "support-agent"
    assert observed["json_body"]["scopes"] == ["crm.customer.read"]
    assert observed["json_body"]["permissions"] == ["case.status.read"]
    assert observed["json_body"]["parent_jti"] == "parent-decision"
    assert observed["json_body"]["root_jti"] == "root-decision"
    assert observed["json_body"]["policy_id"] == "support-policy"
    assert observed["json_body"]["policy_version"] == "3"
    assert observed["json_body"]["policy_hash"] == "sha256:" + "a" * 64
    assert observed["json_body"]["proof_thumbprint"] == "proof-thumbprint"
    assert observed["json_body"]["destination"] == "https://crm.example.test/customers/123"
    assert observed["json_body"]["http_method"] == "GET"
    assert observed["json_body"]["workload_id"] == "spiffe://customer.test/agent/support"
    assert observed["json_body"]["policy_context"]["actor_chain"][0]["id"] == "support-manager"
    assert client.enforcement_headers(
        response,
        workload_id="spiffe://customer.test/agent/support",
    ) == {
        "X-AgenticDome-Execution-Receipt": "signed-receipt",
        "X-AgenticDome-Workload-Id": "spiffe://customer.test/agent/support",
    }


def test_enforced_broker_fails_closed_without_consumed_receipt(monkeypatch):
    client = _client()
    monkeypatch.setattr(client, "_request", lambda *args, **kwargs: {"verdict": "ALLOWED"})

    try:
        client.guardrail_validate(
            text="lookup customer",
            agent_id="support-agent",
            platform="custom_python",
            tool_name="crm.lookup",
            tool_args={"id": "123"},
        )
    except AgenticDomeError as exc:
        assert "atomically consumed" in str(exc)
    else:
        raise AssertionError("missing broker receipt did not fail closed")
