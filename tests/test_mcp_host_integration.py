import asyncio

from agenticdome_sdk.mcp_host import AgenticDomeMCPHostFirewall, FirewallConfig, ProviderActionRule
from agenticdome_sdk.mcp_http_gateway import _review_sse_event


class FakeClient:
    def __init__(self):
        self.calls = []
        self.mcp_response = {"result": {"verdict": "ALLOWED", "reason": "ok"}}
        self.guardrail_response = {"result": {"verdict": "ALLOWED", "reason": "ok"}}
        self.mesh_response = {"result": {"verdict": "ALLOWED"}}
        self.verify_response = {"result": {"valid": True, "reason": "ok"}}
        self.raise_on_mcp = False

    def guardrail_validate(self, **kwargs):
        self.calls.append(("guardrail_validate", kwargs))
        return self.guardrail_response

    def mcp_guardrail_validate(self, **kwargs):
        self.calls.append(("mcp_guardrail_validate", kwargs))
        if self.raise_on_mcp:
            raise RuntimeError("service down")
        return self.mcp_response

    def mesh_validate(self, **kwargs):
        self.calls.append(("mesh_validate", kwargs))
        return self.mesh_response

    def a2a_verify_decision_token_rpc(self, **kwargs):
        self.calls.append(("a2a_verify_decision_token_rpc", kwargs))
        return self.verify_response

    def a2a_authorize_tool(self, **kwargs):
        self.calls.append(("a2a_authorize_tool", kwargs))
        return {"result": {"verdict": "ALLOWED", "decision_token": "handoff-token", "reason": "ok"}}

    def report_incident(self, **kwargs):
        self.calls.append(("report_incident", kwargs))
        return {"ok": True}

    def close(self):
        self.calls.append(("close", {}))


def make_firewall(client=None, **overrides):
    config = FirewallConfig(
        api_base="https://example.test",
        api_key="key",
        tenant_id="tenant",
        **overrides,
    )
    return AgenticDomeMCPHostFirewall(config=config, client=client or FakeClient())


def tools_call(arguments=None):
    return {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {"name": "search_crm", "arguments": arguments or {"query": "alice"}},
    }


def test_booking_cancel_requires_provider_owned_reservation_and_authenticated_member():
    client = FakeClient()
    forwarded = []
    firewall = AgenticDomeMCPHostFirewall(
        config=FirewallConfig(api_base="https://example.test", api_key="key", tenant_id="tenant", fail_closed=False),
        client=client,
        provider_action_rules={"booking.cancel": ProviderActionRule(action="cancel_booking")},
        resolve_provider_facts=lambda _name, args: {
            "reservation_id": args["reservation_id"],
            "owner_id": "member-owner",  # fetched from the provider's reservation record
            "principal_id": "member-requester",  # fetched from the provider's authenticated session
        },
    )
    request = tools_call({"reservation_id": "res-123", "owner_id": "member-requester"})
    request["params"]["name"] = "booking.cancel"

    async def forward(proposal):
        forwarded.append(proposal)
        return {"jsonrpc": "2.0", "id": "req-1", "result": {}}

    result = asyncio.run(firewall.forward_with_firewall(
        mcp_request=request,
        context={"session_id": "s1", "user_id": "member-owner", "policy_context": {"owner_id": "member-requester"}},
        forward_to_third_party=forward,
    ))
    assert result["error"]["code"] == -32000
    assert forwarded == []

    firewall.resolve_provider_facts = lambda _name, args: {
        "reservation_id": args["reservation_id"], "owner_id": "member-owner", "principal_id": "member-owner",
    }
    allowed = asyncio.run(firewall.forward_with_firewall(
        mcp_request=request, context={"session_id": "s1", "user_id": "spoofed"}, forward_to_third_party=forward,
    ))
    assert allowed["result"] == {}
    assert len(forwarded) == 1

    firewall.resolve_provider_facts = lambda _name, _args: {
        "reservation_id": "different-reservation", "owner_id": "member-owner", "principal_id": "member-owner",
    }
    mismatched_record = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))
    assert mismatched_record["error"]["code"] == -32000

    firewall.resolve_provider_facts = None
    missing_integration = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))
    assert missing_integration["error"]["code"] == -32000

    client.raise_on_mcp = True
    unavailable_runtime = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))
    assert unavailable_runtime["error"]["code"] == -32000


def test_booking_horizon_uses_provider_limit_and_final_arguments():
    client = FakeClient()
    seen = []

    async def facts(_name, args):
        seen.append(args)
        return {"principal_id": "member-1", "latest_allowed_date": "2026-10-05"}

    firewall = AgenticDomeMCPHostFirewall(
        config=FirewallConfig(api_base="https://example.test", api_key="key", tenant_id="tenant"),
        client=client,
        provider_action_rules={"booking.create": ProviderActionRule(action="create_booking")},
        resolve_provider_facts=facts,
    )
    request = tools_call({"booking_date": "2026-10-10"})
    request["params"]["name"] = "booking.create"
    blocked = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))
    assert blocked["error"]["code"] == -32000
    assert seen == [{"booking_date": "2026-10-10"}]

    client.mcp_response = {"result": {"verdict": "REDACTED", "sanitized_tool_args": {"booking_date": "2026-10-04"}}}
    allowed = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))
    assert allowed["params"]["arguments"] == {"booking_date": "2026-10-04"}
    assert seen[-1] == {"booking_date": "2026-10-04"}

    firewall.resolve_provider_facts = lambda _name, _args: {"latest_allowed_date": "2026-10-05"}
    missing_principal = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))
    assert missing_principal["error"]["code"] == -32000


def test_preflight_unknown_method_passthrough():
    firewall = make_firewall()
    request = {"jsonrpc": "2.0", "id": 1, "method": "unknown/method"}

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert result is request


def test_preflight_authorizes_tools_call_and_strips_internal_args():
    client = FakeClient()
    firewall = make_firewall(client=client)
    request = tools_call({"query": "alice", "_agenticdome_private": "secret"})

    result = asyncio.run(
        firewall.preflight_request(
            mcp_request=request,
            context={"session_id": "s1", "user_prompt": "find customer", "host_id": "host-a"},
        )
    )

    assert result["params"]["arguments"] == {"query": "alice"}
    assert [name for name, _ in client.calls] == ["guardrail_validate", "mcp_guardrail_validate"]
    mcp_call = client.calls[-1][1]
    assert mcp_call["tool_name"] == "search_crm"
    assert mcp_call["tool_args"] == {"query": "alice"}
    assert mcp_call["agent_id"] == "host-a"


def test_preflight_blocks_tools_call_as_jsonrpc_error():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "BLOCKED", "reason": "private@example.com"}}
    firewall = make_firewall(client=client)

    result = asyncio.run(firewall.preflight_request(mcp_request=tools_call(), context={"session_id": "s1"}))

    assert result["error"]["code"] == -32000
    assert "private@example.com" not in str(result)
    assert "private@example.com" in str(client.calls[-1][1])
    assert ("report_incident",) == tuple([client.calls[-1][0]])


def test_forward_with_firewall_does_not_forward_when_blocked():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "BLOCKED", "reason": "blocked"}}
    firewall = make_firewall(client=client)
    forwarded = {"called": False}

    async def forward(_request):
        forwarded["called"] = True
        return {"jsonrpc": "2.0", "id": "req-1", "result": {}}

    result = asyncio.run(
        firewall.forward_with_firewall(
            mcp_request=tools_call(),
            context={"session_id": "s1"},
            forward_to_third_party=forward,
        )
    )

    assert "error" in result
    assert forwarded["called"] is False


def test_preflight_rejects_missing_or_unknown_policy_verdict():
    for response in ({"result": {"reason": "no verdict"}}, {"result": {"verdict": "PENDING"}}):
        client = FakeClient()
        client.mcp_response = response
        firewall = make_firewall(client=client)

        result = asyncio.run(firewall.preflight_request(mcp_request=tools_call(), context={"session_id": "s1"}))

        assert result["error"]["code"] == -32000


def test_preflight_requires_explicit_safe_arguments_for_redacted_tool_call():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "REDACTED", "tool_args": {"query": "unsafe"}}}
    firewall = make_firewall(client=client)

    result = asyncio.run(firewall.preflight_request(mcp_request=tools_call({"query": "unsafe"}), context={"session_id": "s1"}))

    assert result["error"]["code"] == -32000


def test_unusable_verdict_never_reaches_mcp_forwarder():
    for response in ({"result": {"verdict": "PENDING"}}, {"result": {"verdict": "REDACTED"}}):
        client = FakeClient()
        client.mcp_response = response
        firewall = make_firewall(client=client)
        forwarded = []

        async def forward(request):
            forwarded.append(request)
            return {"jsonrpc": "2.0", "id": "req-1", "result": {}}

        result = asyncio.run(firewall.forward_with_firewall(
            mcp_request=tools_call({"query": "unsafe"}),
            context={"session_id": "s1"},
            forward_to_third_party=forward,
        ))

        assert result["error"]["code"] == -32000
        assert forwarded == []


def test_preflight_uses_empty_sanitized_arguments_instead_of_raw_arguments():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "REDACTED", "sanitized_tool_args": {}}}
    firewall = make_firewall(client=client)

    result = asyncio.run(firewall.preflight_request(mcp_request=tools_call({"query": "unsafe"}), context={"session_id": "s1"}))

    assert result["params"]["arguments"] == {}


def test_other_protected_mcp_methods_reject_unknown_decisions():
    for method, params in (
        ("resources/read", {"uri": "file:///private.txt"}),
        ("prompts/get", {"name": "private"}),
        ("sampling/createMessage", {"messages": [{"role": "user", "content": "private"}]}),
        ("tools/list", {}),
        ("resources/list", {}),
        ("prompts/list", {}),
    ):
        client = FakeClient()
        client.mcp_response = {"result": {"verdict": "UNKNOWN"}}
        firewall = make_firewall(client=client)
        request = {"jsonrpc": "2.0", "id": "req-2", "method": method, "params": params}

        result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

        assert result["error"]["code"] == -32000, method


def test_redacted_resource_request_uses_explicit_empty_replacement_params():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "REDACTED", "sanitized_args": {}}}
    firewall = make_firewall(client=client)
    request = {"jsonrpc": "2.0", "id": "req-2", "method": "resources/read", "params": {"uri": "file:///private.txt"}}

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert result["params"] == {}


def test_decision_token_is_verified_and_stripped_before_forwarding():
    client = FakeClient()
    firewall = make_firewall(client=client)
    request = tools_call(
        {
            "customer_id": "c1",
            "_agenticdome_decision_token": "tok",
            "_agenticdome_source_agent_id": "manager",
        }
    )

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert result["params"]["arguments"] == {"customer_id": "c1"}
    verify_call = client.calls[0]
    assert verify_call[0] == "a2a_verify_decision_token_rpc"
    assert verify_call[1]["token"] == "tok"
    assert verify_call[1]["source_agent_id"] == "manager"
    assert verify_call[1]["tool_args"] == {"customer_id": "c1"}


def test_partial_decision_token_blocks_request():
    firewall = make_firewall()
    request = tools_call({"customer_id": "c1", "_agenticdome_decision_token": "tok"})

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert "error" in result
    assert result["error"]["message"] == "AgenticDome Blocked: MCP request not authorized"


def test_forward_with_firewall_sanitizes_mcp_text_content():
    client = FakeClient()
    client.mesh_validate = lambda **kwargs: {"result": {"verdict": "REDACTED", "sanitized_text": kwargs["text"].replace("alice@example.com", "[REDACTED]")}}
    firewall = make_firewall(client=client)

    async def forward(request):
        assert request["params"]["arguments"] == {"query": "alice"}
        return {
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {"content": [{"type": "text", "text": "email alice@example.com"}]},
        }

    result = asyncio.run(
        firewall.forward_with_firewall(
            mcp_request=tools_call(),
            context={"session_id": "s1"},
            forward_to_third_party=forward,
        )
    )

    assert result["result"]["content"][0]["text"] == "email [REDACTED]"


def test_output_review_never_returns_original_text_for_unusable_verdict_or_redaction():
    for response in ({"result": {"reason": "missing verdict"}}, {"result": {"verdict": "REDACTED"}}):
        client = FakeClient()
        client.mesh_response = response
        firewall = make_firewall(client=client)

        result = asyncio.run(firewall.sanitize_text(text="private@example.com", context={"session_id": "s1"}))

        assert result == "[OUTPUT BLOCKED BY AgenticDome]"


def test_output_review_accepts_explicit_empty_redacted_text():
    client = FakeClient()
    client.mesh_response = {"result": {"verdict": "REDACTED", "sanitized_text": ""}}
    firewall = make_firewall(client=client)

    result = asyncio.run(firewall.sanitize_text(text="private@example.com", context={"session_id": "s1"}))

    assert result == ""
    assert any(name == "mesh_validate" for name, _ in client.calls)


def test_forward_with_firewall_does_not_return_unreviewed_output_when_sanitizer_fails_closed():
    client = FakeClient()

    def unavailable_mesh(**_kwargs):
        raise RuntimeError("output policy unavailable")

    client.mesh_validate = unavailable_mesh
    firewall = make_firewall(client=client, fail_closed=True)

    async def forward(_request):
        return {
            "jsonrpc": "2.0",
            "id": "req-output-failure",
            "result": {"content": [{"type": "text", "text": "unreviewed secret"}]},
        }

    result = asyncio.run(firewall.forward_with_firewall(
        mcp_request=tools_call(),
        context={"session_id": "s1"},
        forward_to_third_party=forward,
    ))

    assert result["error"]["code"] == -32000
    assert "unreviewed secret" not in str(result)


def test_structured_result_is_preserved_when_sanitizer_returns_same_json():
    client = FakeClient()
    structured = {"structuredContent": {"ok": True, "count": 1}}
    client.mesh_response = {"result": {"verdict": "ALLOWED", "sanitized_text": '{"structuredContent": {"count": 1, "ok": true}}'}}
    firewall = make_firewall(client=client)

    result = asyncio.run(firewall.sanitize_mcp_result(tool_output=structured, context={"session_id": "s1"}))

    assert result == structured


def test_mcp_output_reviews_text_and_structured_siblings_together():
    client = FakeClient()
    submitted = []

    def redact_json(**kwargs):
        submitted.append(kwargs["text"])
        return {"result": {"verdict": "REDACTED", "sanitized_text": kwargs["text"].replace("alice@example.com", "[REDACTED]")}}

    client.mesh_validate = redact_json
    firewall = make_firewall(client=client)
    output = {
        "content": [{"type": "text", "text": "Contact alice@example.com"}],
        "structuredContent": {"email": "alice@example.com"},
        "extra": {"owner": "alice@example.com"},
    }

    result = asyncio.run(firewall.sanitize_mcp_result(tool_output=output, context={"session_id": "s1"}))

    assert len(submitted) == 1
    assert "structuredContent" in submitted[0]
    assert "alice@example.com" not in str(result)
    assert result["structuredContent"]["email"] == "[REDACTED]"


def test_mcp_output_blocks_unparseable_whole_result_replacement():
    client = FakeClient()
    client.mesh_response = {"result": {"verdict": "REDACTED", "sanitized_text": "safe text, not JSON"}}
    firewall = make_firewall(client=client)

    async def forward(_request):
        return {
            "jsonrpc": "2.0", "id": "req-1",
            "result": {"content": [{"type": "text", "text": "alice@example.com"}], "structuredContent": {"email": "alice@example.com"}},
        }

    result = asyncio.run(firewall.forward_with_firewall(
        mcp_request=tools_call(), context={"session_id": "s1"}, forward_to_third_party=forward,
    ))

    assert result["error"]["code"] == -32000
    assert "alice@example.com" not in str(result)


def test_mcp_output_reviews_jsonrpc_sibling_and_error_fields():
    client = FakeClient()
    client.mesh_validate = lambda **kwargs: {"result": {
        "verdict": "REDACTED", "sanitized_text": kwargs["text"].replace("alice@example.com", "[REDACTED]"),
    }}
    firewall = make_firewall(client=client)
    request = tools_call()
    response = {"jsonrpc": "2.0", "id": "req-1", "result": {"structuredContent": {"email": "alice@example.com"}},
                "extension": {"email": "alice@example.com"}}
    reviewed = asyncio.run(firewall.review_forwarded_response(mcp_request=request, response=response, context={"session_id": "s1"}))
    assert "alice@example.com" not in str(reviewed)
    assert reviewed["id"] == "req-1"

    error_response = {"jsonrpc": "2.0", "id": "req-1", "error": {"code": 400, "message": "alice@example.com"}}
    reviewed_error = asyncio.run(firewall.review_forwarded_response(mcp_request=request, response=error_response, context={"session_id": "s1"}))
    assert reviewed_error["error"]["message"] == "[REDACTED]"


def test_get_sse_reviews_complete_jsonrpc_payload_without_request_method():
    client = FakeClient()
    observed = []

    def redact_json(**kwargs):
        observed.append(kwargs["text"])
        return {"result": {"verdict": "REDACTED", "sanitized_text": kwargs["text"].replace("alice@example.com", "[REDACTED]")}}

    client.mesh_validate = redact_json
    firewall = make_firewall(client=client)
    event = ["event: message", 'data: {"jsonrpc":"2.0","id":1,"result":{},"extension":{"email":"alice@example.com"}}']
    reviewed = asyncio.run(_review_sse_event(firewall, {}, event, {"session_id": "s1"}))
    assert len(observed) == 1
    assert "extension" in observed[0]
    assert "alice@example.com" not in "\n".join(reviewed)

    error_event = ["event: message", 'data: {"jsonrpc":"2.0","id":2,"error":{"code":400,"data":"alice@example.com"}}']
    reviewed_error = asyncio.run(_review_sse_event(firewall, {}, error_event, {"session_id": "s1"}))
    assert len(observed) == 2
    assert "alice@example.com" not in "\n".join(reviewed_error)

    id_event = ["event: message", 'data: {"jsonrpc":"2.0","id":"alice@example.com","result":{}}']
    reviewed_id = asyncio.run(_review_sse_event(firewall, {}, id_event, {"session_id": "s1"}))
    assert len(observed) == 3
    assert "alice@example.com" not in "\n".join(reviewed_id)
    assert "error" in "\n".join(reviewed_id)


def test_mcp_output_rejects_oversized_complete_review_instead_of_truncating():
    firewall = make_firewall(max_output_chars=64)
    request = tools_call()
    response = {"jsonrpc": "2.0", "id": "req-1", "result": {"structuredContent": {"value": "a" * 100}}}
    reviewed = asyncio.run(firewall.review_forwarded_response(mcp_request=request, response=response, context={"session_id": "s1"}))
    assert reviewed["error"]["code"] == -32000


def test_mcp_output_unlimited_setting_and_response_id_integrity():
    firewall = make_firewall(max_output_chars=0)
    request = tools_call()
    response = {"jsonrpc": "2.0", "id": "req-1", "result": {"structuredContent": {"value": "a" * 200}}}
    reviewed = asyncio.run(firewall.review_forwarded_response(mcp_request=request, response=response, context={"session_id": "s1"}))
    assert reviewed == response

    mismatch = {"jsonrpc": "2.0", "id": "alice@example.com", "result": {}}
    denied = asyncio.run(firewall.review_forwarded_response(mcp_request=request, response=mismatch, context={"session_id": "s1"}))
    assert denied["error"]["code"] == -32000
    assert "alice@example.com" not in str(denied)


def test_mcp_output_blocks_runtime_partial_scan_or_unattested_large_review():
    client = FakeClient()
    firewall = make_firewall(client=client)
    client.mesh_response = {"result": {"verdict": "ALLOWED", "context": {"truncated_for_scan": True, "truncated_for_echo": False}}}

    async def forward(_request):
        return {"jsonrpc": "2.0", "id": "req-1", "result": {"structuredContent": {"value": "alice@example.com"}}}

    denied = asyncio.run(firewall.forward_with_firewall(
        mcp_request=tools_call(), context={"session_id": "s1"}, forward_to_third_party=forward,
    ))
    assert denied["error"]["code"] == -32000

    client.mesh_response = {"result": {"verdict": "ALLOWED"}}
    large = {"jsonrpc": "2.0", "id": "req-1", "result": {"structuredContent": {"value": "a" * 6500}}}
    denied_large = asyncio.run(firewall.review_forwarded_response(
        mcp_request=tools_call(), response=large, context={"session_id": "s1"},
    ))
    assert denied_large["error"]["code"] == -32000


def test_mcp_forwarder_cannot_return_unreviewed_non_jsonrpc_content():
    firewall = make_firewall()

    async def forward(_request):
        return "alice@example.com"

    result = asyncio.run(firewall.forward_with_firewall(
        mcp_request=tools_call(), context={"session_id": "s1"}, forward_to_third_party=forward,
    ))
    assert result["error"]["code"] == -32000
    assert "alice@example.com" not in str(result)
    direct_review = asyncio.run(firewall.review_forwarded_response(
        mcp_request=tools_call(), response="alice@example.com", context={"session_id": "s1"},
    ))
    assert direct_review["error"]["code"] == -32000


def test_fail_open_returns_original_request_on_authorization_error():
    client = FakeClient()
    client.raise_on_mcp = True
    firewall = make_firewall(client=client, fail_closed=False)
    request = tools_call({"query": "alice"})

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert result == request


def test_invalid_request_returns_jsonrpc_invalid_request():
    firewall = make_firewall()

    result = asyncio.run(firewall.preflight_request(mcp_request=[], context={}))

    assert result["error"]["code"] == -32600


def test_resources_read_is_authorized_with_server_context():
    client = FakeClient()
    firewall = make_firewall(client=client)
    request = {"jsonrpc": "2.0", "id": "r1", "method": "resources/read", "params": {"uri": "file:///private/customer_data.csv"}}

    result = asyncio.run(firewall.preflight_request(
        mcp_request=request,
        context={"session_id": "s1", "mcp_server_id": "filesystem-mcp", "mcp_server_url": "https://mcp.internal"},
    ))

    assert result is request
    call = client.calls[0][1]
    assert call["tool_name"] == "mcp.resources/read"
    assert call["tool_args"]["uri"] == "file:///private/customer_data.csv"
    assert call["policy_context"]["mcp_server_id"] == "filesystem-mcp"
    assert call["policy_context"]["mcp_server_url"] == "https://mcp.internal"


def test_prompts_get_is_authorized():
    client = FakeClient()
    firewall = make_firewall(client=client)
    request = {"jsonrpc": "2.0", "id": "p1", "method": "prompts/get", "params": {"name": "debug_admin_prompt"}}

    result = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1"}))

    assert result is request
    assert client.calls[0][1]["tool_name"] == "mcp.prompts/get"
    assert client.calls[0][1]["tool_args"]["name"] == "debug_admin_prompt"


def test_tools_list_response_can_be_filtered():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "ALLOWED", "allowed_tools": ["web_search"]}}
    firewall = make_firewall(client=client)
    request = {"jsonrpc": "2.0", "id": "l1", "method": "tools/list", "params": {}}

    async def forward(_request):
        return {"jsonrpc": "2.0", "id": "l1", "result": {"tools": [{"name": "web_search"}, {"name": "delete_database"}]}}

    result = asyncio.run(firewall.forward_with_firewall(
        mcp_request=request,
        context={"session_id": "s1"},
        forward_to_third_party=forward,
    ))

    assert result["result"]["tools"] == [{"name": "web_search"}]
    assert [call[1]["tool_name"] for call in client.calls if call[0] == "mcp_guardrail_validate"] == ["mcp.tools/list", "mcp.tools/list"]


def test_tools_list_does_not_expose_items_after_unusable_output_decision():
    for output_decision in ({"result": {"reason": "missing verdict"}}, {"result": {"verdict": "REDACTED"}}):
        client = FakeClient()
        decisions = iter(({"result": {"verdict": "ALLOWED"}}, output_decision))
        client.mcp_guardrail_validate = lambda **kwargs: next(decisions)
        firewall = make_firewall(client=client)
        request = {"jsonrpc": "2.0", "id": "l1", "method": "tools/list", "params": {}}

        async def forward(_request):
            return {"jsonrpc": "2.0", "id": "l1", "result": {"tools": [{"name": "public.search"}, {"name": "private.admin"}]}}

        result = asyncio.run(firewall.forward_with_firewall(
            mcp_request=request,
            context={"session_id": "s1"},
            forward_to_third_party=forward,
        ))

        assert result["result"]["tools"] == []


def test_resources_list_response_can_be_filtered():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "ALLOWED", "allowed_resources": ["file:///safe/report.txt"]}}
    firewall = make_firewall(client=client)
    request = {"jsonrpc": "2.0", "id": "rl1", "method": "resources/list", "params": {}}

    async def forward(_request):
        return {
            "jsonrpc": "2.0",
            "id": "rl1",
            "result": {"resources": [{"uri": "file:///safe/report.txt"}, {"uri": "file:///secrets/api_keys.txt"}]},
        }

    result = asyncio.run(firewall.forward_with_firewall(
        mcp_request=request,
        context={"session_id": "s1"},
        forward_to_third_party=forward,
    ))

    assert result["result"]["resources"] == [{"uri": "file:///safe/report.txt"}]
    assert [call[1]["tool_name"] for call in client.calls if call[0] == "mcp_guardrail_validate"] == ["mcp.resources/list", "mcp.resources/list"]


def test_prompts_list_response_can_be_filtered():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "ALLOWED", "blocked_prompts": ["debug_admin_prompt"]}}
    firewall = make_firewall(client=client)
    request = {"jsonrpc": "2.0", "id": "pl1", "method": "prompts/list", "params": {}}

    async def forward(_request):
        return {
            "jsonrpc": "2.0",
            "id": "pl1",
            "result": {"prompts": [{"name": "support_reply"}, {"name": "debug_admin_prompt"}]},
        }

    result = asyncio.run(firewall.forward_with_firewall(
        mcp_request=request,
        context={"session_id": "s1"},
        forward_to_third_party=forward,
    ))

    assert result["result"]["prompts"] == [{"name": "support_reply"}]
    assert [call[1]["tool_name"] for call in client.calls if call[0] == "mcp_guardrail_validate"] == ["mcp.prompts/list", "mcp.prompts/list"]


def test_sanitize_mcp_result_sanitizes_description_but_preserves_uri_metadata():
    client = FakeClient()
    client.mesh_validate = lambda **kwargs: {"result": {"verdict": "REDACTED", "sanitized_text": kwargs["text"].replace("contains alice@example.com", "safe text")}}
    firewall = make_firewall(client=client)

    result = asyncio.run(firewall.sanitize_mcp_result(
        tool_output={"description": "contains alice@example.com", "uri": "file:///safe/report.txt", "mimeType": "text/plain"},
        context={"session_id": "s1"},
    ))

    assert result["description"] == "safe text"
    assert result["uri"] == "file:///safe/report.txt"
    assert result["mimeType"] == "text/plain"


def test_authorization_can_forward_sanitized_tool_args():
    client = FakeClient()
    client.mcp_response = {"result": {"verdict": "ALLOWED", "sanitized_tool_args": {"query": "alice", "limit": 100}}}
    firewall = make_firewall(client=client)

    result = asyncio.run(firewall.preflight_request(
        mcp_request=tools_call({"query": "alice", "limit": 100000}),
        context={"session_id": "s1"},
    ))

    assert result["params"]["arguments"] == {"query": "alice", "limit": 100}


def test_authorize_manager_handoff_stores_token_for_later_mcp_execution():
    client = FakeClient()
    firewall = make_firewall(client=client)

    asyncio.run(firewall.authorize_manager_handoff(
        manager_agent_id="manager",
        target_agent_id="filesystem-agent",
        tool_name="filesystem.read_file",
        tool_args={"path": "/reports/q4.txt"},
        context={"session_id": "s1"},
        tool_platform="filesystem-mcp",
    ))

    request = {
        "jsonrpc": "2.0",
        "id": "req-2",
        "method": "tools/call",
        "params": {"name": "filesystem.read_file", "arguments": {"path": "/reports/q4.txt"}},
    }
    result = asyncio.run(firewall.preflight_request(
        mcp_request=request,
        context={"session_id": "s1", "target_agent_id": "filesystem-agent"},
    ))

    assert result["params"]["arguments"] == {"path": "/reports/q4.txt"}
    assert [name for name, _ in client.calls][:2] == ["a2a_authorize_tool", "a2a_verify_decision_token_rpc"]
    assert client.calls[1][1]["token"] == "handoff-token"


def test_rate_limit_blocks_abuse():
    firewall = make_firewall(rate_limit_per_minute=1)
    request = tools_call({"query": "alice"})

    first = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1", "user_id": "u1"}))
    second = asyncio.run(firewall.preflight_request(mcp_request=request, context={"session_id": "s1", "user_id": "u1"}))

    assert "error" not in first
    assert "error" in second
    assert second["error"]["message"] == "AgenticDome Blocked: MCP request not authorized"


def test_streaming_response_sanitization():
    client = FakeClient()
    client.mesh_validate = lambda **kwargs: {"result": {"verdict": "REDACTED", "sanitized_text": kwargs["text"].replace("secret chunk", "safe chunk")}}
    firewall = make_firewall(client=client)

    async def chunks():
        yield {"jsonrpc": "2.0", "id": "s1", "result": {"content": [{"type": "text", "text": "secret chunk"}]}}

    async def run():
        output = []
        async for chunk in firewall.sanitize_streaming_response(chunks=chunks(), context={"session_id": "s1"}):
            output.append(chunk)
        return output

    result = asyncio.run(run())

    assert result[0]["result"]["content"][0]["text"] == "safe chunk"
