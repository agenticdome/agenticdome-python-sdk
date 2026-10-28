import asyncio
from copy import deepcopy
from unittest.mock import patch

import pytest
import requests

from agenticdome_sdk import OwnershipGuard, OwnershipDenied, ResourceRule, AgenticDomeClient, AgenticDomeError, ApprovalRequired


def guard(facts=None, **kwargs):
    base = {"tenant_id": "tenant-a", "resource_type": "record", "resource_id": "record-a", "owner_id": "alice", "allowed_operations": ["read", "cancel"]}
    base.update(facts or {})
    rules = kwargs.pop("rules", {"records.cancel": ResourceRule("record", "body.id", "cancel")})
    return OwnershipGuard(rules, resolve_subject=lambda: {"tenant_id": "tenant-a", "principal_id": "alice"},
                          resolve_resource=lambda request: deepcopy(base), **kwargs)


@pytest.mark.parametrize("facts", [{"owner_id": "bob"}, {"tenant_id": "tenant-b"}, {"resource_id": "record-b"}, {"resource_type": "volume"}, {"allowed_operations": ["read"]}])
def test_provider_facts_override_all_caller_claims(facts):
    with pytest.raises(OwnershipDenied): guard(facts).check("records.cancel", {"body": {"id": "record-a", "owner_id": "alice"}})


def test_own_record_allowed_and_unknown_or_bulk_denied():
    g = guard(); g.check("records.cancel", {"body": {"id": "record-a"}})
    for tool, args in [("other", {"body": {"id": "record-a"}}), ("records.cancel", {"body": {"id": ["record-a", "record-b"]}})]:
        with pytest.raises(OwnershipDenied): g.check(tool, args)


def test_entitlements_cover_non_owner_reads_without_granting_deletes():
    rules = {"records.read": ResourceRule("record", "id", "read", relationship="entitled")}
    g = guard({"owner_id": "bob", "entitled_principals": ["alice"]}, rules=rules)
    g.check("records.read", {"id": "record-a"})
    with pytest.raises(OwnershipDenied): g.check("records.delete", {"id": "record-a"})


def test_matching_owner_in_another_enforcement_tenant_is_denied():
    g = guard()
    with pytest.raises(OwnershipDenied): g.check("records.cancel", {"body": {"id": "record-a"}}, expected_tenant="tenant-b")
    with pytest.raises(OwnershipDenied): asyncio.run(g.check_async("records.cancel", {"body": {"id": "record-a"}}, expected_tenant="tenant-b"))


def test_async_resolver_timeout_and_rule_mutation_fail_closed():
    rules = {"read": ResourceRule("record", "id", "read")}
    async def slow(request): await asyncio.sleep(1)
    g = OwnershipGuard(rules, resolve_subject=lambda: {"tenant_id": "tenant-a", "principal_id": "alice"}, resolve_resource=slow, timeout_seconds=.01)
    rules.clear()
    with pytest.raises(OwnershipDenied): asyncio.run(g.check_async("read", {"id": "record-a"}))


def test_graphql_ownership_uses_resolved_arguments_not_unused_variables():
    g = guard(rules={"api#Mutation.cancel": ResourceRule("record", "id", "cancel")})
    args = {"body": {"variables": {"id": "record-a"}}}
    evidence = {"graphql_interpretation": "agenticdome.graphql-actions.v1", "graphql_actions": [{"coordinate": "Mutation.cancel", "arguments": {"id": "record-b"}}]}
    with pytest.raises(OwnershipDenied): g.check_http("api", args, evidence)
    with pytest.raises(OwnershipDenied): g.check_http("api", args, {})


def test_http_rechecks_revoked_ownership_after_approval_before_any_send():
    state = {"owner": "alice", "approved": False}
    g = OwnershipGuard({"records.cancel": ResourceRule("record", "body.id", "cancel")},
        resolve_subject=lambda: {"tenant_id": "tenant-a", "principal_id": "alice"},
        resolve_resource=lambda req: {**req, "owner_id": state["owner"], "allowed_operations": ["cancel"]})
    client = AgenticDomeClient(api_base="https://sidecar.invalid", api_key="fixture", tenant_id="tenant-a", ownership_guard=g)
    rid = "8d50b9df-d260-4f45-9773-85daceb0edb2"
    def broker(method, route, **kw):
        if route.endswith("/grant"): return {"approval_grant": "fixture"}
        if not state["approved"]: return {"verdict": "APPROVAL_REQUIRED", "context": {"approval": {"id": rid}}}
        return {"verdict": "ALLOWED", "execution_receipt": "fixture", "enforcement_evidence": {"http_request_bound": True},
                "broker": {"verified": True, "token_consumed": True, "approval_request_id": rid}}
    client._request = broker
    try:
        with patch.object(requests.Session, "send") as send:
            with pytest.raises(ApprovalRequired) as pending:
                client.execute_http(method="POST", url="https://api.invalid/cancel", agent_id="agent", tool_name="records.cancel", body='{"id":"record-a"}', headers={"content-type": "application/json"})
            state.update(approved=True, owner="bob")
            with pytest.raises(OwnershipDenied): client.resume_approved_http(pending.value)
            send.assert_not_called()
    finally: client.close()


def test_graphql_helper_requires_interpreting_runtime_before_transport():
    client = AgenticDomeClient(api_base="https://sidecar.invalid", api_key="fixture", tenant_id="tenant-a")
    client._request = lambda *a, **kw: {"verdict": "ALLOWED", "execution_receipt": "fixture", "enforcement_evidence": {"http_request_bound": True}, "broker": {"verified": True, "token_consumed": True}}
    try:
        with patch.object(requests.Session, "send") as send:
            with pytest.raises(AgenticDomeError): client.execute_graphql(url="https://api.invalid/graphql", query="query { version }", agent_id="agent", tool_name="api")
            send.assert_not_called()
    finally: client.close()
