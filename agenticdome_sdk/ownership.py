"""Provider-owned resource authorization shared by HTTP and MCP adapters.

Instantiate in a trusted gateway/provider process. Callbacks read the server's
authenticated request scope and system of record; no user/owner claim from an
agent is authoritative. Facts are resolved again on every execution, not cached.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass
import inspect
import re
import time


class OwnershipDenied(ValueError):
    """The action must not reach the provider transport."""


@dataclass(frozen=True)
class ResourceRule:
    resource_type: str
    resource_argument: str
    operation: str
    relationship: str = "owner"
    max_resources: int = 1


def _id(value):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 512


def verify_resource_fact(subject, request, fact, relationship):
    """Universal fact contract; a matching owner still needs operation rights."""
    if not isinstance(subject, dict) or not all(_id(subject.get(k)) for k in ("tenant_id", "principal_id")):
        raise OwnershipDenied("Authenticated tenant and principal are required")
    if not isinstance(fact, dict) or any(fact.get(k) != request[k] for k in ("tenant_id", "resource_type", "resource_id")):
        raise OwnershipDenied("Provider facts do not match the requested tenant and resource")
    operations = fact.get("allowed_operations")
    if not isinstance(operations, list) or request["operation"] not in operations:
        raise OwnershipDenied("Provider does not permit this operation")
    if relationship == "owner":
        permitted = fact.get("owner_id") == subject["principal_id"]
    else:
        principals = fact.get("entitled_principals")
        permitted = isinstance(principals, list) and subject["principal_id"] in principals
    if not permitted: raise OwnershipDenied("Authenticated principal has no required resource relationship")


class OwnershipGuard:
    def __init__(self, rules, *, resolve_subject, resolve_resource, deny_unmapped=True, timeout_seconds=5):
        if not isinstance(rules, dict) or not rules or not callable(resolve_subject) or not callable(resolve_resource):
            raise ValueError("Supply reviewed resource rules and trusted provider resolvers")
        if not 0 < timeout_seconds <= 30: raise ValueError("Resolver timeout must be within 30 seconds")
        self._rules = deepcopy(rules)
        for tool, rule in self._rules.items():
            if not _id(tool) or not isinstance(rule, ResourceRule) or not _id(rule.resource_type) or not _id(rule.operation):
                raise ValueError("Use exact tool names and resource types/operations")
            if rule.relationship not in {"owner", "entitled"} or type(rule.max_resources) is not int or not 1 <= rule.max_resources <= 50:
                raise ValueError("Invalid resource relationship or batch limit")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,7}", rule.resource_argument):
                raise ValueError("Use an exact resource argument path")
        self._subject = resolve_subject
        self._resource = resolve_resource
        self._deny_unmapped = deny_unmapped
        self._timeout = timeout_seconds

    def protects(self, tool):
        return self._deny_unmapped or tool in self._rules

    def _requests(self, tool, arguments, subject):
        rule = self._rules.get(tool)
        if rule is None:
            if self._deny_unmapped: raise OwnershipDenied("Tool has no reviewed resource adapter")
            return []
        if not isinstance(subject, dict) or not all(_id(subject.get(k)) for k in ("tenant_id", "principal_id")):
            raise OwnershipDenied("Authenticated tenant and principal are required")
        value = arguments
        for part in rule.resource_argument.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        ids = value if isinstance(value, list) else [value]
        if not ids or len(ids) > rule.max_resources or any(not _id(v) for v in ids):
            raise OwnershipDenied("Missing resource identity or excessive resource scope")
        return [(rule, {"tenant_id": subject["tenant_id"], "principal_id": subject["principal_id"],
            "resource_type": rule.resource_type, "resource_id": rid, "operation": rule.operation,
            "tool": tool, "arguments": deepcopy(arguments)}) for rid in dict.fromkeys(ids)]

    def check(self, tool, arguments, *, expected_tenant=None):
        if not self.protects(tool): return
        try:
            deadline = time.monotonic() + self._timeout
            subject = self._subject()
            if inspect.isawaitable(subject):
                if inspect.iscoroutine(subject): subject.close()
                raise OwnershipDenied("Use check_async with asynchronous resolvers")
            subject = deepcopy(subject)
            if expected_tenant is not None and (not isinstance(subject, dict) or subject.get("tenant_id") != str(expected_tenant)):
                raise OwnershipDenied("Provider subject tenant does not match the enforcement tenant")
            for rule, request in self._requests(tool, arguments, subject):
                if time.monotonic() >= deadline: raise OwnershipDenied("Provider resource authorization timed out")
                fact = self._resource(deepcopy(request))
                if inspect.isawaitable(fact):
                    if inspect.iscoroutine(fact): fact.close()
                    raise OwnershipDenied("Use check_async with asynchronous resolvers")
                if time.monotonic() >= deadline: raise OwnershipDenied("Provider resource authorization timed out")
                verify_resource_fact(subject, request, fact, rule.relationship)
        except OwnershipDenied: raise
        except Exception as exc: raise OwnershipDenied("Provider resource authorization unavailable") from exc

    async def check_async(self, tool, arguments, *, expected_tenant=None):
        if not self.protects(tool): return
        arguments = deepcopy(arguments)
        async def resolve():
            async def call(fn, *args):
                value = fn(*args) if inspect.iscoroutinefunction(fn) else await asyncio.to_thread(fn, *args)
                return await value if inspect.isawaitable(value) else value
            subject = await call(self._subject)
            subject = deepcopy(subject)
            if expected_tenant is not None and (not isinstance(subject, dict) or subject.get("tenant_id") != str(expected_tenant)):
                raise OwnershipDenied("Provider subject tenant does not match the enforcement tenant")
            for rule, request in self._requests(tool, arguments, subject):
                fact = await call(self._resource, deepcopy(request))
                verify_resource_fact(subject, request, fact, rule.relationship)
        try: await asyncio.wait_for(resolve(), timeout=self._timeout)
        except OwnershipDenied: raise
        except Exception as exc: raise OwnershipDenied("Provider resource authorization unavailable") from exc

    def check_http(self, tool, arguments, evidence, *, expected_tenant=None):
        # GraphQL IDs must come from interpreted fields, never unused variables
        # or agent-provided aliases. The authenticated sidecar supplies evidence.
        has_graphql = any(k.startswith(tool + "#") for k in self._rules)
        if has_graphql or evidence.get("graphql_interpretation"):
            if evidence.get("graphql_interpretation") != "agenticdome.graphql-actions.v1" or not isinstance(evidence.get("graphql_actions"), list):
                raise OwnershipDenied("A compatible sidecar must interpret GraphQL before ownership checks")
            for action in evidence["graphql_actions"]:
                self.check(tool + "#" + action["coordinate"], action["arguments"], expected_tenant=expected_tenant)
        else:
            self.check(tool, arguments, expected_tenant=expected_tenant)
