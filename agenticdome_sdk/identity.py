from __future__ import annotations

import hashlib
import json
from typing import Any


IDENTITY_CONTEXT_VERSION = "agenticdome.identity.v1"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = value.replace(",", " ").split()
    if not isinstance(value, (list, tuple, set)):
        value = [value]
    return sorted({_text(item) for item in value if _text(item)})


def _hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonicalize_identity_context(
    policy_context: dict[str, Any] | None,
    *,
    platform: str | None = None,
    target_agent_id: str | None = None,
) -> dict[str, Any]:
    context = dict(policy_context or {})
    existing = context.get("agenticdome_identity")
    if isinstance(existing, dict) and existing.get("version") == IDENTITY_CONTEXT_VERSION:
        return existing

    claims = context.get("verified_identity_claims")
    claims = dict(claims) if isinstance(claims, dict) else {}
    asserted_subject = _text(claims.get("oid") or claims.get("sub") or claims.get("user_id"))
    runtime_subject = _text(context.get("user_id") or context.get("principal_id") or context.get("caller_id"))
    subject_id = runtime_subject or asserted_subject

    subject = None
    if subject_id:
        subject = {
            "id": subject_id,
            "type": "human" if runtime_subject or claims.get("oid") else "principal",
            "tenant_id": _text(claims.get("tid") or context.get("entra_tenant_id") or context.get("tenant_id")) or None,
            "issuer": _text(claims.get("iss") or context.get("issuer")) or None,
            "provenance": "runtime_context" if runtime_subject else "client_claim_assertion",
            "verified": False,
            "attributes": {
                "asserted_roles": _list(claims.get("roles") or context.get("roles")),
                "asserted_scopes": _list(claims.get("scp") or context.get("scp")),
            },
        }

    raw_chain = context.get("actor_chain") or context.get("delegation_chain") or []
    if not isinstance(raw_chain, list):
        raw_chain = [raw_chain]
    actors: list[dict[str, Any]] = []
    for item in raw_chain:
        if len(actors) >= 32:
            break
        if isinstance(item, dict):
            actor_id = _text(item.get("id") or item.get("sub") or item.get("agent_id"))
            framework = _text(item.get("framework") or item.get("platform"))
            verified = False
            provenance = "client_runtime_assertion"
        else:
            actor_id = _text(item)
            framework = ""
            verified = False
            provenance = "runtime_context"
        if actor_id and len(actor_id) <= 512 and not any(actor["id"] == actor_id for actor in actors):
            actors.append({
                "id": actor_id,
                "type": "agent",
                "framework": framework or None,
                "verified": verified,
                "provenance": provenance,
            })

    for actor_id, framework in (
        (context.get("source_agent_id"), context.get("source_platform") or platform),
        (target_agent_id or context.get("target_agent_id") or context.get("agent_id"), context.get("platform") or platform),
    ):
        if len(actors) >= 32:
            break
        value = _text(actor_id)
        if value and not any(actor["id"] == value for actor in actors):
            actors.append({
                "id": value,
                "type": "agent",
                "framework": _text(framework) or None,
                "verified": False,
                "provenance": "request_binding",
            })

    return {
        "version": IDENTITY_CONTEXT_VERSION,
        "framework": _text(platform or context.get("platform")) or "unknown",
        "subject": subject,
        "actors": actors,
        "provenance": {
            "client_claims_asserted": bool(claims),
            "verified_claims_present": False,
            "native_context_hash": _hash(context),
        },
    }


def enrich_policy_context(
    policy_context: dict[str, Any] | None,
    *,
    platform: str | None = None,
    target_agent_id: str | None = None,
) -> dict[str, Any]:
    context = dict(policy_context or {})
    context["agenticdome_identity"] = canonicalize_identity_context(
        context,
        platform=platform,
        target_agent_id=target_agent_id,
    )
    return context
