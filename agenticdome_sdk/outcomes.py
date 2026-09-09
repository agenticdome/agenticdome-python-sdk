"""Closed-loop outcome reporting helpers."""

from __future__ import annotations

import hashlib
import json
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _sha256(value: Optional[str]) -> Optional[str]:
    if value is None or not str(value).strip():
        return None
    text = str(value).strip()
    if len(text) == 64 and all(char in "0123456789abcdefABCDEF" for char in text):
        return text.lower()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sdk_outcome(*, tenant_id: str, chain_id: str, action_id: str, outcome_class: str,
                authorised_action_sha256: Optional[str] = None, observed_action_sha256: Optional[str] = None,
                destination: Optional[str] = None, side_effect_reference: Optional[str] = None) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "schema": "agenticdome.outcome-receipt.v1", "tenant_id": tenant_id,
        "chain_id": chain_id, "action_id": action_id, "jti": "sdk_" + uuid.uuid4().hex,
        "outcome_class": outcome_class, "assurance_level": "sdk_reported",
        "authorised_action_sha256": _sha256(authorised_action_sha256),
        "observed_action_sha256": _sha256(observed_action_sha256),
        "destination_sha256": _sha256(destination), "side_effect_ref_sha256": _sha256(side_effect_reference),
        "attempted_at": now, "completed_at": now,
    }


def _post(portal: str, access_token: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    request = urllib.request.Request(
        portal.rstrip("/") + "/api/agentguard/verified-actions/outcomes",
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"), method="POST",
        headers={"Authorization": "Bearer " + access_token, "Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - explicit AgenticDome portal
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("AgenticDome returned an invalid outcome response.")
    return value


def report_outcome(portal: str, access_token: str, receipt: Dict[str, Any]) -> Dict[str, Any]:
    return _post(portal, access_token, receipt)


def report_runtime_receipt(portal: str, access_token: str, signed_receipt: str) -> Dict[str, Any]:
    return _post(portal, access_token, {"receipt_token": signed_receipt})
