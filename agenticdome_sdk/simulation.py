"""Deterministic, network-free AgenticDome onboarding simulation.

This module deliberately models only a small public baseline policy. It does not
load tenant policy, issue trusted decisions, or claim runtime assurance.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Dict, Optional


LOCAL_POLICY_ID = "agenticdome-local-baseline-v1"
SIMULATED_TOKEN_PREFIX = "agenticdome-local-sim-not-for-production."
logger = logging.getLogger("agenticdome_sdk.local_sim")


_BLOCK_PATTERNS = (
    (r"\bignore\s+(?:all\s+)?(?:prior|previous|system)\s+instructions?\b", "prompt-injection override"),
    (r"\b(?:reveal|export|send|exfiltrat\w*)\b.{0,100}\b(?:secret|password|api[ _-]?key|token|credential)s?\b", "secret exfiltration"),
    (r"\b(?:drop|truncate|delete)\b.{0,80}\b(?:table|database|audit[ _-]?log|production)\b", "destructive data operation"),
    (r"\b(?:download|fetch)\b.{0,100}\b(?:execute|run)\b.{0,100}\b(?:patch|script|powershell|shell)\b", "remote code execution"),
    (r"\bimpersonat\w*\b.{0,100}\b(?:admin|payment|billing|privileged)\b", "privilege impersonation"),
)

_SENSITIVE_PATTERNS = (
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "email address"),
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "payment-card-like number"),
    (re.compile(r"\b(?:api[_ -]?key|password|secret|bearer token)\s*[:=]\s*\S+", re.I), "credential-like value"),
)


def _canonical(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except Exception:
        return str(value)


def _decision_id(material: str) -> str:
    return "sim-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _simulated_token(material: str) -> str:
    return SIMULATED_TOKEN_PREFIX + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _redact(text: str) -> tuple[str, list[str]]:
    sanitized = text
    findings: list[str] = []
    for pattern, finding in _SENSITIVE_PATTERNS:
        updated, count = pattern.subn("[REDACTED]", sanitized)
        if count:
            findings.append(finding)
            sanitized = updated
    return sanitized, findings


class LocalSimulationEngine:
    """Small deterministic evaluator used only when AGENTICDOME_MODE=local_sim."""

    def evaluate(self, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        body = dict(payload or {})
        text = str(body.get("text") or body.get("prompt") or body.get("output") or "")
        material = " ".join(
            [
                text,
                str(body.get("tool_name") or body.get("name") or ""),
                _canonical(body.get("tool_args") or body.get("arguments") or {}),
                _canonical(body.get("policy_context") or {}),
            ]
        )
        lowered = material.lower()
        reason = "Local baseline found no blocked pattern."
        verdict = "ALLOWED"
        findings: list[str] = []

        for expression, label in _BLOCK_PATTERNS:
            if re.search(expression, lowered, re.I | re.S):
                verdict = "BLOCKED"
                reason = f"Local baseline detected {label}."
                findings.append(label)
                break

        sanitized_text, sensitive_findings = _redact(text)
        if verdict == "ALLOWED" and sensitive_findings and str(body.get("direction", "")).lower() in {"output", "outbound"}:
            verdict = "REDACTED"
            reason = "Local baseline redacted sensitive output."
            findings.extend(sensitive_findings)

        decision_id = _decision_id(material)
        result = {
            "verdict": verdict,
            "decision": verdict,
            "status": verdict.lower(),
            "allowed": verdict in {"ALLOWED", "REDACTED"},
            "reason": reason,
            "message": reason,
            "decision_id": decision_id,
            "incident_id": decision_id if verdict == "BLOCKED" else None,
            "sanitized_text": sanitized_text,
            "text": sanitized_text,
            "findings": findings,
            "simulated": True,
            "mode": "local_sim",
            "policy_id": LOCAL_POLICY_ID,
            "policy_source": "bundled_public_demonstration_policy",
            "assurance": "not_cloud_enforced",
            "warning": "Simulation only: no tenant policy, cloud assurance, signed token, or execution receipt was used.",
        }
        # Give trial users an immediate terminal signal without leaking prompts,
        # arguments, credentials, or other payload content into application logs.
        log = logger.warning if verdict in {"BLOCKED", "REDACTED"} else logger.info
        log(
            "AgenticDome local simulation decision verdict=%s decision_id=%s "
            "agent_id=%s tool_name=%s reason=%s (not cloud enforcement)",
            verdict,
            decision_id,
            str(body.get("agent_id") or "unknown"),
            str(body.get("tool_name") or body.get("name") or "none"),
            reason,
        )
        return result

    def request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        body = dict(payload or {})

        if path.startswith("/health/readiness"):
            return {
                "status": "simulation_only",
                "ready": True,
                "simulated": True,
                "mode": "local_sim",
                "runtime_security": "not_attested",
                "warning": "Local simulation is not a deployed or attested sidecar.",
            }
        if path.startswith("/tools/mesh/topology"):
            return {
                "tenant_id": "local-sim",
                "nodes": [],
                "edges": [],
                "simulated": True,
                "mode": "local_sim",
                "warning": "No tenant topology is loaded in local simulation.",
            }
        if path.startswith("/tools/provenance/status"):
            return {
                "verified": False,
                "approved_tools": 0,
                "simulated": True,
                "mode": "local_sim",
                "warning": "Signed provenance is available only from an assigned runtime sidecar.",
            }
        if path.startswith("/a2a/decision/verify"):
            token = str(body.get("token") or "")
            valid = token.startswith(SIMULATED_TOKEN_PREFIX)
            result = self.evaluate(body)
            result.update({"valid": valid, "verified": valid, "token_consumed": valid})
            if not valid:
                result.update({"verdict": "BLOCKED", "decision": "BLOCKED", "allowed": False, "reason": "Unknown simulation token."})
            return result
        if path == "/a2a":
            params = body.get("params") if isinstance(body.get("params"), dict) else {}
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else params
            result = self.evaluate(arguments)
            if str(body.get("method")) == "actions/call" and result["verdict"] != "BLOCKED":
                result["decision_token"] = _simulated_token(_canonical(arguments))
                result["token_warning"] = "This simulation marker is not a signed or production-valid decision token."
            return {"jsonrpc": "2.0", "id": body.get("id", "1"), "result": result}
        if path == "/mcp":
            params = body.get("params") if isinstance(body.get("params"), dict) else {}
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else params
            result = self.evaluate(arguments)
            return {"jsonrpc": "2.0", "id": body.get("id", "1"), "result": result}
        if path.startswith("/tools/execution/authorize"):
            result = self.evaluate(body)
            result["broker"] = {"verified": False, "token_consumed": False, "simulated": True}
            result["warning"] = "Simulation cannot issue a trusted execution receipt; broker enforcement remains fail-closed."
            return result
        if path.startswith("/incidents") or path.startswith("/trust"):
            result = self.evaluate(body)
            result["recorded"] = False
            result["warning"] = "Simulation events are local and are not written to tenant telemetry."
            return result

        return self.evaluate(body)
