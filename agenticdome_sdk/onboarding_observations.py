"""Optional static observations, separate from runtime enforcement and proof."""

import re
from pathlib import Path


POLICY = "pass_with_observations_v1"
SCHEMA = "agenticdome.onboarding-observations.v1"
FILE = ".agenticdome/DISCLAIMER.md"


def observations_summary(gate):
    names = ("action_required", "unresolved_bypasses", "review_required", "high_severity_bypasses")
    values = {name: gate.get(name, 0) for name in names}
    valid = "high_severity_bypasses" in gate and all(
        isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10000
        for value in values.values()
    )
    counts = {name: value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10000 else 0
              for name, value in values.items()}
    actions = max(counts["action_required"], counts["unresolved_bypasses"])
    high = counts["high_severity_bypasses"]
    valid = valid and high <= actions
    candidates = max(0, actions - high)
    cross_part = bool(gate.get("cross_part_review_required") or gate.get("cross_workload_review_required"))
    return {
        "schema": SCHEMA, "policy": POLICY, "file": FILE,
        "classification_complete": valid,
        "candidate_count": candidates, "review_count": counts["review_required"],
        "cross_part_note": cross_part,
        "total_count": candidates + counts["review_required"] + int(cross_part),
    }


def disclaimer_markdown(plan, verification, *, evidence_status="Current local verification"):
    gate = verification.get("semantic_gate", {})
    observations = verification.get("onboarding_observations") or observations_summary(gate)
    semantic = plan.get("semantic_analysis", {})
    lines = [
        "# AgenticDome onboarding observations and disclaimer", "",
        f"Evidence status: {evidence_status}", "",
        "These observations are optional. The tenant may investigate or improve these paths later; no acknowledgement or AgenticDome clearance is required to continue onboarding solely because of these observations.",
        "Passing local checks does not certify every execution branch or activate production. High-severity bypass findings, missing protection, uninspected source, failed tests and runtime/tenant proof failures remain blocking. Runtime BLOCKED decisions, unknown verdicts and policy failures still stop execution.", "",
        "| Observation | Count | Tenant action |",
        "|---|---:|---|",
        f"| Lower-severity analyzer candidates | {observations['candidate_count'] if observations['classification_complete'] else 0} | Optional investigation |",
        f"| Review-only paths | {observations['review_count']} | Optional investigation |",
        f"| Cross-part flow not automatically proven | {int(observations['cross_part_note'])} | Optional additional path tests |", "",
        "## Optional locations", "",
    ]
    if not observations["classification_complete"]:
        lines.extend(["Severity classification is incomplete. Unclassified candidates remain in RECONCILIATION.md for the coding assistant to resolve; they are not optional observations.", ""])
    for field in ("bypass_risks", "review_findings"):
        rows = semantic.get(field, [])
        if not isinstance(rows, list):
            continue
        for item in rows[:100]:
            if not isinstance(item, dict) or (field == "bypass_risks" and (
                not observations["classification_complete"] or item.get("severity") not in {"medium", "low"}
            )):
                continue
            raw = str(item.get("path") or "")[:500].replace("\\", "/")
            if not raw or raw.startswith("/") or ".." in Path(raw).parts:
                location = "[invalid relative path]"
            else:
                location = re.sub(r"[^A-Za-z0-9_./ -]", "_", raw)
            line = item.get("line", 1)
            line = max(1, min(line, 10000000)) if isinstance(line, int) and not isinstance(line, bool) else 1
            kind = "analyzer candidate" if field == "bypass_risks" else "review-only path"
            lines.append(f"- `{location}:{line}` — {kind}; static metadata may not observe an existing shared or downstream guard.")
    if observations["total_count"] == 0:
        lines.append("No optional observations in this run.")
    lines.extend(["", "This file is replaced in place on verification; it is a local note, not a protection certificate or an authorization to execute a business action.", ""])
    return "\n".join(lines)
