"""Separate current source assessment from historical and operator handoff text.

Markdown remains an assertion; inspection, semantic bypass and test gates still
run independently. Unknown application read sites remain source gaps.
"""
import re


OPERATOR_SECTIONS = {
    "runtime configuration handoff", "must do steps to activate firewall",
    "activation prerequisites", "production activation",
}
HISTORY_SECTIONS = {"preserved historical baseline and unique evidence", "historical evidence"}


def assessment_scope(markdown):
    headings = []
    source_incomplete = False
    activation_pending = False
    source_rows = 0
    structured = False
    for line in markdown.splitlines():
        match = re.match(r"^\s*(#{1,6})\s+(.+?)\s*$", line)
        if match:
            level, title = len(match[1]), match[2].casefold()
            headings = [(depth, name) for depth, name in headings if depth < level]
            headings.append((level, title))
            structured = structured or title == "source assessment scope"
            continue
        sections = {name for _, name in headings}
        if sections & HISTORY_SECTIONS:
            continue
        cells = [cell.strip().strip("*`").strip() for cell in line.strip().strip("|").split("|")] if line.lstrip().startswith("|") else []
        if "source assessment scope" in sections and cells:
            if cells[0].casefold() == "runtime source paths":
                source_rows += 1
                source_incomplete |= len(cells) < 2 or cells[1].upper() != "ASSESSED" or bool(re.search(r"\bNOT ASSESSED\b", line, re.I))
                continue
            if cells[0].casefold() == "production activation":
                activation_pending |= len(cells) < 2 or cells[1].upper() != "VERIFIED"
                continue
        # A missing code read site is a source defect, even in an operator table.
        if cells and cells[0].startswith(("AGENTICDOME_", "AGENTIC_ORCHESTRATOR_")):
            if len(cells) < 2 or re.search(r"NOT ASSESSED|Not found|Unknown", cells[1], re.I):
                source_incomplete = True
        not_assessed = bool(re.search(r"\bNOT ASSESSED\b", line, re.I))
        operator_row = bool(cells and (
            cells[0].startswith(("AGENTICDOME_", "AGENTIC_ORCHESTRATOR_"))
            or (len(cells) == 4 and re.match(r"^[1-6]\.", cells[0]))
        ))
        if sections & OPERATOR_SECTIONS:
            activation_pending |= (not_assessed and operator_row) or bool(re.search(r"REQUIRED BEFORE LIVE|LIVE VERIFICATION PENDING|\bPENDING\b", line, re.I))
            # Arbitrary uninspected source prose cannot be hidden in handoff.
            source_incomplete |= not_assessed and not operator_row
        else:
            source_incomplete |= not_assessed
    source_incomplete |= structured and source_rows != 1
    return {"scope_incomplete": bool(source_incomplete), "activation_pending": bool(activation_pending)}
