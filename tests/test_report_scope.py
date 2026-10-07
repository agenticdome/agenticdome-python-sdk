import json
from pathlib import Path

import pytest

from agenticdome_sdk.report_scope import assessment_scope


CASES = json.loads((Path(__file__).parent / "fixtures/report_scope.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_source_scope_and_operator_activation_have_distinct_gates(case):
    assert assessment_scope(case["markdown"]) == {
        "scope_incomplete": case["scope_incomplete"],
        "activation_pending": case["activation_pending"],
    }
