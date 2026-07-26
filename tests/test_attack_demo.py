import runpy
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "attack_demo.py"


def test_attack_demo_catalog_includes_claude_smolagents_and_autogen():
    namespace = runpy.run_path(str(DEMO), run_name="agenticdome_attack_demo_test")
    frameworks = namespace["FRAMEWORKS"]
    scenarios = namespace["SCENARIOS"]

    assert frameworks["claude"]["platform"] == "claude_agent_sdk"
    assert "AgenticDomeClaudeFirewall" in frameworks["claude"]["snippet"]
    assert frameworks["smolagents"]["platform"] == "smolagents"
    assert "AgenticDomeSmolagentsFirewall" in frameworks["smolagents"]["snippet"]
    assert "generated_code_exfil" in scenarios
    assert frameworks["autogen"]["platform"] == "autogen"
    assert "AgenticDomeAutoGenFirewall" in frameworks["autogen"]["snippet"]
    assert "cross_agent_poisoning" in scenarios


@pytest.mark.parametrize(
    ("framework", "scenario", "label"),
    [
        ("claude", "metadata_exfil", "Anthropic Claude Agent SDK"),
        ("smolagents", "generated_code_exfil", "Hugging Face smolagents"),
        ("autogen", "cross_agent_poisoning", "Microsoft AutoGen"),
    ],
)
def test_framework_awareness_attack_demos_run_offline(framework, scenario, label):
    completed = subprocess.run(
        [sys.executable, str(DEMO), "--framework", framework, "--scenario", scenario],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert f"AgenticDome attack demo: {label}" in completed.stdout
    assert "Decision: BLOCKED" in completed.stdout
    assert "Tool executed: False" in completed.stdout
    assert "Outcome: the compromised agent is stopped before the dangerous tool executes." in completed.stdout
