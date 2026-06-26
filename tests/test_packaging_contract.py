import ast
import importlib.metadata
import pathlib
import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback for local dev only
    tomllib = None


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_pyproject():
    if tomllib is None:
        pytest.skip("tomllib is unavailable on this Python runtime")
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_pyproject_is_the_single_packaging_metadata_source():
    project = load_pyproject()["project"]
    setup_py = (ROOT / "setup.py").read_text(encoding="utf-8")

    assert project["name"] == "agenticdome-python-sdk"
    assert project["version"] == "1.1.1"
    assert "AgenticDome" in project["description"]
    assert "AgentGuard Intelligence Engine" not in project["description"]

    tree = ast.parse(setup_py)
    setup_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "setup"
    ]
    assert len(setup_calls) == 1
    assert setup_calls[0].keywords == []
    assert "version=" not in setup_py
    assert "install_requires" not in setup_py


def test_distribution_metadata_matches_pyproject_when_installed():
    project = load_pyproject()["project"]

    try:
        installed = importlib.metadata.metadata(project["name"])
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("agenticdome-python-sdk is not installed in this environment")

    assert installed["Name"] == project["name"]
    assert installed["Version"] == project["version"]


def test_public_package_exports_are_importable():
    from agenticdome_sdk import (
        AgentGuardClient,
        AgentGuardError,
        AgentGuardHTTPError,
        GuardrailClient,
    )

    assert GuardrailClient is AgentGuardClient
    assert issubclass(AgentGuardHTTPError, AgentGuardError)


def test_manifest_and_ignore_files_keep_release_artifacts_out_of_source_contract():
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    for required in ["include README.md", "include LICENSE", "include pyproject.toml", "include setup.py"]:
        assert required in manifest

    for ignored in ["build/", "dist/", "*.egg-info/", "__pycache__/", ".pytest_cache/"]:
        assert ignored in gitignore

    forbidden_manifest_entries = ["recursive-include build", "recursive-include dist", "recursive-include *.egg-info"]
    for forbidden in forbidden_manifest_entries:
        assert forbidden not in manifest


def test_project_extras_cover_documented_frameworks():
    project = load_pyproject()["project"]
    extras = project["optional-dependencies"]

    expected = {
        "crewai",
        "redis",
        "pydanticai",
        "langgraph",
        "microsoft",
        "foundry",
        "agno",
        "openai-agents",
        "mcp",
        "bedrock",
        "llamaindex",
        "google-adk",
        "all",
        "dev",
    }
    assert expected.issubset(extras)
    assert "pytest>=8.0.0" in extras["dev"]
    assert "build>=1.0.0" in extras["dev"]

def test_readme_documents_framework_verification_matrix():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "## Package Build and Verification" in readme
    assert "### Framework Test Matrix" in readme
    assert "tests/test_live_tenant.py" in readme

    for test_file in [
        "tests/test_client.py",
        "tests/test_packaging_contract.py",
        "tests/test_crewai_integration.py",
        "tests/test_pydanticai_integration.py",
        "tests/test_langgraph_integration.py",
        "tests/test_microsoft_agent_framework_integration.py",
        "tests/test_microsoft_ai_foundry_integration.py",
        "tests/test_openai_agents_integration.py",
        "tests/test_agno_integration.py",
        "tests/test_mcp_host_integration.py",
        "tests/test_aws_bedrock_integration.py",
        "tests/test_google_adk_integration.py",
        "tests/test_llamaindex_integration.py",
    ]:
        assert test_file in readme

