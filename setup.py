from pathlib import Path

from setuptools import find_packages, setup


ROOT = Path(__file__).parent
README = ROOT / "README.md"

setup(
    name="agenticdome-python-sdk",
    version="1.0.1",
    description="Python SDK for AgenticDome AI security, guardrails, A2A, MCP, CrewAI, and enterprise agent governance APIs.",
    long_description=README.read_text(encoding="utf-8") if README.exists() else "",
    long_description_content_type="text/markdown",
    author="AgenticDome",
    license="MIT",
    url="https://github.com/agenticdome/agenticdome-python-sdk-python",
    project_urls={
        "Homepage": "https://github.com/agenticdome/agenticdome-python-sdk-python",
        "Source": "https://github.com/agenticdome/agenticdome-python-sdk-python",
        "Issues": "https://github.com/agenticdome/agenticdome-python-sdk-python/issues",
        "Console": "https://au.agenticdome.io",
    },
    packages=find_packages(include=["agenticdome_sdk", "agenticdome_sdk.*"]),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "crewai": [
            "crewai",
        ],
        "redis": [
            "redis>=4.5.0",
        ],
         "pydanticai": [
        "pydantic-ai",
        "anyio>=4.0.0",
        ],
        "pydantic": [
        "pydantic-ai",
        "anyio>=4.0.0",
        ],
        "all": [
            "crewai",
            "redis>=4.5.0",
            "pydantic-ai",
            "anyio>=4.0.0",
        ],
        "dev": [
            "build",
            "twine",
            "pytest",
            "ruff",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords=[
        "agenticdome",
        "agentguard",
        "ai-security",
        "guardrails",
        "crewai",
        "mcp",
        "a2a",
        "llm-security",
    ],
)
