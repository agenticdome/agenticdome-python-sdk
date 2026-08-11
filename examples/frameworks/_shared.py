"""Shared network-free runner for the public framework gallery."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def run(framework: str) -> int:
    os.environ["AGENTICDOME_MODE"] = "local_sim"
    for name in ("AGENTICDOME_API_BASE", "AGENTICDOME_API_KEY", "AGENTICDOME_TENANT_ID", "AGENTICDOME_BEARER_TOKEN"):
        os.environ.pop(name, None)

    sdk_root = Path(__file__).resolve().parents[2]
    if str(sdk_root) not in sys.path:
        sys.path.insert(0, str(sdk_root))

    from agenticdome_sdk.demo import main as demo_main

    return demo_main(["--framework", framework, "--scenario", "both"])

