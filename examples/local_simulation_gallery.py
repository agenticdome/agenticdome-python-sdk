#!/usr/bin/env python3
"""Run AgenticDome's network-free allowed/blocked gallery.

With no arguments this exercises all supported Python integrations. Any normal
``agenticdome-demo`` arguments may be supplied to focus the run.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    os.environ["AGENTICDOME_MODE"] = "local_sim"
    for name in ("AGENTICDOME_API_BASE", "AGENTICDOME_API_KEY", "AGENTICDOME_TENANT_ID", "AGENTICDOME_BEARER_TOKEN"):
        os.environ.pop(name, None)

    sdk_root = Path(__file__).resolve().parents[1]
    if str(sdk_root) not in sys.path:
        sys.path.insert(0, str(sdk_root))

    from agenticdome_sdk.demo import main as demo_main

    arguments = sys.argv[1:] or ["--framework", "all", "--scenario", "both"]
    return demo_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())

