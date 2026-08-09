"""Runtime-mode helpers shared by the core client and framework adapters."""

from __future__ import annotations

import os
from typing import Optional


LIVE_MODE = "live"
LOCAL_SIM_MODE = "local_sim"
SUPPORTED_MODES = {LIVE_MODE, LOCAL_SIM_MODE}


def resolve_mode(value: Optional[str] = None) -> str:
    """Return a validated SDK mode without silently changing live behavior."""
    mode = str(value if value is not None else os.getenv("AGENTICDOME_MODE", LIVE_MODE)).strip().lower()
    if mode not in SUPPORTED_MODES:
        raise ValueError("AGENTICDOME_MODE must be 'live' or 'local_sim'")
    if mode == LOCAL_SIM_MODE and str(os.getenv("AGENTICDOME_PRODUCTION_MODE", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        raise ValueError("AGENTICDOME_MODE=local_sim is refused when AGENTICDOME_PRODUCTION_MODE=true")
    return mode


def is_local_sim_mode(value: Optional[str] = None) -> bool:
    return resolve_mode(value) == LOCAL_SIM_MODE


def credentials_or_local_sim(api_base: str, api_key: str, tenant_id: str) -> bool:
    """Adapters may omit cloud credentials only in the explicit simulation mode."""
    return is_local_sim_mode() or bool(str(api_base).strip() and str(api_key).strip() and str(tenant_id).strip())
