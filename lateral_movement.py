"""Compatibility shim — real implementation lives in ``lateral_movement_executor``.

This file used to contain ``LateralMovementModule``: a fake lateral-movement
engine that invented ``success_rate`` numbers and "simulated network
discovery" without ever contacting a host. Per ``docs/MODULE_MAP.md`` this
legacy path is now a thin re-export of the canonical executor.
Do not extend this file.
"""

from lateral_movement_executor import (  # noqa: F401
    LateralMovementExecutor,
    Target,
)

__all__ = ["LateralMovementExecutor", "Target"]
