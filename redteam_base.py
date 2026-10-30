"""Canonical home moved to modules/redteam_base.py (single source of truth).

This shim keeps `import redteam_base` working. New code should use
`from modules.redteam_base import ...`.
"""
from modules.redteam_base import *  # noqa: F401,F403
from modules.redteam_base import (  # noqa: F401
    OpSecScore,
    RedTeamModule,
)
