"""Compatibility shim — the real implementation lives in ``modules.attacks``.

Historically this module re-exported ``ardf.offensive.runner``, a package that
was never shipped. It now forwards to the canonical tier-gated attack
registry (``list_attacks`` / ``run_attack``) so legacy imports keep working.
Do not extend this file: see ``docs/MODULE_MAP.md``.
"""

from modules.attacks import (  # noqa: F401
    get_attack,
    list_attacks,
    run_attack,
)

__all__ = ["get_attack", "list_attacks", "run_attack"]
