"""Compatibility shim — the real implementation lives in ``modules.attacks.base``.

Historically this module re-exported ``ardf.offensive.base``, a package that
was never shipped. It now forwards to the canonical attack-module base
(``AttackModule``, ``require_in_scope``) so legacy imports keep working.
Do not extend this file: see ``docs/MODULE_MAP.md``.
"""

from modules.attacks.base import AttackModule, require_in_scope  # noqa: F401

__all__ = ["AttackModule", "require_in_scope"]
