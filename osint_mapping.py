"""Canonical home moved to modules/osint_mapping.py (single source of truth).

This shim keeps `import osint_mapping` working. New code should use
`from modules.osint_mapping import ...`.
"""
from modules.osint_mapping import *  # noqa: F401,F403
