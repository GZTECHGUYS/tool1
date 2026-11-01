"""ARDF legacy entry point — forwards to the real CLI in ``ardf.py``.

History: this file used to construct ``ARDFOrchestrator`` with the wrong
signature and drive a hardcoded ``example.com`` attack chain with no
operator confirmation gate. Both problems are gone: this entry now simply
invokes the canonical CLI (``ardf.py``), which runs everything through
scope checks and the Tier-1/2/3 confirmation gates.

Usage (identical to ardf.py):
    python main.py --help
    python main.py --target example.com --mode osint
    python main.py --list-attacks
"""

import sys

from ardf import main as _ardf_main

if __name__ == "__main__":
    sys.argv[0] = "ardf.py"
    _ardf_main()
