#!/usr/bin/env bash
# ARDF one-command setup — run once per machine.
#   sudo ./setup.sh        (full: system tools + python deps into ./env)
#   ./setup.sh --no-apt    (python deps only, no sudo needed)
#
# Kali blocks system-wide pip (PEP 668), so Python deps always go into
# the project virtualenv ./env (created if missing). Run ARDF with:
#   ./env/bin/python ardf.py --preflight
#   ./env/bin/python ardf_v3_main.py --dashboard
set -euo pipefail
cd "$(dirname "$0")"

APT_TOOLS="hydra gobuster dirb hashcat metasploit-framework bloodhound responder python3-impacket nmap sqlmap nikto masscan amass subfinder nuclei john python3-flask-cors python3-reportlab python3-cloudscraper python3-selenium python3-pytest python3-pytest-asyncio"
PIP_REQS="requirements.txt"
VENV_DIR="./env"

if [[ "${1:-}" != "--no-apt" ]]; then
  echo "[*] Installing system tools (needs sudo)..."
  sudo apt-get update
  # shellcheck disable=SC2086
  sudo apt-get install -y $APT_TOOLS
else
  echo "[*] Skipping apt ( --no-apt ). Tool gaps will be reported by preflight."
fi

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "[*] Creating project virtualenv at $VENV_DIR ..."
  python3 -m venv "$VENV_DIR"
fi

# Best-effort venv fill (PyPI may be slow/blocked — apt packages above
# already cover every requirement, so a venv failure is non-fatal).
echo "[*] Trying Python deps into $VENV_DIR (non-fatal if offline)..."
set +e
timeout 240 "$VENV_DIR/bin/python" -m pip install -r "$PIP_REQS" 2>&1 | tail -2
set -e

echo "[*] Verifying with SYSTEM python (primary runtime)..."
/usr/bin/python3 - <<'PY'
import shutil
tools = ["nmap","sqlmap","hydra","gobuster","dirb","nikto","masscan","amass",
         "subfinder","nuclei","john","hashcat","msfconsole","bloodhound",
         "responder","secretsdump.py"]
missing = [t for t in tools if shutil.which(t) is None]
print("tools missing:", missing if missing else "none")
import importlib
for m in ["flask","flask_cors","yaml","rich","aiohttp","reportlab","argon2"]:
    try:
        importlib.import_module(m); print(f"py OK: {m}")
    except ImportError:
        print(f"py MISSING: {m}")
PY
echo "[*] Setup complete."
echo "    Run ARDF with system python, e.g.:"
echo "      /usr/bin/python3 ardf.py --preflight"
echo "      /usr/bin/python3 ardf_v3_main.py --dashboard"
