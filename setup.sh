#!/usr/bin/env bash
# ARDF setup — Kali tool provisioning, driven by modules/preflight.py
# (single source of truth: setup and `ardf.py --preflight` cannot drift).
#
# Usage:
#   ./setup.sh                  install everything missing (apt + final gate)
#   ./setup.sh --check          report only: exit 0 if ready, 1 if gaps
#   ./setup.sh --no-apt         skip apt; gate only (plus venv if requested)
#   ./setup.sh --venv           also create ./env virtualenv (optional)
#   ./setup.sh --with-wordlists also install seclists/wordlists
#
# Kali blocks system-wide pip (PEP 668): Python deps come from apt
# python3-* packages. System python (/usr/bin/python3) is the primary
# runtime; ./env is optional.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PY:-/usr/bin/python3}"
[[ -x "$PY" ]] || PY="$(command -v python3)"

APT=(apt-get)
if [[ "$(id -u)" -ne 0 ]]; then
  command -v sudo >/dev/null || { echo "need root or sudo for apt"; exit 1; }
  APT=(sudo apt-get)
fi

DO_APT=1; DO_VENV=0; DO_WORDS=0; MODE=install
for arg in "$@"; do
  case "$arg" in
    --check)          MODE=check ;;
    --no-apt)         DO_APT=0 ;;
    --venv)           DO_VENV=1 ;;
    --with-wordlists) DO_WORDS=1 ;;
    -h|--help)        grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg (see --help)"; exit 2 ;;
  esac
done

export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"

# Print the full preflight table; exit code = readiness (0 ready / 1 gaps).
run_check() {
  "$PY" - <<'PY'
import sys
sys.path.insert(0, ".")
from modules.preflight import check
r = check()
print("== tools ==")
for t in r["tools"]:
    mark = "ok  " if t["installed"] else "GAP "
    line = f"  [{mark}] {t['tool']:<16} {t['purpose']}"
    if not t["installed"]:
        line += f"   -> {t['fix']}"
    print(line)
print("== python deps ==")
for p in r["python"]:
    mark = "ok  " if p["installed"] else "GAP "
    line = f"  [{mark}] {p['package']:<16} {p['purpose']}"
    if not p["installed"]:
        line += f"   -> {p['fix']}"
    print(line)
cov = r.get("v2_coverage") or {}
if cov.get("count"):
    print(f"== v2 tool coverage: {cov.get('installed', 0)}/{cov['count']} ==")
print()
print("READY" if r["ready"] else f"NOT READY — {r['setup_hint']}")
sys.exit(0 if r["ready"] else 1)
PY
}

if [[ "$MODE" == "check" ]]; then
  run_check
  exit $?
fi

# ── install missing apt packages (derived from preflight, not hard-coded) ──
if [[ "$DO_APT" -eq 1 ]]; then
  echo "[*] Resolving missing packages from modules/preflight.py ..."
  MISSING="$("$PY" -c 'import sys; sys.path.insert(0, "."); from modules.preflight import missing_apt_packages; print(" ".join(missing_apt_packages()))')"
  if [[ -z "$MISSING" ]]; then
    echo "[*] all preflight packages already present"
  else
    echo "[*] apt packages to install: $MISSING"
    "${APT[@]}" update
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive "${APT[@]}" install -y $MISSING
  fi
  if [[ "$DO_WORDS" -eq 1 ]]; then
    # seclists is ~545MB download / ~2GB installed — only attempt when the
    # disk can actually take it (a failed unpack leaves dpkg noise).
    FREE_MB=$(df -m --output=avail / | tail -1 | tr -d ' ')
    if [[ "$FREE_MB" -ge 2600 ]]; then
      echo "[*] installing wordlists (optional)..."
      DEBIAN_FRONTEND=noninteractive "${APT[@]}" install -y seclists wordlists \
        || echo "[!] wordlists package failed (optional, continuing)"
    else
      echo "[!] only ${FREE_MB}MB free; seclists needs ~2600MB — skipping"
      echo "    (gobuster falls back to /usr/share/dirb/wordlists/common.txt)"
      DEBIAN_FRONTEND=noninteractive "${APT[@]}" install -y wordlists \
        || echo "[!] wordlists package failed (optional, continuing)"
    fi
  fi
else
  echo "[*] --no-apt: skipping package installation"
fi

# ── optional virtualenv (system python stays primary on Kali) ──
if [[ "$DO_VENV" -eq 1 ]]; then
  if [[ ! -x ./env/bin/python ]]; then
    echo "[*] creating ./env virtualenv..."
    if ! "$PY" -m venv ./env 2>/dev/null; then
      if [[ "$DO_APT" -eq 1 ]]; then
        DEBIAN_FRONTEND=noninteractive "${APT[@]}" install -y python3-venv
        "$PY" -m venv ./env
      else
        echo "[!] cannot create venv (python3-venv missing; --no-apt set)"
      fi
    fi
  fi
  if [[ -x ./env/bin/python ]]; then
    echo "[*] filling ./env from requirements.txt (best effort)..."
    set +e
    timeout 240 ./env/bin/python -m pip install -r requirements.txt >/dev/null 2>&1
    set -e
  fi
fi

# ── final gate: the same preflight that `ardf.py --preflight` runs ──
echo
echo "[*] preflight gate:"
if run_check; then
  echo "[*] setup complete — run ARDF with system python:"
  echo "      $PY ardf.py --preflight"
  echo "      $PY ardf_v3_main.py --dashboard"
else
  echo "[!] setup finished with gaps — see fixes above."
  exit 1
fi
