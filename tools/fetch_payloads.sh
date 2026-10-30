#!/usr/bin/env bash
# Fetch ARDF web-payload repos (selective shallow clones).
# Usage: sudo tools/fetch_payloads.sh [all|small|DIR...]
#   all    - all 10 repos (SecLists/PATT are big; allow time + disk)
#   small  - only the 8 lightweight repos (skip SecLists + PATT)
#   default: small
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${ARDF_PAYLOADS:-$ROOT/payloads}"
mkdir -p "$DEST"
cd "$DEST"

clone() { # $1=dir $2=url — never aborts the batch on one failure
  if [[ -d "$1/.git" ]]; then echo "== $1 exists, pull =="; git -C "$1" pull --ff-only || true
  else echo "== cloning $1 =="; git clone --depth 1 "$2" "$1" || echo "!! $1 FAILED, continuing"; fi
}
SMALL_ONLY=true; [[ "${1:-small}" == "all" ]] && SMALL_ONLY=false

clone foospidy    https://github.com/foospidy/payloads
clone xss         https://github.com/7ioSecurity/XSS-Payloads
clone tiny-xss    https://github.com/terjanq/Tiny-XSS-Payloads
clone watt        https://github.com/iamshafayat/WordlistsAllTheThings
clone intruder    https://github.com/patuuh/Payloads-and-wordlists
clone secpayloads https://github.com/ogh-bnz/SecPayloads
clone sec2025     https://github.com/0ff-set/SecLists-2025-advanced
clone fuzzdb      https://github.com/fuzzdb-project/fuzzdb
if [[ "$SMALL_ONLY" == false ]]; then
  clone seclists  https://github.com/danielmiessler/SecLists
  clone patt      https://github.com/swisskyrepo/PayloadsAllTheThings
fi
echo "payloads at $DEST"; du -sh "$DEST"/*
