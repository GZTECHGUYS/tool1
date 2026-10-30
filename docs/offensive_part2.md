# Offensive Expansion — Part 2 (saved brief)

More offensive modules + GUI improvements, stealth throughout.
Status: BRIEFED, not yet built.

## Modules (Part 2)
1. **Session-hijack prober** — scores session-theft exposure (cookie flags,
   Authorization leakage via referrer/logs/JS). No theft performed.
2. **API auth-matrix tester** — replays endpoints with stripped/expired/
   forged tokens, maps fail-open via status deltas. No data extraction.
3. **Subdomain-takeover prover** — dangling-CNAME fingerprints + harmless
   canary check, never claims the resource.
4. **Cloud-key spray surface** — scans JS/wayback finds for key patterns,
   validates shape only, never calls cloud APIs.
5. **RCE sink mapper** — classifies confirmed-injection sinks and produces
   the exact manual-escalation command; engine stops, human takes the shot.
6. **Browser-hook planner** — hook.js delivery planner for XSS-confirmed
   pages (OPSEC review, Tier-3, no auto-fire).

## GUI improvements (offensive + stealth only)
1. **Kill-chain timeline view** — findings on a recon→exploit→persist axis.
2. **Live OPSEC banner** — egress/profile/hostile signals always visible.
3. **Attack replay** — re-run chain transcripts step-by-step with diffs.
4. **Target switcher** — scope-aware header dropdown swapping full context.
5. **Dark-ops mode** — one-click quiet-profile + Tor rotate + egress check.

## Build order (when approved)
Session-hijack prober → auth-matrix → takeover prover → cloud-key
surface → sink mapper → hook planner → GUI items in listed order.
