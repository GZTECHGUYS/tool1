# Offensive Expansion — Part 1 (saved brief)

All attack-side, no defense fluff. Status: BRIEFED, not yet built.

## 1. Initial access (new)
- **Password-spray engine** — low-and-slow spray across many users (1 attempt
  each, long jitter) vs current brute-force which hammers one account.
  Uses payload-DB credential lists.
- **AD enumeration pack** — Kerberoasting / AS-REP roasting candidate
  detection (SPN enumeration, `dontreqpreauth` flags) wired to the
  BloodHound ingest already in `attack_chains.py`.
- **File-upload bypass tester** — polyglot + MIME-mismatch probes against
  upload endpoints (detection: does the file persist + execute context,
  never drops a real shell).

## 2. Execution & persistence (new)
- **LOLBins catalog + runner** — trusted-binary abuse matrix per OS,
  Tier-3 generated commands for an existing agent session.
- **Scheduled-task/cron persistence builders** — generate-only artifacts
  (like track-cover scripts), delivered via agent, Tier-3 gated.

## 3. Lateral movement (extend)
- **SMB/RDP/WinRM relay prober** — NSE-backed read-only checks (signing
  enforced? NTLMv1?) producing a relayability matrix, never blind relays.
- **Jump-host pivoting planner** — consumes BloodHound shortest-paths +
  live sessions to propose pivot routes in the Attack Graph tab.

## 4. C2 & exfil (extend)
- **Dead-drop resolver** — gist/pastebin-style tasking fallback when direct
  C2 is burned (config-driven, Tier-3).
- **DNS/ICMP tunnel provers** — wire the v2 beacon classes to an opt-in
  live check with byte caps.

## 5. OPSEC for louder phases (pairs with all above)
- **Egress rotation per-phase** — Tor NEWNYM auto-trigger before
  password/relay phases, not just manual button.
- **Decoy traffic mixer** — interleave benign requests into scan/exploit
  runs so logs don't show pure attack sequences.

## Suggested build order
Spray engine → relay prober → LOLBins → pivoting planner → dead-drop →
decoy mixer.
