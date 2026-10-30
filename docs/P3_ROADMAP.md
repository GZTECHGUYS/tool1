# ARDF P3 — Posture & Validation Pack

Registry: `modules/attacks/p3_pack.py` · API: `/api/v3/attacks` · UI:
**Module Grid** (sci-fi console) or **Attack Runner**.

P3 adds 17 modules to the P1/P2 offensive registry (37 total). The pack is
deliberately split between **real, bounded checks** and **operator-gated
runbooks**, so the console stays useful without turning every click into an
unbounded action.

## Execution rules

| Tier | Meaning | Confirmation |
|------|---------|--------------|
| T1 | Read-only / DNS / TLS / header / banner observation | none |
| T2 | One active probe against an in-scope target | `APPROVE` (or `CONFIRM`) |
| T3 | State-changing or high-judgement action | typed `CONFIRM` |

Every module calls `require_in_scope()` before any network activity.
Network helpers cap timeouts and response bytes; secret evidence is redacted.

## Modules

| # | id | tier | status | notes |
|---|----|------|--------|-------|
| 1 | `tls_posture` | 1 | EXEC | certificate chain/expiry, self-signed, TLS version, cipher |
| 2 | `email_security_posture` | 1 | EXEC | SPF all-mechanism, DMARC policy, common DKIM selectors |
| 3 | `dns_hygiene` | 1 | EXEC | NS redundancy, MX, CAA, DNSSEC DS, duplicate SPF |
| 4 | `http_header_audit` | 1 | EXEC | HSTS/CSP/frame/MIME/referrer/permissions + cookie flags |
| 5 | `jwt_audit` | 2 | EXEC | alg=none, jku/x5u, missing exp/aud/iss, long lifetime |
| 6 | `cors_origin_audit` | 2 | EXEC | canary Origin, ACAO reflection, ACAC trust |
| 7 | `admin_panel_discovery` | 2 | EXEC | bounded 14-path admin/.git probe |
| 8 | `secret_leak_scan` | 1 | EXEC | up to 12 pages/JS assets, redacted cloud/token hits |
| 9 | `smb_signing_audit` | 2 | EXEC | tcp/445 + optional `smb2-security-mode` NSE |
| 10 | `ssh_posture_audit` | 1 | EXEC | banner/version family, no auth attempts |
| 11 | `graphql_introspection_audit` | 2 | EXEC | common GraphQL paths, schema exposure |
| 12 | `request_smuggling_plan` | 3 | _plan_ | CL.TE/TE.CL/TE.TE canary workflow |
| 13 | `cache_poison_plan` | 3 | _plan_ | unkeyed input + cache-key + purge workflow |
| 14 | `api_bola_plan` | 3 | _plan_ | two-account object-authorization differential |
| 15 | `cloud_metadata_plan` | 3 | _plan_ | IMDSv1/v2 + GCP/Azure reachability, no token theft |
| 16 | `adcs_esc_plan` | 3 | _plan_ | ESC1-ESC8 template audit |
| 17 | `supply_chain_plan` | 3 | _plan_ | typosquat/dependency confusion/CI tokens |

## Bug fixes landed with P3

* P2 modules now report `phase = P2` (previously every P2 module was listed
  under P1 because they inherited the P1 scaffold).
* Tier-2 `execute()` accepts a stronger typed `CONFIRM` as well as `APPROVE`.
* `/api/v3/attacks/run` merges top-level `mode`, `confirm_text` and `target`
  into `spec`, so the console's Tier-3 runner actually executes.
* `flask-cors` is optional; the console is same-origin by default and CORS is
  only enabled for explicit `ARDF_CORS_ORIGINS`.
* Dashboard auth key is read from config/env **before** the API object is
  constructed.
* `_count_methods` parsed `GET /path` incorrectly; it now counts Flask routes.
* `/api/v3/dashboard/telemetry` powers the new HUD without N+1 full scans.
* `secret_leak_scan` and `graphql_introspection_audit` now re-check every
  candidate URL, so URLs discovered in findings cannot pull the scanner
  out of scope. The secret scan is capped at 12 fetched URLs.
* The shared HTTP helper follows redirects manually and scope-checks every
  hop, closing the in-scope-to-third-party redirect pivot.
* `_host_of()` now strips ports from bare `host:port` values and handles
  userinfo/IPv6-style inputs; NXDOMAIN is no longer reported as a healthy
  domain with missing records.
* The command palette now filters on input, and an expired session closes the
  SSE stream before showing the login overlay.

## Console hardening (3.1.1)

* TUI phosphor theme is now the default deck; the HUD `THEME` button switches
  between `TUI` and `NEON` and persists the choice in `localStorage`.
* `index.html` loads `/app.js?v=3.1.1` and `/style.css?v=3.1.1`, so a stale
  browser cache cannot pair the new shell with an old console script.
* If `/app.js` never initializes, an inline watchdog shows a boot-failure
  banner instead of leaving the page on a blank/login frame.
* Boot now treats `/api/v3/audit` as informational, survives a failed scope
  lookup, and falls back to a usable overview card if telemetry errors.
* A 12-second boot watchdog converts a hung API call into a visible
  “Boot stalled” panel with Retry and Re-authenticate actions.
* Firefox and WebKit scrollbars are themed, removing the white native bars
  that appeared beside the sidebar and content pane.
* Dashboard startup probes the configured port before binding. If 5000 is
  taken by another local service, ARDF steps through 5001–5010 and prints the
  URL it actually bound instead of dying after module load.
