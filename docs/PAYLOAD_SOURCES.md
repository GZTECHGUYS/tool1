# ARDF Web Payload Sources — 10 curated GitHub repos (read-only reference)
#
# These repos feed Burp Intruder / ffuf / manual testing. Clone selectively
# with tools/fetch_payloads.sh (shallow, per-repo). Nothing auto-downloads.
# All payloads are for AUTHORISED testing only.

| # | Repo | Covers | Use in ARDF |
|---|---|---|---|
| 1 | `swisskyrepo/PayloadsAllTheThings` | XSS, SQLi, SSTI, XXE, SSRF, LFI, deserialization, WAF bypass (master reference) | validator design, tamper ideas |
| 2 | `danielmiessler/SecLists` | Fuzzing/, passwords, usernames, discovery, web shells | `wordlists.yaml` primaries |
| 3 | `fuzzdb-project/fuzzdb` | Attack patterns: SQLi, XSS, traversal, format strings | validator payload cross-check |
| 4 | `foospidy/payloads` | Web attack payloads bundle (sqli/xss curated) | quick grep reference |
| 5 | `7ioSecurity/XSS-Payloads` | XSS vectors + filter evasions | xss validator extensions |
| 6 | `terjanq/Tiny-XSS-Payloads` | Minimal XSS (shortest vectors, WAF gaps) | WAF-evasion tests |
| 7 | `iamshafayat/WordlistsAllTheThings` | Bug-bounty wordlists: LFI, SSRF, CRLF, redirect, 403 bypass, JWT, API | surface + validators |
| 8 | `patuuh/Payloads-and-wordlists` | Burp Intruder-ready sets (XSS/XXE/LDAP/SQL/XPath/SSTI/Log4j) | intruder imports |
| 9 | `ogh-bnz/SecPayloads` | IDOR, HTMLi, dorks, WP, XOR | authz_mapper + dorking |
| 10 | `0ff-set/SecLists-2025-advanced` | 2025 packs: GraphQL, smuggling headers, SSRF internals | modern vectors |

Clone map (target dir under `/opt/ardf/payloads/`):

- PayloadsAllTheThings → `patt/` (docs only, ~200MB full)
- SecLists → `seclists/` (large; shallow clone recommended)
- fuzzdb → `fuzzdb/`
- foospidy/payloads → `foospidy/`
- 7ioSecurity/XSS-Payloads → `xss/`
- terjanq/Tiny-XSS-Payloads → `tiny-xss/`
- WordlistsAllTheThings → `watt/`
- patuuh/Payloads-and-wordlists → `intruder/`
- SecPayloads → `secpayloads/`
- SecLists-2025-advanced → `sec2025/`
