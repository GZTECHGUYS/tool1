# ARDF Offensive Module Tracker (P1 + P2)

Registry: `modules/attacks/` · API: `/api/v3/attacks` · UI: **Attacks** tab.
Status legend: `_plan_` = scaffolded (plan + runbook), **EXEC** = performs
real action after tier gate, WIP = in progress, DONE = verified live.

## P1 (saved 2026-10-23)

| # | id | status | notes |
|---|----|--------|-------|
| 1 | subdomain_takeover        | EXEC | verify dangling CNAME -> provider fingerprint; S3-style providers claimed for real after CONFIRM (canary index.html); owner-only providers return runbook |
| 2 | ad_enum_builder           | _plan_ | LDAP SPN/AS-REP/delegation audit; crack hook to credential_operations |
| 3 | mfa_sso_chain             | _plan_ | OAuth state/nonce, EWS NTLM forced-auth, relay via proxy_chain |
| 4 | container_k8s             | _plan_ | kubelet 10250 / etcd 2379 / RBAC graph |
| 5 | deserial_factory          | _plan_ | JNDI/ViewState/pickle, canary-gated classes |
| 6 | ssh_key_reuse             | EXEC  (paramiko key try-once across loot keys) |
| 7 | wifi_adjacency            | EXEC | live survey via `iw`/`nmcli`/Termux radio; rogue-AP/evil-twin + open/WEP/WPS posture; allow-listed PMKID capture (hashcat 22000); needs auth ref |
| 8 | c2_macro_chain            | _plan_ | stager builder -> ardf_v2_c2_infrastructure |
| 9 | password_spray            | EXEC  (lockout-aware, validate/auth.test_credentials) |
| 10| persistence_check         | _plan_ | dry-run persistence, sandbox-only reboot test |

## P2 (added 2026-10-23)

| # | id | status | notes |
|---|----|--------|-------|
| 11| cicd_pipeline             | _plan_ | GH Actions/GitLab runner, .git leak, artifact secrets |
| 12| cloud_iam_planner         | _plan_ | AssumeRole/impersonation graph -> ops.chains spec |
| 13| cloud_storage_audit       | EXEC  (s3_enum + bucket-family claims test) |
| 14| graphql_deep              | _plan_ | introspection, alias batching, suggestions |
| 15| dns_attack                | _plan_ | AXFR, wildcard/lame delegation, rebinding PoC |
| 16| vpn_appliance             | _plan_ | SonicWall/Citrix/Fortinet/Pulse banner-CVE match |
| 17| session_tokens            | _plan_ | cookie attrs, entropy, oauth state checks |
| 18| firmware_audit            | _plan_ | binwalk/entropy, hardcoded keys, OTA sig |
| 19| exposed_services          | EXEC  (banner walk docker/redis/winrm/elastic/mongo/memcached/consul/epmd) |
| 20| lateral_planner           | _plan_ | cred inventory + RDP/WinRM/SMB graph -> chain |

## Takeover execution rule (confirmed by operator)

Detection-only is a finding; when CONFIRM is issued the tier-3 action
PERFORMS the takeover for claimable providers:
- claim resource (S3 bucket by name) -> serve canary index.html (track_cover tokens)
- `TAKEOVER PERFORMED` finding (CRITICAL) written to session
- revert = delete claimed resource; runbook column lists provider-specific manual step
- requires AWS credentials available to the server process (env/profile)

## Next

- [ ] TUI (`ardf_tui.py`, textual) — same registry + job streams
- [ ] remove dependence on `requests verify=False` (pin CA bundle)
- [ ] creds pick-up standard: loot dir convention for ssh_key_reuse
- [ ] move EXEC statuses from _plan_ to EXEC as each executes() is built
