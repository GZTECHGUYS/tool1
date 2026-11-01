# ARDF Module Map — canonical import surface (E23)

Single source of truth per capability. Legacy paths still import (shims)
but new code must use the **canonical** column.

| Capability | Canonical | Legacy shim (do not extend) |
|---|---|---|
| Red-team base classes | `modules.redteam_base` | `redteam_base` (re-exports) |
| OSINT mapping | `modules.osint_mapping` | `osint_mapping` (re-exports), `OSINT_INTEGRATION` (guide) |
| Red-team orchestration | `modules.redteam` | `redteam` (flat, historical) |
| Attack chains | `attack_chains` | — |
| C2 | `ardf_v2_c2_infrastructure` (`C2Controller`, `BeaconListener`, `HTTPSBeacon`) + `ops.c2` (sync API, listener lifecycle) | `c2_infrastructure` (deleted in WS-1) |
| Payload delivery | `ardf_v2_payload_delivery` + `modules.payloads` (profiles) | — |
| v2 hub (every ardf_v2_* wired) | `ops/v2.py` → `/api/v3/v2/*`, preflight `v2_coverage`, recon CT | — |
| Evasion | `ardf_v2_evasion_complete` + `modules.opsec_profiles` | `detection_evasion` (flat, historical) |
| Persistence / privesc / post-ex | `persistence`, `privilege_escalation`, `post_exploitation` | — |
| Lateral movement | `lateral_movement_executor` (runner) | `lateral_movement` (thin) |
| Credentials | `credential_operations` | — |
| Framework models (v3 lib) | `complete_framework` (re-exported via `core`) | — |
| Orchestration | `core.orchestrator.Orchestrator` | `ardf_v2_orchestrator_complete`, `ardf_v3_framework` |
| Dashboard backend | `ops.jobs`, `ops.scope`, `ops.auth`, `ops.c2` | — |
| Preflight | `modules.preflight` | — |
| Verification loop | `modules.verify` | — |
| Loot / exfil | `modules.loot`, `modules.exfil_ledger` | — |
| PDF / remediation | `modules.pdf_report` | — |
| Intel enrich | `modules.intel_enrich` | — |
| Attack modules (tier-gated) | `modules.attacks` (`p1_pack`–`p4_pack`, `base.require_in_scope`) | flat attack files (deleted in WS-1) |
| API keys (Settings) | `modules.apikeys` (env → `config/api_keys.yaml` 0600 → ardf.yaml) | `ardf.yaml api_keys` placeholders (still honoured) |
| Setup / provisioning | `setup.sh` driven by `modules.preflight.missing_apt_packages()` | — |

## Rules for new code
1. New modules live under `modules/`, `ops/`, `core/`, `ai/`, `graph/`, `daemon/` or `playbook/`.
2. No new top-level `ardf_*` snapshots — extend in place.
3. Every new module must import cleanly standalone (lazy-load heavy deps).
4. Every new capability gets: dashboard endpoint + smoke-test coverage.
