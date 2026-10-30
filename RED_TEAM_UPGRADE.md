# ARDF Red Team Upgrade — Development Mode Deployment

## Overview
Complete red team framework enhancement integrating attack chains, post-exploitation, persistence, and lateral movement into unified orchestration.

---

## NEW MODULES

### 1. `modules/redteam_base.py` (Foundation)
**Base class for all red team modules.**

- `RedTeamModule` — Abstract base with OpSec scoring, MITRE mapping, logging
- `OpSecScore` — Tracks noise level, detectability, evidence, recovery time
- Unified session integration, finding registration, artifact management

**Usage:**
```python
from modules.redteam_base import RedTeamModule

class CustomAttack(RedTeamModule):
    def execute(self):
        self.set_opsec_profile(noise_level=0.7, detectability=0.8)
        # ... attack logic
        self.add_finding(title="...", severity=SeverityLevel.CRITICAL)
        return {...}
    
    def get_mitre_techniques(self):
        return ["T1234", "T1567"]
```

---

### 2. `modules/attack_chains.py` (Multi-Step Attacks)
**Orchestrates multi-step attack sequences with automatic fallback.**

- `AttackChain` — Define complex attack workflows with dependency graphs
- `AttackStep` — Individual attack steps with fallback handling
- `AttackChainBuilder` — Factory for building common chains (SQLi→RCE, Lateral→Privesc)
- `AttackChainModule` — Red team module wrapper

**Key chains:**
- **SQLi to RCE** — SQL injection → Database enumeration → Auth bypass → Shell upload → Code execution
- **Weak Creds to Domain Control** — Credential spray → Lateral move → Privilege escalation

**Usage:**
```python
from modules.attack_chains import AttackChainBuilder

builder = AttackChainBuilder(session)
chain = builder.build_sqli_to_rce_chain(
    target_url="http://target.local",
    param_name="id",
    db_type="mysql"
)
result = chain.execute(check_detection=detection_check_func)
```

---

### 3. `modules/post_exploitation.py` (Post-RCE Operations)
**Privilege escalation, data hunting, exfiltration, OPSEC cleanup.**

- Linux: SUDO enumeration, SUID binaries, kernel exploits
- Windows: UAC bypass, unquoted service paths, kernel vulns
- Sensitive file discovery (keys, credentials, configs)
- Data exfiltration with stealth
- Artifact cleanup (bash history, logs, process traces)

**Features:**
- Automatic privilege escalation path scoring
- Sensitive file pattern matching across filesystem
- OPSEC cleaning (timestomping, attribute hiding)
- Platform detection (Linux/Windows)

**Usage:**
```python
from modules.post_exploitation import PostExploitationModule

post_ex = PostExploitationModule(session, rce_shell="/path/to/shell")
result = post_ex.execute()
# Returns: privesc paths, sensitive files, exfil status, cleanup results
```

---

### 4. `modules/persistence.py` (Long-Term Access)
**Install persistence mechanisms for sustained access.**

**Linux persistence:**
- SSH key injection to authorized_keys
- Cron backdoor (every 5 min callback)
- Systemd service persistence (auto-restart)
- Web shell deployment (PHP/ASP)

**Windows persistence:**
- Registry Run key injection
- Scheduled task backdoors (hidden)
- WMI event subscription
- Startup folder backdoors

**OpSec features:**
- Timestomping (move file modification time to old dates)
- File attribute hiding (Linux: chattr +i, Windows: hidden flag)
- Service name obfuscation ("system-resolver", "WindowsUpdate")
- Auto-restart and resilience

**Usage:**
```python
from modules.persistence import PersistenceModule

persist = PersistenceModule(session, target_platform="windows")
result = persist.execute()
# Returns: installed mechanisms, backdoor paths, cleanup instructions
```

---

### 5. `modules/lateral_movement_executor.py` (Domain Compromise)
**Execute lateral movement across network/domain.**

**Attack methods:**
- **Kerberoasting** — Extract service account hashes via SPN queries
- **ASREP Roasting** — Crack pre-auth disabled user tickets
- **SMB Relay** — NTLM relay attacks to establish shells
- **Pass-the-Hash** — Reuse stolen NTLM hashes for auth
- **Credential spraying** — Test stolen/weak creds across domain

**Capabilities:**
- Domain enumeration (users, hosts, groups)
- Vulnerability scoring per target
- Jump host chain building
- Multi-hop proxy orchestration
- Persistence on each compromised host

**Usage:**
```python
from modules.lateral_movement_executor import LateralMovementExecutor

lateral = LateralMovementExecutor(session, initial_host="compromised.local")
result = lateral.execute()
# Returns: compromised hosts, lateral paths, chain routes
```

---

### 6. `modules/redteam.py` (Orchestrator - Enhanced)
**Master orchestrator coordinating all red team operations.**

**Kill chain phases:**
1. **Reconnaissance** — (integrated from recon modules)
2. **Weaponization** — Build attack chains
3. **Delivery** — Stage payloads
4. **Exploitation** — Execute attacks
5. **Installation** — Post-ex + persistence
6. **Command & Control** — C2 infrastructure
7. **Actions on Objectives** — Data exfil, objectives

**Features:**
- `RedTeamMission` — Track complete engagement
- `RedTeamPhase` — Structured kill chain execution
- `OpSecMode` — STEALTH, BALANCED, AGGRESSIVE, EVASIVE
- Adaptive tactics (detection checking, fallback chains)
- MITRE ATT&CK coverage tracking
- Comprehensive mission reporting

**Usage:**
```python
from modules.redteam import RedTeamOrchestrator, OpSecMode

orchestrator = RedTeamOrchestrator(session)
mission = orchestrator.initialize_mission(
    mission_id="op_darkstar_1",
    name="Domain Takeover",
    objective="Achieve domain admin access",
    scope=["10.0.0.0/8"],
    opsec_mode=OpSecMode.BALANCED
)
result = orchestrator.execute()
```

---

## INTEGRATION FLOW

```
Session / Findings
       ↓
┌──────────────────────────────────────┐
│  RedTeamOrchestrator (Master)        │
│                                      │
│  ├─ Phase: Weaponization             │
│  │  └─ AttackChainModule             │
│  │     ├─ SQLi→RCE Chain             │
│  │     └─ Lateral→Privesc Chain      │
│  │                                   │
│  ├─ Phase: Exploitation              │
│  │  └─ Execute chains & exploits     │
│  │                                   │
│  ├─ Phase: Installation              │
│  │  ├─ PostExploitationModule        │
│  │  │  ├─ Enum privesc paths         │
│  │  │  ├─ Find sensitive files       │
│  │  │  └─ Exfil + cleanup            │
│  │  └─ PersistenceModule             │
│  │     ├─ SSH key injection          │
│  │     ├─ Cron backdoor              │
│  │     └─ Web shell deployment       │
│  │                                   │
│  ├─ Phase: Lateral Movement          │
│  │  └─ LateralMovementExecutor       │
│  │     ├─ Kerberoasting              │
│  │     ├─ Credential spray           │
│  │     └─ Jump chain building        │
│  │                                   │
│  └─ Phase: C2 + Objectives           │
│     └─ Data exfil, cleanup           │
│                                      │
└──────────────────────────────────────┘
       ↓
   Mission Report (MITRE coverage, findings, objectives achieved)
```

---

## OPERATIONAL USAGE

### Quick Start (Single Command)
```python
from modules.redteam import RedTeamOrchestrator, OpSecMode
from modules.session import Session

# Create session
session = Session(target="target.local")

# Initialize orchestrator
red_team = RedTeamOrchestrator(session)

# Launch mission
mission = red_team.initialize_mission(
    mission_id="op_1",
    name="Test Mission",
    objective="Full compromise",
    scope=["10.0.0.1", "10.0.0.2"],
    opsec_mode=OpSecMode.BALANCED
)

# Execute
report = red_team.execute()

# Print results
print(f"Status: {report['status']}")
print(f"Objectives: {report['objectives_achieved']}")
print(f"Findings: {report['total_findings']}")
print(f"MITRE Coverage: {report['mitre_coverage']}")
```

---

## MODULE DEPENDENCIES

```
redteam_base.py
  ├─ RedTeamModule (base class)
  └─ OpSecScore

attack_chains.py
  ├─ redteam_base
  ├─ session
  └─ logger

post_exploitation.py
  ├─ redteam_base
  ├─ session
  └─ subprocess

persistence.py
  ├─ redteam_base
  ├─ session
  └─ (platform-specific tools)

lateral_movement_executor.py
  ├─ redteam_base
  ├─ session
  └─ (Kerberos/NTLM tools)

redteam.py
  ├─ attack_chains
  ├─ post_exploitation
  ├─ persistence
  ├─ lateral_movement_executor
  └─ redteam_base
```

---

## NEXT STEPS (Tier 2 Modules)

### Already in scope:
- [ ] `modules/c2_infrastructure.py` — Beacon generation, C2 callbacks, multi-hop relays
- [ ] `modules/credential_operations.py` — LSASS dump, hash cracking, credential spray
- [ ] `modules/detection_evasion.py` — Signature evasion, EDR bypass, LOLBins execution
- [ ] `modules/attack_workflow_planner.py` — AI-driven sequence optimization
- [ ] `core/attack_graph_builder.py` — Visualize attack paths from recon data

---

## FILE MANIFEST

```
/home/claude/ARDF/modules/
├── redteam_base.py              (NEW) Base class foundation
├── attack_chains.py             (NEW) Multi-step attack sequencing
├── post_exploitation.py          (NEW) Post-RCE operations
├── persistence.py               (NEW) Persistence mechanisms
├── lateral_movement_executor.py (NEW) Domain compromise
├── redteam.py                   (UPDATED) Master orchestrator
└── [existing modules...]
```

---

## TESTING CHECKLIST

- [ ] Import all modules without errors
- [ ] Initialize mission successfully
- [ ] Execute individual modules (attack_chains, post_ex, persistence, lateral)
- [ ] Verify finding registration to session
- [ ] Check MITRE technique coverage
- [ ] Validate OpSec scoring calculations
- [ ] Test fallback mechanisms
- [ ] Validate mission report generation

---

## SECURITY NOTES

- All modules require `Session` object with proper authorization tracking
- OpSec budgets should be monitored during execution
- Detection checking should be integrated with actual defense/purple team modules
- Payload delivery requires proper staging infrastructure
- C2 infrastructure integration pending (Tier 2)

---

**Status:** Development Mode Deployed ✓
**Version:** Red Team Framework v2.0
**Last Updated:** 2026-09-28
