#!/usr/bin/env python3
"""
ARDF v2 Configuration Files
All configuration in one place - copy to config/ directory
"""

ARDF_MAIN_CONFIG = """
# ARDF v2 Configuration
# Complete red team automation framework

ardf:
  version: "2.0"
  name: "ARDF v2 - Advanced Red Team Delivery Framework"
  
engagement:
  # Engagement settings
  timeout_days: 7
  confirmation_required: true
  auto_escalate: true
  max_agents: 100
  
  # Engagement phases
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
  # C2 Infrastructure
  primary_server: "c2.attacker.com"
  primary_port: 443
  
  beacons:
    https:
      enabled: true
      port: 443
      certificate_path: "/path/to/cert.pem"
      jitter: 10  # seconds
      sleep_interval: 60  # seconds
    
    dns:
      enabled: true
      domain: "exfil.attacker.com"
      nameserver: "8.8.8.8"
      
    icmp:
      enabled: true
      attacker_ip: "203.0.113.1"
      
    websocket:
      enabled: true
      url: "wss://c2.attacker.com/ws"
      
    p2p:
      enabled: true
      peers:
        - "peer1.com"
        - "peer2.com"
  
  failover:
    primary: "https://c2.attacker.com:443"
    backup_1: "dns://exfil.attacker.com"
    backup_2: "icmp://attacker.com"

reconnaissance:
  # Reconnaissance capabilities
  tools:
    nmap:
      enabled: true
      aggressive: true
      timing: "T4"  # T0-T5
      
    shodan:
      enabled: true
      api_key: "${SHODAN_API_KEY}"
      
    amass:
      enabled: true
      config_file: "/path/to/amass.config"

scanning:
  # Scanning & enumeration
  tools:
    burp:
      enabled: true
      url: "http://localhost:8090"
      api_key: "${BURP_API_KEY}"
      scan_type: "crawl_and_audit"
      
    nessus:
      enabled: false
      url: "https://nessus.internal"
      
    openvas:
      enabled: false
      
    active_directory:
      enabled: true
      domain: "corp.local"
      dc: "dc.corp.local"

exploitation:
  # Exploitation frameworks
  web:
    sqli: true
    xss: true
    ssti: true
    xxe: true
    ssrf: true
    jwt: true
    cors: true
    oauth: true
    graphql: true
    crlf: true
    http_smuggle: false
    
  cloud:
    s3_enum: true
    iam_privesc: true
    azure_ad: true
    lambda: true
    
  identity:
    kerberos: true
    ldap: true
    saml: false
    azure_oauth: true
    
  network:
    smb_relay: true
    llmnr_poison: true
    dns_poison: false

persistence:
  # Persistence mechanisms
  windows:
    registry_run_key: true
    scheduled_task: true
    wmi_event: true
    dll_injection: true
    startup_folder: true
    
  linux:
    cron_job: true
    ssh_keys: true
    systemd_service: true
    kernel_module: false
    
  cloud:
    iam_user: true
    lambda_backdoor: true
    api_gateway: true

post_exploitation:
  # Post-exploitation
  lateral_movement:
    kerberoasting: true
    asreproasting: true
    pass_the_hash: true
    golden_ticket: true
    dcsync: true
    
  exfiltration:
    https: true
    dns_tunnel: true
    icmp_tunnel: false
    cloud_storage: true
    steganography: false

evasion:
  # Evasion techniques
  process_level:
    process_hollowing: true
    dll_injection: true
    reflective_injection: true
    direct_syscalls: true
    
  kernel:
    callback_disable: false  # Requires driver
    driver_deployment: false
    
  security_bypass:
    etw_bypass: true
    amsi_bypass: true
    defender_disable: true
    
  artifact_elimination:
    delete_event_logs: true
    delete_web_logs: true
    clear_temp: true
    timestamp_manipulation: true
    
  detection_evasion:
    sandbox_detection: true
    behavior_evasion: true
    ml_evasion: false

reporting:
  # Reporting
  formats:
    - json
    - html
    - pdf
    
  reports:
    executive_summary: true
    technical_report: true
    compliance_analysis: true
    remediation_roadmap: true
    evidence_package: true
    
  output_dir: "/tmp/ardf_reports"

logging:
  # Logging configuration
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "/tmp/ardf_engagement.log"
  console: true
  format: "[%(levelname)s] %(asctime)s - %(message)s"

security:
  # Security settings
  encryption_key: "${ENCRYPTION_KEY}"
  verify_ssl: false  # For testing only
  timeout: 30
  retries: 3
"""

PLAYBOOK_FULL_ENGAGEMENT = """
# ARDF v2 Playbook - Full Red Team Engagement
# Automated complete attack chain

playbook:
  name: "Full Red Team Engagement"
  description: "Complete 247-capability red team assessment"
  duration_days: 7
  
stages:
  
  # Stage 1: Reconnaissance
  - stage: 1
    name: "Reconnaissance & Intelligence Gathering"
    duration_hours: 8
    capabilities:
      - subdomain_enumeration
      - email_harvesting
      - whois_footprinting
      - ssl_cert_enum
      - cloud_detection
      - api_enumeration
      - tech_stack_detection
      - cdn_detection
      - breached_database_check
    
  # Stage 2: Scanning
  - stage: 2
    name: "Scanning & Vulnerability Discovery"
    duration_hours: 12
    capabilities:
      - port_scanning
      - service_enumeration
      - vulnerability_scanning
      - web_app_scanning
      - directory_discovery
      - cloud_enum
      - kerberos_enum
      - ldap_enum
    conditions:
      - "Reconnaissance complete"
    
  # Stage 3: Exploitation
  - stage: 3
    name: "Exploitation & Initial Access"
    duration_hours: 6
    capabilities:
      - sql_injection
      - xss_exploitation
      - ssti
      - xxe_exploitation
      - ssrf_exploitation
      - jwt_exploitation
      - oauth_bypass
      - cloud_exploitation
    conditions:
      - "Scanning complete"
      - "Vulnerabilities identified"
    
  # Stage 4: Persistence
  - stage: 4
    name: "Persistence Establishment"
    duration_hours: 2
    capabilities:
      - registry_persistence
      - scheduled_task_persistence
      - wmi_persistence
      - dll_injection_persistence
      - cron_persistence
    conditions:
      - "Initial access established"
    
  # Stage 5: Lateral Movement
  - stage: 5
    name: "Lateral Movement & Privilege Escalation"
    duration_hours: 8
    capabilities:
      - credential_theft
      - kerberoasting
      - pass_the_hash
      - golden_ticket
      - dcsync
      - pivot_to_dc
      - domain_admin_access
    conditions:
      - "Persistence established"
    
  # Stage 6: Data Collection
  - stage: 6
    name: "Data Identification & Exfiltration"
    duration_hours: 6
    capabilities:
      - database_enumeration
      - sensitive_file_discovery
      - credential_harvesting
      - data_extraction
      - https_exfiltration
      - dns_tunnel_exfiltration
    conditions:
      - "Domain admin access achieved"
    
  # Stage 7: Evasion
  - stage: 7
    name: "Anti-Forensics & Track Covering"
    duration_hours: 2
    capabilities:
      - log_deletion
      - artifact_cleanup
      - timestamp_manipulation
      - track_covering
    conditions:
      - "Data exfiltration complete"
    
  # Stage 8: Reporting
  - stage: 8
    name: "Evidence Collection & Reporting"
    duration_hours: 8
    capabilities:
      - evidence_collection
      - screenshot_capture
      - report_generation
      - compliance_analysis
      - remediation_planning
    conditions:
      - "Evasion complete"

# Success Metrics
success_criteria:
  - "Full domain compromise achieved"
  - "Domain admin access obtained"
  - "50,000+ records exfiltrated"
  - "Persistence established on 5+ systems"
  - "Undetected for 4+ days"
  - "Evidence collected and documented"
  - "Comprehensive report delivered"
"""

MISSION_PROFILE = """
# ARDF v2 Mission Profile
# Define specific engagement parameters

mission:
  name: "Example Corp - Full Assessment"
  target: "192.168.1.0/24"
  engagement_type: "Full Red Team"
  
  scope:
    include:
      - "Internal network"
      - "Web applications"
      - "Cloud (AWS)"
      - "Active Directory"
    exclude:
      - "Production databases"
      - "Payment systems"
      - "Emergency services"
  
  constraints:
    business_hours_only: false
    avoid_denial_of_service: true
    preserve_data_integrity: true
    
  team:
    lead: "Red Team Lead"
    operators: 3
    analysts: 2
    
  timeline:
    start_date: "2024-01-15"
    end_date: "2024-01-22"
    daily_operations: "9 AM - 5 PM"
    
  objectives:
    - "Identify critical vulnerabilities"
    - "Demonstrate full domain compromise"
    - "Measure detection capabilities"
    - "Assess incident response"
    - "Provide remediation guidance"
"""

if __name__ == '__main__':
    import os
    from pathlib import Path
    
    config_dir = Path('/tmp/ardf_config')
    config_dir.mkdir(exist_ok=True)
    
    # Write configurations
    with open(config_dir / 'ardf.yaml', 'w') as f:
        f.write(ARDF_MAIN_CONFIG)
    
    with open(config_dir / 'playbook.yaml', 'w') as f:
        f.write(PLAYBOOK_FULL_ENGAGEMENT)
    
    with open(config_dir / 'mission.yaml', 'w') as f:
        f.write(MISSION_PROFILE)
    
    print(f"[+] Configuration files written to {config_dir}")
    print(f"    - ardf.yaml (main configuration)")
    print(f"    - playbook.yaml (full engagement playbook)")
    print(f"    - mission.yaml (mission parameters)")
