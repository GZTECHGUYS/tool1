"""Reconnaissance modules for ARDF v3."""

import asyncio
from typing import List

from core import (
    OffensiveModule, Finding, ExecutionContext, FindingType,
    TacticType
)


class PassiveReconModule(OffensiveModule):
    """Passive reconnaissance and OSINT gathering."""
    
    module_name = "passive_recon"
    module_version = "1.0.0"
    description = "Passive information gathering without target interaction"
    
    finding_types = [FindingType.RECONNAISSANCE]
    tactics = [TacticType.RECONNAISSANCE]
    required_access = "unauthenticated"
    timeout_seconds = 120
    
    async def execute(self, context: ExecutionContext) -> List[Finding]:
        """Execute passive reconnaissance."""
        findings = []
        
        # WHOIS lookup
        whois = await self._whois_lookup(context.target)
        whois_finding = self._create_finding(
            title=f"WHOIS data for {context.target}",
            description=f"Retrieved WHOIS registration data",
            finding_type=FindingType.RECONNAISSANCE,
            evidence=whois,
            severity="low",
        )
        findings.append(whois_finding)
        
        # DNS records
        dns = await self._dns_lookup(context.target)
        for record_type, records in dns.items():
            dns_finding = self._create_finding(
                title=f"{record_type} records for {context.target}",
                description=f"Found {len(records)} {record_type} records",
                finding_type=FindingType.RECONNAISSANCE,
                evidence={"record_type": record_type, "records": records},
                severity="low",
            )
            findings.append(dns_finding)
        
        # SSL certificate data
        cert = await self._ssl_cert_info(context.target)
        cert_finding = self._create_finding(
            title=f"SSL certificate enumerated for {context.target}",
            description="Retrieved certificate details and SANs",
            finding_type=FindingType.RECONNAISSANCE,
            evidence=cert,
            severity="low",
        )
        findings.append(cert_finding)
        
        return findings
    
    async def _whois_lookup(self, domain: str) -> dict:
        """Simulate WHOIS lookup."""
        await asyncio.sleep(0.1)
        return {
            "registrar": "GoDaddy",
            "registered": "2018-03-15",
            "updated": "2023-01-20",
            "registrant_country": "US",
        }
    
    async def _dns_lookup(self, domain: str) -> dict:
        """Simulate DNS lookup."""
        await asyncio.sleep(0.1)
        return {
            "A": ["192.168.1.100"],
            "MX": ["mail.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 include:_spf.google.com ~all"],
        }
    
    async def _ssl_cert_info(self, domain: str) -> dict:
        """Simulate SSL certificate retrieval."""
        await asyncio.sleep(0.1)
        return {
            "issuer": "Let's Encrypt",
            "subject": f"CN={domain}",
            "valid_from": "2023-01-01",
            "valid_to": "2024-01-01",
            "san": [f"www.{domain}", f"api.{domain}"],
        }


class ActiveScanModule(OffensiveModule):
    """Active scanning and probing."""
    
    module_name = "active_scan"
    module_version = "1.0.0"
    description = "Active port scanning and service enumeration"
    
    finding_types = [FindingType.RECONNAISSANCE]
    tactics = [TacticType.RECONNAISSANCE, TacticType.DISCOVERY]
    required_access = "unauthenticated"
    timeout_seconds = 300
    
    async def execute(self, context: ExecutionContext) -> List[Finding]:
        """Execute active scanning."""
        findings = []
        
        # Port scan
        ports = await self._port_scan(context.target)
        for port, service, version in ports:
            port_finding = self._create_finding(
                title=f"{service} on port {port}",
                description=f"{service} {version} detected on {context.target}:{port}",
                finding_type=FindingType.RECONNAISSANCE,
                evidence={
                    "port": port,
                    "service": service,
                    "version": version,
                },
                severity="low",
            )
            port_finding.next_tactics = [TacticType.INITIAL_ACCESS]
            findings.append(port_finding)
        
        return findings
    
    async def _port_scan(self, target: str) -> List[tuple]:
        """Simulate port scanning."""
        await asyncio.sleep(0.2)
        return [
            (22, "ssh", "OpenSSH 7.4"),
            (80, "http", "Apache 2.4.6"),
            (443, "https", "nginx 1.16"),
        ]
