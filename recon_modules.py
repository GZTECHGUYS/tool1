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
        self._ctx_session_id = context.session_id
        
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
        """Real WHOIS lookup (modules.recon.domain.DomainRecon)."""
        from modules.recon.domain import DomainRecon

        loop = asyncio.get_running_loop()
        recon = DomainRecon(self._session(domain))
        return await loop.run_in_executor(None, recon.whois_lookup, domain)

    async def _dns_lookup(self, domain: str) -> dict:
        """Real DNS record enumeration (dnspython via DomainRecon)."""
        from modules.recon.domain import DomainRecon

        loop = asyncio.get_running_loop()
        recon = DomainRecon(self._session(domain))
        return await loop.run_in_executor(None, recon.dns_records, domain)

    async def _ssl_cert_info(self, domain: str) -> dict:
        """Real TLS certificate retrieval (modules.recon.web.WebRecon).

        Contacts the target, so it is scope-gated first.
        """
        from modules.attacks.base import require_in_scope
        from modules.recon.web import WebRecon

        require_in_scope(domain)
        loop = asyncio.get_running_loop()
        recon = WebRecon(self._session(domain))
        return await loop.run_in_executor(None, recon.ssl_certificate, domain)

    def _session(self, target: str):
        """Real ARDF session for artifact storage (identity from context)."""
        from modules.session import Session

        return Session(target, session_id=self._ctx_session_id)


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
        """Execute active scanning (scope-gated: contacts the target)."""
        from modules.attacks.base import require_in_scope

        require_in_scope(context.target)
        findings = []
        self._ctx_session_id = context.session_id
        
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
    
    # Bounded default port set — real TCP connect scan + banner fingerprint.
    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000,
        8080, 8443, 8888, 9090, 9200, 11211, 27017,
    ]

    async def _port_scan(self, target: str) -> List[tuple]:
        """Real port scan via modules.recon.port_fingerprint.scan_ports."""
        from modules.recon.port_fingerprint import scan_ports

        loop = asyncio.get_running_loop()
        results = await loop.run_in_executor(
            None, scan_ports, target, self.DEFAULT_PORTS
        )
        return [
            (p["port"], p.get("service") or "unknown", p.get("version") or "")
            for p in results.get("ports", [])
        ]
