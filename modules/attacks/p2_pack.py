"""P2 offensive pack — 10 modules (exposed-services has real exec)."""
from __future__ import annotations

import re
import socket
from typing import Any, Dict, List, Optional

from modules.logger import ARDFLogger
from modules.session import Finding, SeverityLevel, Session

from .base import AttackModule, require_in_scope
from .p1_pack import _RunbookModule, _fnd


class CICDExploit(_RunbookModule):
    id = "cicd_pipeline"
    title = "CI/CD pipeline exploitation"
    tier = 3
    summary = ("GitHub Actions / GitLab runner abuse, exposed .git, "
               "runner takeover, artifact secret scraping.")
    steps = [
        "probe /.git/HEAD + /.git/config on surface hosts",
        "enumerate Actions workflows leak paths (workflow_run PR abuse)",
        "self-hosted runner token discovery via exposed metadata pages",
        "artifact store download -> grep for aws keys, npm tokens",
    ]


class CloudIAMPlanner(_RunbookModule):
    id = "cloud_iam_planner"
    title = "Cloud IAM escalation planner"
    tier = 2
    summary = ("AWS/GCP/Az role-assumption graph builder -> least-path "
               "escalation chain, feeds ardf_v2 auto tool discovery.")
    steps = [
        "collect role/account ids from surface + github recon findings",
        "build AssumeRole/impersonate graph (planner, read-only)",
        "emit least-path escalation chain for ops.chains runbook",
    ]


class CloudStorageAudit(AttackModule):
    id = "cloud_storage_audit"
    title = "Cloud storage exposure audit"
    tier = 2
    summary = ("public buckets, leaked env/build artifacts, policy "
               "conflicts across S3/GCS/Azure.")
    confirm_word = "CONFIRM"


    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        from modules.recon.s3_enum import run as s3_run

        out = s3_run(session, target)
        return {"module": self.id, "mode": "plan", "target": target,
                "s3_enum": out}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        from modules.recon.s3_enum import candidates, test_bucket

        hits = []
        for b in candidates(target)[:25]:
            r = test_bucket(b)
            if r.get("open") or r.get("status", 0) in (200, 301):
                hits.append(r)
        return {"module": self.id, "mode": "exec", "target": target,
                "hits": hits}


class GraphQLDeep(_RunbookModule):
    id = "graphql_deep"
    title = "GraphQL deep attack (introspect + batching brute)"
    tier = 2
    summary = ("introspection audit, alias/field-suggestion fuzzing, "
               "persisted-query abuse; extends modules/validate/graphql.")
    steps = [
        "locate /graphql|/v1/graphql|graphiql from surface",
        "introspection on/off -> if on, dump depth-limited schema",
        "field-suggestion + alias-batching login brute (rateboss aware)",
    ]


class DNSAttack(_RunbookModule):
    id = "dns_attack"
    title = "DNS/zone attack module"
    tier = 3
    summary = ("AXFR zone transfer, DNS rebinding proof against SSRF "
               "endpoints, wildcard + lame delegation audit.")
    steps = [
        "AXFR against discovered NS (dnspython req)",
        "wildcard/dangling delegation audit (pairs with takeover pack)",
        "rebinding PoC against confirmed SSRF finding (loopback test)",
    ]


class VPNAppliance(_RunbookModule):
    id = "vpn_appliance"
    title = "VPN/edge appliance CVE matcher"
    tier = 2
    summary = ("banner version harvest on SonicWall/Citrix/Fortinet/Pulse "
               "family, known-CVE matching, patch-gap reporting.")
    steps = [
        "banner harvest 443/4443/444 on in-scope hosts",
        "match version + build ID against local CVE matrix",
        "report claim-only proof (version exposure), no payload",
    ]


class SessionTokens(_RunbookModule):
    id = "session_tokens"
    title = "Session/token policy audit"
    tier = 2
    summary = ("cookie attributes, token entropy, oauth state/nonce "
               "validation, TLS downgrade; extends cookie_analyzer.")
    steps = [
        "cookie attribute extraction from every surface response",
        "entropy score session ids (shannon, padded)",
        "state/nonce/pkce absence re-check on oauth flows",
    ]


class FirmwareAudit(_RunbookModule):
    id = "firmware_audit"
    title = "Firmware/OTA imaging audit"
    tier = 3
    summary = ("firmware pull, binwalk/entropy scan, hardcoded keys, "
               "OTA signature validation.")
    steps = [
        "locate firmware URLs in surface/js miner output",
        "fetch + hash + binwalk ent profile (read-only lab mode)",
        "hardcoded token/entropy checks (aws keys, provider escapes)",
        "OTA sig validation report for authorized kit",
    ]


class ExposedServices(AttackModule):
    id = "exposed_services"
    title = "Exposed service walker (Docker/Redis/Mongo/WinRM...)"
    tier = 2
    summary = ("banner capture + unauth read-only probe for high-signal "
               "management services outside db_access coverage.")

    SERVICES = {"6379": "redis", "2375": "docker", "2376": "docker-tls",
                "5985": "winrm", "9200": "elasticsearch", "27017": "mongo",
                "11211": "memcached", "4369": "epmd", "8500": "consul"}

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        hosts = sorted({f.host.split("/")[0] for f in session.get_findings()
                        if f.host})[:40]
        return {"module": self.id, "mode": "plan", "target": target,
                "host_count": len(hosts)}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("target") or session.meta.target
        if "/" in target:
            base = target.split("/")[0]
        else:
            base = target
        hosts = spec.get("targets") or [base] or [
            f.host.split("/")[0] for f in session.get_findings() if f.host]
        hosts = list(dict.fromkeys(h for h in hosts if h))[:30]
        for h in hosts:
            require_in_scope(h)
        found = []
        for h in hosts:
            for port, svc in self.SERVICES.items():
                sock = socket.socket()
                sock.settimeout(4)
                if sock.connect_ex((h, int(port))) != 0:
                    sock.close()
                    continue
                ev = ""
                if svc == "redis":
                    sock.sendall(b"PING\r\n")
                    ev = (sock.recv(64) or b"").decode("utf-8", "ignore")
                elif svc == "memcached":
                    sock.sendall(b"version\r\n")
                    ev = (sock.recv(64) or b"").decode("utf-8", "ignore")
                else:
                    ev = f"port open {port}/{svc}"
                sock.close()
                found.append({"host": h, "port": port, "svc": svc,
                              "evidence": ev[:80]})
                session.add_finding(Finding(
                    source="attacks",
                    title=f"exposed service {svc} on {h}:{port}",
                    host=h, port=int(port),
                    severity=SeverityLevel.HIGH, evidence=ev[:200],
                    tags=["exposed_service", "p2", "executed"]))
        if found:
            session.save()
        return {"module": self.id, "mode": "exec", "scanned": hosts,
                "findings": found}


class LateralPlanner(_RunbookModule):
    id = "lateral_planner"
    title = "Lateral movement plan builder"
    tier = 3
    summary = ("hash exposure inventory, adjacency (RDP/WinRM/SMB) graph "
               "from evidence, chain into lateral_movement_executor.")
    steps = [
        "collect credentials/hash evidence from loot + findings",
        "RDP/WinRM/SMB reachable-graph build (planner, no fire)",
        "emit ops.chains spec for operator-gated execution",
    ]


PACK2 = [
    CICDExploit(),
    CloudIAMPlanner(),
    CloudStorageAudit(),
    GraphQLDeep(),
    DNSAttack(),
    VPNAppliance(),
    SessionTokens(),
    FirmwareAudit(),
    ExposedServices(),
    LateralPlanner(),
]

# P2 classes inherit the P1 scaffolding, so stamp the phase explicitly.
for _module in PACK2:
    _module.phase = "P2"
