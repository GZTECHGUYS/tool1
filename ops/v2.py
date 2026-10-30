"""v2 integration hub — wires every ardf_v2_* module into the framework.

Previously 8 of 13 v2 files were orphans (mentioned only in docs).
Each function below is consumed by live code (dashboard / preflight /
recon / verify). Engines that execute attacks are catalogued read-only;
only explicitly Tier-gated entry points execute anything.
"""
from __future__ import annotations

import asyncio
import inspect
import shutil
from typing import Any, Dict, List, Optional

SEV_CVSS = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0,
            "info": 0.0}


def _run(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _public_methods(cls) -> List[str]:
    return sorted(n for n, m in inspect.getmembers(cls, inspect.isfunction)
                  if not n.startswith("_"))


# ── catalog (read-only; execution stays behind Tier gates) ────

CATALOG_SOURCES = [
    ("ardf_v2_exploitation_complete",
     ["SQLiFramework", "XSSFramework", "SSTIFramework", "XXEFramework",
      "SSRFFramework", "JWTFramework", "CORSFramework", "OAuthFramework",
      "GraphQLFramework", "HTTPSmuggleFramework", "CRLFInjectionFramework"]),
    ("ardf_v2_evasion_complete",
     ["ProcessEvasion", "KernelEvasion", "EDRBypass", "ArtifactElimination",
      "NetworkEvasion", "DetectionEvasion", "EvasionOrchestrator"]),
    ("ardf_v2_c2_infrastructure", ["C2Controller", "C2Agent"]),
    ("ardf_v2_payload_delivery", ["PayloadGenerator"]),
    ("ardf_v2_social_engineering",
     ["PhishingCampaignOrchestrator", "CredentialHarvestingServer"]),
    ("ardf_v2_reporting_complete",
     ["EvidenceCollector", "VulnerabilityAssessment", "ComplianceAnalyzer",
      "ReportGenerator"]),
    ("ardf_v2_failure_recovery", ["FailureDetector", "AdaptiveRecovery"]),
    ("ardf_v2_adaptive_orchestrator",
     ["DeepReconOrchestrator", "AdaptiveTaskExecutor"]),
    ("ardf_v2_infrastructure_advanced",
     ["PassiveReconAtScale", "PersistenceMechanisms", "LateralMovement",
      "NetworkReconnaissance"]),
    ("ardf_v2_orchestrator_complete", ["ARDFv2Orchestrator"]),
    ("ardf_v2_auto_tool_discovery",
     ["ToolRegistry", "ToolInstaller", "AdaptiveWorkflow"]),
]


def toolkit_catalog() -> Dict[str, Any]:
    """Introspect every v2 framework class (import + method list)."""
    import importlib
    modules: List[Dict[str, Any]] = []
    ok, failed = 0, []
    for mod_name, classes in CATALOG_SOURCES:
        try:
            mod = importlib.import_module(mod_name)
        except Exception as e:
            failed.append({"module": mod_name, "error": str(e)[:200]})
            continue
        info = {"module": mod_name, "classes": []}
        for cls_name in classes:
            cls = getattr(mod, cls_name, None)
            if cls is None:
                info["classes"].append({"name": cls_name,
                                        "error": "not found"})
                continue
            info["classes"].append({"name": cls_name,
                                    "methods": _public_methods(cls)})
            ok += 1
        modules.append(info)
    return {"modules": modules, "classes_ok": ok, "failed": failed}


def phishing_templates() -> List[str]:
    """List social-engineering template options (no sending)."""
    from ardf_v2_social_engineering import PhishingTemplate
    return [t.name for t in PhishingTemplate]


def v2_configs() -> List[Dict[str, Any]]:
    """Parse-check the v2 YAML config constants."""
    import yaml
    import ardf_v2_config_complete as cfg
    out = []
    for name in ("ARDF_MAIN_CONFIG", "PLAYBOOK_FULL_ENGAGEMENT",
                 "MISSION_PROFILE"):
        raw = getattr(cfg, name, "")
        try:
            data = yaml.safe_load(raw)
            out.append({"name": name, "ok": True,
                        "top_keys": sorted(data.keys()) if isinstance(data, dict)
                        else type(data).__name__})
        except Exception as e:
            out.append({"name": name, "ok": False, "error": str(e)[:200]})
    return out


def tool_coverage() -> Dict[str, Any]:
    """v2 ToolRegistry tasks x local install status (feeds preflight)."""
    from ardf_v2_auto_tool_discovery import ToolRegistry
    reg = ToolRegistry()
    entries = getattr(reg, "registry", None) or getattr(reg, "tools", {}) or {}
    rows = []
    for name, meta in entries.items():
        binary = (getattr(meta, "executable_name", None)
                  or getattr(meta, "binary", None) or name)
        tasks = getattr(meta, "task_types", "")
        try:
            task = ", ".join(t.name if hasattr(t, "name") else str(t)
                             for t in (tasks or []))
        except TypeError:
            task = str(tasks)
        rows.append({"tool": name, "binary": binary,
                     "installed": (shutil.which(binary) or shutil.which(name))
                     is not None,
                     "task": task})
    return {"count": len(rows), "tools": rows,
            "installed": sum(1 for r in rows if r["installed"])}


# ── functional: session risk via v2 reporting stack ───────────

def session_risk(session) -> Dict[str, Any]:
    """Map session findings -> v2 VulnerabilityAssessment + compliance +
    financial impact + executive summary. Async stack driven synchronously."""
    from ardf_v2_reporting_complete import (
        Vulnerability, VulnerabilityAssessment, ComplianceAnalyzer,
        ReportGenerator)

    async def _go():
        assess = VulnerabilityAssessment()
        for f in session.get_findings():
            sev = f.severity.value
            await assess.add_vulnerability(Vulnerability(
                vuln_id=f.id, name=f.title[:120],
                description=f.description[:500] or f.title,
                cvss_score=SEV_CVSS.get(sev, 0.0),
                cvss_vector="", cve=f.cve,
                affected_systems=[f.host] if f.host else [],
                remediation=f.remediation or "",
                severity=sev, impact="", exploitable=False))
        vulns = assess.vulnerabilities
        top = sorted(vulns, key=lambda v: v.cvss_score, reverse=True)[:5]
        blast = {}
        for v in top:
            try:
                blast[v.vuln_id] = await assess.calculate_blast_radius(v)
            except Exception:
                blast[v.vuln_id] = {}
        financial = await assess.calculate_financial_impact(len(vulns))
        comp = ComplianceAnalyzer()
        violations = await comp.analyze_violations(
            [{"title": f.title, "severity": f.severity.value,
              "tags": f.tags} for f in session.get_findings()])
        gen = ReportGenerator(session.meta.name or "ardf",
                              session.meta.target)
        summary = await gen.generate_executive_summary(
            len(vulns),
            len({h for v in vulns for h in v.affected_systems}),
            0)
        return {
            "vulns": len(vulns),
            "blast_radius": blast,
            "financial_impact": financial,
            "violations": [getattr(v, "__dict__", str(v)) for v in violations],
            "executive_summary": summary,
        }

    return _run(_go())


# ── Tier-3 gated: payload generation ──────────────────────────

def generate_agent(kind: str, c2_server: str, c2_port: int = 443,
                   key: str = "", confirm_text: str = "") -> Dict[str, Any]:
    """Generate a v2 agent stub. Requires confirm_text='CONFIRM'."""
    if confirm_text.strip() != "CONFIRM":
        raise PermissionError("Tier-3: pass confirm_text='CONFIRM'")
    from ardf_v2_payload_delivery import PayloadGenerator
    if kind == "powershell":
        code = PayloadGenerator.generate_powershell_agent(
            c2_server, c2_port, key)
    elif kind == "python":
        code = PayloadGenerator.generate_python_agent(
            c2_server, c2_port, key)
    else:
        raise ValueError("kind must be powershell|python")
    return {"kind": kind, "c2_server": c2_server, "c2_port": c2_port,
            "bytes": len(code), "code": code}


# ── passive: certificate-transparency subdomains ──────────────

def ct_subdomains(target: str) -> List[str]:
    """crt.sh subdomain harvest via v2 PassiveReconAtScale (passive)."""
    from ardf_v2_infrastructure_advanced import PassiveReconAtScale
    host = target.split("/")[0].split(":")[0]
    try:
        return _run(PassiveReconAtScale(host).certificate_transparency_scan()) or []
    except Exception:
        return []
