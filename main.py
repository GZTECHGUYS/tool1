"""ARDF v3 Main Entry Point - Offensive Security Framework."""

import asyncio
import logging
import sys
from pathlib import Path
import json
from datetime import datetime

from core import ARDFOrchestrator, TacticType, SessionState


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ARDF-CLI")


class ARDFCli:
    """Command-line interface for ARDF framework."""
    
    def __init__(self):
        """Initialize CLI."""
        # Get module paths
        framework_root = Path(__file__).parent
        module_paths = [framework_root / "modules"]
        
        # Initialize orchestrator with auto-discovery
        self.orchestrator = ARDFOrchestrator(module_paths)
        logger.info(f"ARDF v3 Framework initialized")
    
    async def scan(self, target: str, deep: bool = False):
        """Scan target for reconnaissance."""
        logger.info(f"Starting reconnaissance on {target}")
        
        tactics = [TacticType.RECONNAISSANCE]
        if deep:
            tactics.extend([
                TacticType.DISCOVERY,
                TacticType.CREDENTIAL_ACCESS,
            ])
        
        session = await self.orchestrator.scan(target, "host", tactics)
        
        self._print_findings(session, "Reconnaissance Results")
        self._print_summary(session)
        
        return session
    
    async def enumerate(self, target: str):
        """Deep enumeration of target."""
        logger.info(f"Starting deep enumeration on {target}")
        
        findings = await self.orchestrator.enumerate(target, "host", deep=True)
        
        logger.info(f"Enumeration complete: {len(findings)} findings")
        for finding in findings:
            logger.info(f"  [{finding.severity.value.upper()}] {finding.title}")
        
        return findings
    
    async def full_attack(self, target: str):
        """Execute full attack chain from recon to compromise."""
        logger.info(f"Starting full attack chain on {target}")
        
        # Initial recon
        logger.info("[1/5] RECONNAISSANCE")
        session = await self.orchestrator.scan(target, "host", [TacticType.RECONNAISSANCE])
        logger.info(f"  Found {len(session.all_findings)} reconnaissance findings")
        
        # Vulnerability discovery
        logger.info("[2/5] VULNERABILITY DISCOVERY")
        context = self._create_context(target, session)
        from core.module_system import ExecutionEngine
        engine = ExecutionEngine(self.orchestrator.registry)
        
        vuln_findings = await engine.execute_tactic(
            TacticType.DISCOVERY,
            context,
            session
        )
        for f in vuln_findings:
            session.add_finding(f)
        logger.info(f"  Found {len(vuln_findings)} vulnerabilities")
        
        # Exploitation
        logger.info("[3/5] EXPLOITATION")
        exploit_findings = await engine.execute_tactic(
            TacticType.EXECUTION,
            context,
            session
        )
        for f in exploit_findings:
            session.add_finding(f)
        logger.info(f"  Achieved RCE: {len(exploit_findings) > 0}")
        
        if exploit_findings:
            session.compromised_targets.add(target)
            session.current_access = "admin"
        
        # Persistence
        logger.info("[4/5] PERSISTENCE")
        persist_findings = await engine.execute_tactic(
            TacticType.PERSISTENCE,
            context,
            session
        )
        for f in persist_findings:
            session.add_finding(f)
        logger.info(f"  Persistence mechanisms: {len(persist_findings)}")
        
        # Privilege escalation
        logger.info("[5/5] PRIVILEGE ESCALATION")
        privesc_findings = await engine.execute_tactic(
            TacticType.PRIVILEGE_ESCALATION,
            context,
            session
        )
        for f in privesc_findings:
            session.add_finding(f)
        logger.info(f"  Privilege escalation: {len(privesc_findings) > 0}")
        
        self._print_summary(session)
        self._save_report(session)
        
        return session
    
    async def auto_run(self, target: str, iterations: int = 5):
        """Autonomous framework operation."""
        logger.info(f"Starting autonomous operation on {target}")
        
        session = await self.orchestrator.auto_run(
            target,
            max_iterations=iterations,
            auto_exploit=True
        )
        
        self._print_summary(session)
        return session
    
    async def list_modules(self):
        """List all available modules."""
        modules = self.orchestrator.list_modules()
        
        logger.info(f"Available modules ({len(modules)}):")
        for name, info in sorted(modules.items()):
            tactics = ", ".join(info.get("tactics", []))
            logger.info(f"  - {name}: {info.get('description')}")
            logger.info(f"      Tactics: {tactics}")
            logger.info(f"      Version: {info.get('version')}")
    
    def _create_context(self, target: str, session: SessionState):
        """Create execution context from session."""
        from core import ExecutionContext
        context = ExecutionContext(
            target=target,
            target_type="host",
            session_id=session.session_id
        )
        context.access_level = session.current_access
        return context
    
    def _print_findings(self, session: SessionState, title: str):
        """Print findings from session."""
        logger.info(f"\n{'='*60}")
        logger.info(f"{title}")
        logger.info(f"{'='*60}")
        
        for finding in session.all_findings:
            logger.info(f"\n[{finding.severity.value.upper()}] {finding.title}")
            logger.info(f"  Type: {finding.finding_type.value}")
            logger.info(f"  Target: {finding.target}")
            logger.info(f"  Confidence: {finding.confidence:.2f}")
            
            if finding.exploitable:
                logger.info(f"  ⚠️  EXPLOITABLE")
    
    def _print_summary(self, session: SessionState):
        """Print session summary."""
        summary = self.orchestrator.get_session_summary()
        
        logger.info(f"\n{'='*60}")
        logger.info("SESSION SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Session ID: {summary.get('session_id')}")
        logger.info(f"Duration: {summary.get('duration', 0):.2f} seconds")
        logger.info(f"Total Findings: {summary.get('total_findings', 0)}")
        logger.info(f"High Severity: {summary.get('findings_by_type', {}).get('vulnerability', 0)}")
        logger.info(f"Compromised Targets: {len(summary.get('compromised_targets', []))}")
        logger.info(f"Current Access Level: {summary.get('current_access')}")
        logger.info(f"Attack Paths: {summary.get('attack_paths', 0)}")
    
    def _save_report(self, session: SessionState):
        """Save findings to JSON report."""
        report = {
            "session_id": session.session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "findings": [f.to_dict() for f in session.all_findings],
            "summary": {
                "total": len(session.all_findings),
                "by_severity": {
                    "critical": len([f for f in session.all_findings if f.severity.value == "critical"]),
                    "high": len([f for f in session.all_findings if f.severity.value == "high"]),
                    "medium": len([f for f in session.all_findings if f.severity.value == "medium"]),
                    "low": len([f for f in session.all_findings if f.severity.value == "low"]),
                },
            }
        }
        
        report_file = Path(f"ardf_report_{session.session_id}.json")
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to {report_file}")


async def main():
    """Main entry point."""
    cli = ARDFCli()
    
    print("""
    ╔═══════════════════════════════════════════════╗
    ║          ARDF v3 - Offensive Framework         ║
    ║    Advanced Red Team Development Platform      ║
    ╚═══════════════════════════════════════════════╝
    """)
    
    # Example usage - full attack chain
    target = "example.com"
    
    try:
        # List available modules
        await cli.list_modules()
        
        # Execute full attack
        logger.info(f"\nStarting full attack chain on {target}\n")
        session = await cli.full_attack(target)
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
