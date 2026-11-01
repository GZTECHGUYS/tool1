#!/usr/bin/env python3
"""
ARDF v2 CLI Interface
Command-line control for complete red team framework
"""

import argparse
import asyncio
import json
import sys
from typing import Optional
from pathlib import Path
import logging

# Import ARDF modules (in production, these would be from installed package)
# from ardf_v2_orchestrator_complete import ARDFv2Orchestrator
# from ardf_v2_c2_infrastructure import C2Controller, C2CommandType
# etc.

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ARDFCLIv2:
    """ARDF v2 Command Line Interface"""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize CLI"""
        self.config_file = config_file or '/tmp/ardf_config/ardf.yaml'
        self.session = None
        self.session_id = None
        self.c2 = None
        
        logger.info("[+] ARDF v2 CLI Initialized")
    
    async def engagement(self, args):
        """Run a REAL engagement through the ARDF pipeline.

        Everything here goes through the normal ARDF path: scope guard,
        mission playbooks / orchestrator phases, and the Tier-1/2/3
        confirmation gates. Nothing is simulated.
        """
        from modules.session import Session, SessionMode
        from core.mission import run_mission

        session = Session(args.target, SessionMode.RED)
        self.session = session
        self.session_id = session.meta.session_id
        logger.info(f"session: {self.session_id}  target: {args.target}")

        if args.full:
            logger.info("[*] FULL workflow: run_orchestrator (gated phases)")
            from core.orchestrator import run_orchestrator
            result = await asyncio.to_thread(
                run_orchestrator, session, logger, {"depth": "normal"})
        elif args.web_only:
            logger.info("[*] Web assessment playbook (web_audit)")
            result = await asyncio.to_thread(
                run_mission, session, "web_audit", logger)
        elif args.cloud_only:
            logger.info("[*] Cloud assessment: passive_osint playbook "
                        "(cloud/asset OSINT — no cloud playbook registered)")
            result = await asyncio.to_thread(
                run_mission, session, "passive_osint", logger)
        else:
            logger.info("[*] Reconnaissance: passive_osint playbook")
            result = await asyncio.to_thread(
                run_mission, session, "passive_osint", logger)

        logger.info(f"engagement finished: {result}")
        return result
    
    def _c2(self):
        """Shared controller instance with the dashboard (ops.c2 global)."""
        from ops import c2 as c2ops
        return c2ops.get_controller(), c2ops

    async def c2_status(self, args):
        """Display REAL C2 status from the shared controller state."""
        ctl, c2ops = self._c2()
        overview = c2ops.overview()
        listener = getattr(ctl, "listener", None)
        running = bool(listener and listener.running)
        where = (f"{listener.listen_host}:{listener.listen_port}"
                 if running else "stopped")
        logger.info(f"\n{'='*60}")
        logger.info("C2 INFRASTRUCTURE STATUS (live)")
        logger.info(f"{'='*60}")
        logger.info(f"Listener:  {where}")
        logger.info(f"Token:     {ctl.token[:4]}... (set ARDF_C2_TOKEN to pin)")
        beacons = ", ".join(str(b) for b in overview.get("beacons", []))
        logger.info(f"Beacons:   {beacons}")
        logger.info("           (TCP channel implemented; dns/icmp/"
                    "websocket/p2p: not implemented)")
        fo = overview.get("failover")
        logger.info(f"Failover:  {json.dumps(fo) if fo else 'not configured'}")
        agents = overview.get("agents", [])
        queued = sum(1 for c in ctl.commands.values()
                     if c.status in ("queued", "sent"))
        done = sum(1 for c in ctl.commands.values() if c.status == "executed")
        logger.info(f"Agents:    {len(agents)} registered")
        logger.info(f"Commands:  {queued} queued | {done} executed | "
                    f"{len(ctl.commands)} total")
        if not running:
            logger.info("Start it:  dashboard C2 tab -> Start listener, or "
                        "POST /api/v3/c2/listener/start")

    async def agent_list(self, args):
        """List REAL registered agents."""
        ctl, c2ops = self._c2()
        agents = c2ops.agents()
        if not agents:
            logger.info("No agents registered (listener not reached yet).")
            return
        logger.info(f"\n{'='*60}")
        logger.info(f"AGENT LIST ({len(agents)})")
        logger.info(f"{'='*60}")
        hdr = (f"{'ID':<14}{'HOSTNAME':<18}{'USER':<12}{'OS':<10}"
               f"{'STATUS':<10}{'PENDING':<9}{'LAST SEEN'}")
        logger.info(hdr)
        logger.info("-" * len(hdr))
        for a in agents:
            aid = a.get("agent_id") or a.get("id", "?")
            logger.info(
                f"{str(aid):<14}{str(a.get('hostname', '?')):<18}"
                f"{str(a.get('username', '?')):<12}"
                f"{str(a.get('os', '?')):<10}"
                f"{str(a.get('status', '?')):<10}"
                f"{str(a.get('pending_commands', 0)):<9}"
                f"{a.get('last_seen', '?')}")

    async def _wait_result(self, ctl, command_id: str,
                           timeout: int = 30):
        """Poll the shared controller for a command result."""
        for _ in range(timeout):
            cmd = ctl.commands.get(command_id)
            if cmd and cmd.status == "executed":
                return cmd.result
            await asyncio.sleep(1)
        return None

    async def execute_command(self, args):
        """Queue a REAL shell command on an agent and wait for its output."""
        ctl, _ = self._c2()
        if args.agent_id not in getattr(ctl, "agents", {}):
            logger.error(f"unknown agent {args.agent_id!r} "
                         "(see: ardf.py --v2 ... agents --list)")
            return
        from ardf_v2_c2_infrastructure import C2CommandType
        logger.info(f"[*] queue on {args.agent_id}: {args.command}")
        cid = await ctl.queue_command(args.agent_id, C2CommandType.SHELL,
                                      args.command)
        logger.info(f"[*] command_id={cid}; waiting for agent poll "
                    "(agent sleeps ~10s between polls)...")
        result = await self._wait_result(ctl, cid)
        if result is None:
            logger.info("[*] no result within timeout — command stays queued; "
                        "check the C2 tab later")
        else:
            logger.info("[+] result:")
            print(result)

    async def download_file(self, args):
        """Fetch a file from the agent (real queue + wait + write)."""
        ctl, _ = self._c2()
        if args.agent_id not in getattr(ctl, "agents", {}):
            logger.error(f"unknown agent {args.agent_id!r}")
            return
        from ardf_v2_c2_infrastructure import C2CommandType
        cid = await ctl.queue_command(args.agent_id, C2CommandType.DOWNLOAD,
                                      args.remote_path)
        logger.info(f"[*] queued download of {args.remote_path} ({cid})...")
        result = await self._wait_result(ctl, cid, timeout=60)
        if result is None or result.startswith("error:"):
            logger.error(f"download failed: {result or 'timeout'}")
            return
        dest = args.output or Path(args.remote_path).name
        Path(dest).write_text(result)
        logger.info(f"[+] wrote {len(result)} bytes -> {dest}")

    async def upload_file(self, args):
        """Push a local file to the agent (real queue + wait)."""
        ctl, _ = self._c2()
        if args.agent_id not in getattr(ctl, "agents", {}):
            logger.error(f"unknown agent {args.agent_id!r}")
            return
        import base64 as _b64
        from ardf_v2_c2_infrastructure import C2CommandType
        data = Path(args.local_path).read_bytes()
        cid = await ctl.queue_command(
            args.agent_id, C2CommandType.UPLOAD, args.remote_path,
            {"content_b64": _b64.b64encode(data).decode()})
        logger.info(f"[*] queued upload of {len(data)} bytes -> "
                    f"{args.remote_path} ({cid})...")
        result = await self._wait_result(ctl, cid, timeout=60)
        if result is None or result.startswith("error:"):
            logger.error(f"upload failed: {result or 'timeout'}")
        else:
            logger.info(f"[+] {result}")

    async def report(self, args):
        """Generate a REAL report from the active engagement session."""
        if self.session is None:
            logger.error("no active session — run 'engagement' first")
            return
        from modules.report import generate_report
        logger.info("[*] generating report from live session data...")
        await asyncio.to_thread(generate_report, self.session, logger, False)

    async def run(self):
        """Run CLI"""
        parser = argparse.ArgumentParser(
            description='ARDF v2 - Advanced Red Team Delivery Framework',
            epilog='For detailed help: ardf <command> --help'
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Engagement command
        engagement = subparsers.add_parser('engagement', help='Start red team engagement')
        engagement.add_argument('target', help='Target IP/CIDR/domain')
        engagement.add_argument('--full', action='store_true', help='Full red team (all 247+ capabilities)')
        engagement.add_argument('--web-only', action='store_true', help='Web assessment only')
        engagement.add_argument('--cloud-only', action='store_true', help='Cloud assessment only')
        engagement.set_defaults(func=self.engagement)
        
        # C2 status
        c2 = subparsers.add_parser('c2', help='C2 infrastructure status')
        c2.add_argument('--status', action='store_true', help='Show C2 status')
        c2.add_argument('--restart', action='store_true', help='Restart C2 listener')
        c2.set_defaults(func=self.c2_status)
        
        # Agent management
        agents = subparsers.add_parser('agents', help='Manage agents')
        agents.add_argument('--list', action='store_true', help='List all agents')
        agents.add_argument('--status', help='Show specific agent status')
        agents.add_argument('--kill', help='Kill agent')
        agents.set_defaults(func=self.agent_list)
        
        # Command execution
        cmd = subparsers.add_parser('execute', help='Execute command on agent')
        cmd.add_argument('agent_id', help='Agent ID')
        cmd.add_argument('command', help='Command to execute')
        cmd.set_defaults(func=self.execute_command)
        
        # File operations
        download = subparsers.add_parser('download', help='Download file from agent')
        download.add_argument('agent_id', help='Agent ID')
        download.add_argument('remote_path', help='Remote file path')
        download.add_argument('-o', '--output', help='Output file path')
        download.set_defaults(func=self.download_file)
        
        upload = subparsers.add_parser('upload', help='Upload file to agent')
        upload.add_argument('agent_id', help='Agent ID')
        upload.add_argument('local_path', help='Local file path')
        upload.add_argument('remote_path', help='Remote file path')
        upload.set_defaults(func=self.upload_file)
        
        # Reporting
        report = subparsers.add_parser('report', help='Generate engagement report')
        report.add_argument('--type', choices=['executive', 'technical', 'full'], default='full')
        report.add_argument('-o', '--output', help='Output directory')
        report.set_defaults(func=self.report)
        
        args = parser.parse_args()
        
        if hasattr(args, 'func'):
            await args.func(args)
        else:
            parser.print_help()


async def main():
    """Main entry point"""
    cli = ARDFCLIv2()
    await cli.run()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"[-] Error: {str(e)}")
        sys.exit(1)
