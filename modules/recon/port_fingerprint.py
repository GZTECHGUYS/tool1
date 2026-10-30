#!/usr/bin/env python3
"""Advanced port fingerprinting and service identification module."""

import socket
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

__version__ = "2.1.0"
__all__ = ["fingerprint_port", "banner_grab", "identify_service", "scan_ports"]

logger = logging.getLogger(__name__)


@dataclass
class ServiceFingerprint:
    """Result of service fingerprinting."""
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: float = 0.0


SERVICE_PATTERNS = {
    "HTTP": [b"HTTP/", b"Server:", b"<html", b"<!DOCTYPE"],
    "HTTPS": [b"HTTP/", b"SSL", b"TLS"],
    "SSH": [b"SSH-", b"OpenSSH", b"libssh"],
    "FTP": [b"220", b"FTP", b"WELCOME"],
    "SMTP": [b"220", b"SMTP", b"mail"],
    "DNS": [b"\x00\x00\x84\x00"],
    "MySQL": [b"\x00\x00\x00", b"mysql"],
    "PostgreSQL": [b"FATAL", b"postgres"],
    "MongoDB": [b"ismaster"],
    "Redis": [b"REDIS", b"+PONG"],
}


def banner_grab(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Grab banner from service on port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        banner = sock.recv(1024)
        sock.close()
        
        return banner.decode('utf-8', errors='ignore') if banner else None
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Failed to grab banner from {host}:{port}: {e}")
        return None


def identify_service(banner: Optional[str], port: int) -> Tuple[str, float]:
    """Identify service from banner and port."""
    if not banner:
        # Port-based guessing
        common_ports = {
            80: ("HTTP", 0.6),
            443: ("HTTPS", 0.7),
            22: ("SSH", 0.8),
            21: ("FTP", 0.7),
            25: ("SMTP", 0.7),
            53: ("DNS", 0.8),
            3306: ("MySQL", 0.8),
            5432: ("PostgreSQL", 0.8),
            6379: ("Redis", 0.8),
            27017: ("MongoDB", 0.8),
        }
        return common_ports.get(port, ("Unknown", 0.1))
    
    banner_bytes = banner.encode('utf-8', errors='ignore')
    best_match = ("Unknown", 0.0)
    
    for service, patterns in SERVICE_PATTERNS.items():
        for pattern in patterns:
            if pattern in banner_bytes:
                confidence = 0.85 if len(patterns) > 1 else 0.7
                if confidence > best_match[1]:
                    best_match = (service, confidence)
    
    return best_match


def fingerprint_port(host: str, port: int, timeout: float = 2.0) -> ServiceFingerprint:
    """Fingerprint a single port on target host."""
    banner = banner_grab(host, port, timeout)
    service, confidence = identify_service(banner, port)
    
    version = None
    if banner and "version" in banner.lower():
        version = banner.split("\n")[0][:50]
    
    return ServiceFingerprint(
        port=port,
        protocol="TCP",
        service=service,
        version=version,
        banner=banner[:200] if banner else None,
        confidence=confidence
    )


def scan_ports(host: str, ports: List[int], timeout: float = 2.0) -> Dict[str, Any]:
    """Scan multiple ports and fingerprint services."""
    results = {
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "scan_time": 0.0,
        "ports": [],
        "services_found": {}
    }
    
    import time
    start_time = time.time()
    
    for port in ports:
        try:
            fp = fingerprint_port(host, port, timeout)
            port_info = {
                "port": fp.port,
                "protocol": fp.protocol,
                "service": fp.service,
                "version": fp.version,
                "confidence": fp.confidence,
                "banner": fp.banner
            }
            results["ports"].append(port_info)
            
            if fp.service != "Unknown":
                if fp.service not in results["services_found"]:
                    results["services_found"][fp.service] = []
                results["services_found"][fp.service].append(port)
            
            logger.info(f"Fingerprinted {host}:{port} - {fp.service} ({fp.confidence:.0%})")
        except Exception as e:
            logger.error(f"Error fingerprinting {host}:{port}: {e}")
    
    results["scan_time"] = time.time() - start_time
    results["total_ports"] = len(results["ports"])
    results["services_detected"] = len(results["services_found"])
    
    return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python port_fingerprint.py <host> <port1,port2,...>")
        sys.exit(1)
    
    host = sys.argv[1]
    ports = [int(p) for p in sys.argv[2].split(",")]
    
    result = scan_ports(host, ports)
    print(f"\n=== Port Fingerprinting Results ===")
    print(f"Host: {result['host']}")
    print(f"Total ports: {result['total_ports']}")
    print(f"Services found: {result['services_detected']}")
    print(f"Scan time: {result['scan_time']:.2f}s")
    
    for port_info in result["ports"]:
        print(f"\n[{port_info['port']}] {port_info['service']} ({port_info['confidence']:.0%})")
        if port_info["version"]:
            print(f"    Version: {port_info['version']}")


# ── ARDF session wiring ──────────────────────────────────────

def run(session, target: str = "", logger=None, ports=None):
    """Fingerprint open ports recorded in the session + top web ports."""
    import re as _re
    from modules.session import Finding, SeverityLevel
    if logger is None:
        from modules.logger import get_logger
        logger = get_logger("recon.portfp")
    target = (target or session.meta.target).split("/")[0].split(":")[0]
    found_ports = set()
    for f in session.get_findings():
        m = _re.search(r"Port (\d+)/tcp open", f.title)
        if m:
            found_ports.add(int(m.group(1)))
    ports = sorted(found_ports | set(ports or [80, 443]))[:12]
    out = scan_ports(target, ports)
    for p in out["ports"]:
        if p["service"] != "Unknown":
            session.add_finding(Finding(
                source="recon.portfp",
                title=f"Service: {p['service']} on {p['port']}/tcp "
                      f"({p['confidence']:.0f}%)",
                description=(f"Banner: {p['banner'][:120]}"
                             if p.get("banner") else "port-inferred"),
                severity=SeverityLevel.INFO, host=f"{target}:{p['port']}",
                tags=["service", "banner", "recon"]))
    logger.success(f"port-fingerprint: {out['services_detected']} services")
    return out
