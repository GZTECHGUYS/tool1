#!/usr/bin/env python3
"""
ARDF v2 OPERATIONAL FAILURE RECOVERY
Real-time detection of operational failures + adaptive recovery
The difference between operations that burn and operations that continue
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import socket
import requests

logger = logging.getLogger(__name__)


class FailureType(Enum):
    """Types of operational failures"""
    SCANNING_DETECTED = "scanning_detected"
    EXPLOITATION_FAILED = "exploitation_failed"
    PAYLOAD_EXECUTION_FAILED = "payload_execution_failed"
    C2_COMMUNICATION_FAILED = "c2_communication_failed"
    PERSISTENCE_FAILED = "persistence_failed"
    DETECTION_ALERT_TRIGGERED = "detection_alert_triggered"
    IDS_IPS_TRIGGER = "ids_ips_trigger"
    WAF_BLOCK = "waf_block"
    CREDENTIAL_INVALID = "credential_invalid"
    EXECUTION_TIMEOUT = "execution_timeout"


class RecoveryStrategy(Enum):
    """Recovery strategies for failures"""
    PAUSE_AND_RESUME = "pause_and_resume"
    SWITCH_VECTOR = "switch_vector"
    SWITCH_TECHNIQUE = "switch_technique"
    SWITCH_EVASION = "switch_evasion"
    THROTTLE_OPERATIONS = "throttle_operations"
    ABORT_PHASE = "abort_phase"
    PIVOT_TO_FALLBACK = "pivot_to_fallback"
    COUNTER_DETECT = "counter_detect"


@dataclass
class OperationalMetrics:
    """Real-time operational metrics"""
    phase: str
    elapsed_time: float
    attempts: int
    failures: int
    detections: int
    alerts_triggered: int
    operations_paused: int
    operations_resumed: int
    vectors_switched: int
    techniques_failed: List[str]
    current_evasion_level: int  # 1-10 (1=aggressive, 10=stealth)
    estimated_detection_risk: float  # 0-100%


class DetectionMonitor:
    """Monitor for operational detection"""
    
    def __init__(self, siem_server: Optional[str] = None, 
                 edr_monitor: Optional[str] = None):
        """Initialize detection monitoring"""
        self.siem_server = siem_server
        self.edr_monitor = edr_monitor
        self.detection_history = []
        self.baseline_metrics = None
    
    async def monitor_siem_queries(self) -> List[Dict]:
        """Monitor SIEM for queries about our activity"""
        
        if not self.siem_server:
            return []
        
        suspicious_queries = []
        
        try:
            # Query SIEM for recent searches
            # This would connect to actual SIEM (Splunk, ELK, etc)
            response = await self._query_siem_logs()
            
            # Pattern detection
            keywords = [
                'suspicious',
                'anomaly',
                'unusual access',
                'privilege escalation',
                'failed login',
                'port scan',
                'vulnerability',
                'malware',
                'persistence',
                'lateral movement'
            ]
            
            for log in response:
                for keyword in keywords:
                    if keyword.lower() in log.get('query', '').lower():
                        suspicious_queries.append({
                            'time': log.get('time'),
                            'query': log.get('query'),
                            'severity': self._assess_query_severity(log)
                        })
            
            return suspicious_queries
        
        except Exception as e:
            logger.error(f"[-] SIEM monitoring failed: {str(e)}")
            return []
    
    async def monitor_edr_alerts(self) -> List[Dict]:
        """Monitor for EDR alerts triggered by our activity"""
        
        if not self.edr_monitor:
            return []
        
        alerts = []
        
        try:
            # Query EDR for recent alerts
            # This would connect to actual EDR (Crowdstrike, SentinelOne, etc)
            response = await self._query_edr_alerts()
            
            for alert in response:
                if self._is_alert_about_us(alert):
                    alerts.append({
                        'time': alert.get('timestamp'),
                        'type': alert.get('alert_type'),
                        'process': alert.get('process_name'),
                        'severity': alert.get('severity'),
                        'confidence': self._assess_alert_confidence(alert)
                    })
            
            self.detection_history.append({
                'timestamp': datetime.now(),
                'alerts': len(alerts)
            })
            
            return alerts
        
        except Exception as e:
            logger.error(f"[-] EDR monitoring failed: {str(e)}")
            return []
    
    async def monitor_network_traffic(self, target_network: str) -> Dict:
        """Monitor network traffic for signs of detection"""
        
        indicators = {
            'increased_dns_queries': False,
            'increased_packet_captures': False,
            'increased_syslog_traffic': False,
            'unusual_port_access': False,
            'threat_hunt_activity': False
        }
        
        try:
            # Monitor for increased network traffic to sensors
            # Signs include: more DNS queries, packet capture tool running, etc
            
            # Check for increased DNS queries (could indicate threat hunting)
            dns_query_count = await self._measure_dns_queries()
            if dns_query_count > 1000:  # Abnormally high
                indicators['increased_dns_queries'] = True
            
            # Check for packet capture tools
            packet_tools = await self._detect_packet_capture_tools()
            if packet_tools:
                indicators['increased_packet_captures'] = True
            
            # Check for increased syslog traffic
            syslog_volume = await self._measure_syslog_volume()
            if syslog_volume > 5000:  # Abnormally high
                indicators['increased_syslog_traffic'] = True
            
            return indicators
        
        except Exception as e:
            logger.error(f"[-] Network monitoring failed: {str(e)}")
            return indicators
    
    async def _query_siem_logs(self) -> List[Dict]:
        """Query SIEM for recent activity"""
        # Implementation: Connect to actual SIEM
        return []
    
    async def _query_edr_alerts(self) -> List[Dict]:
        """Query EDR for alerts"""
        # Implementation: Connect to actual EDR
        return []
    
    def _is_alert_about_us(self, alert: Dict) -> bool:
        """Determine if alert is about our activity"""
        suspicious_indicators = [
            'powershell',
            'cmd.exe',
            'mimikatz',
            'credential',
            'lateral',
            'privilege',
            'persistence'
        ]
        
        text = f"{alert.get('process_name', '')} {alert.get('command_line', '')}".lower()
        return any(indicator in text for indicator in suspicious_indicators)
    
    def _assess_alert_confidence(self, alert: Dict) -> float:
        """Assess confidence that alert is about us"""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on severity
        severity = alert.get('severity', '').lower()
        if severity == 'critical':
            confidence += 0.3
        elif severity == 'high':
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _assess_query_severity(self, query: Dict) -> str:
        """Assess severity of SIEM query"""
        query_text = query.get('query', '').lower()
        
        if any(x in query_text for x in ['privilege', 'lateral', 'persistence']):
            return 'critical'
        elif any(x in query_text for x in ['exploit', 'vulnerability']):
            return 'high'
        else:
            return 'medium'
    
    async def _measure_dns_queries(self) -> int:
        """Measure DNS query volume"""
        return 0  # Placeholder
    
    async def _detect_packet_capture_tools(self) -> List[str]:
        """Detect packet capture tools"""
        return []  # Placeholder
    
    async def _measure_syslog_volume(self) -> int:
        """Measure syslog volume"""
        return 0  # Placeholder


class FailureDetector:
    """Detect operational failures in real-time"""
    
    def __init__(self):
        """Initialize failure detector"""
        self.failures = []
        self.baseline_metrics = {}
    
    async def detect_scanning_activity(self, scan_metrics: Dict) -> Optional[FailureType]:
        """Detect if scanning is triggering IDS/IPS"""
        
        # Indicators of detection:
        # 1. Sudden drop in responses (IPS blocking)
        # 2. Increased timeout rate
        # 3. Increased ICMP unreachable
        # 4. Increased TCP resets
        
        response_rate = scan_metrics.get('response_rate', 1.0)
        timeout_rate = scan_metrics.get('timeout_rate', 0.0)
        reset_rate = scan_metrics.get('reset_rate', 0.0)
        
        if response_rate < 0.5:  # 50% drop
            logger.warning("[!] SCANNING DETECTION: Response rate dropped 50%+")
            return FailureType.IDS_IPS_TRIGGER
        
        if timeout_rate > 0.3:  # 30% timeouts
            logger.warning("[!] SCANNING DETECTION: Timeout rate exceeded 30%")
            return FailureType.IDS_IPS_TRIGGER
        
        if reset_rate > 0.2:  # 20% resets
            logger.warning("[!] SCANNING DETECTION: Reset rate exceeded 20%")
            return FailureType.IDS_IPS_TRIGGER
        
        return None
    
    async def detect_exploitation_failure(self, exploit_results: Dict) -> Optional[FailureType]:
        """Detect if exploitation failed"""
        
        success_rate = exploit_results.get('success_rate', 0.0)
        alert_count = exploit_results.get('alerts_triggered', 0)
        
        if success_rate == 0.0:
            logger.error("[!] EXPLOITATION FAILURE: No successful exploits")
            return FailureType.EXPLOITATION_FAILED
        
        if alert_count > 10:
            logger.warning("[!] EXPLOITATION DETECTED: Multiple alerts triggered")
            return FailureType.DETECTION_ALERT_TRIGGERED
        
        return None
    
    async def detect_payload_failure(self, payload_execution: Dict) -> Optional[FailureType]:
        """Detect if payload failed to execute"""
        
        execution_status = payload_execution.get('status')
        error_code = payload_execution.get('error_code')
        
        if execution_status == 'failed':
            logger.error(f"[!] PAYLOAD EXECUTION FAILED: {error_code}")
            return FailureType.PAYLOAD_EXECUTION_FAILED
        
        if 'timeout' in str(error_code).lower():
            logger.error("[!] PAYLOAD EXECUTION TIMEOUT")
            return FailureType.EXECUTION_TIMEOUT
        
        return None
    
    async def detect_c2_failure(self, c2_metrics: Dict) -> Optional[FailureType]:
        """Detect if C2 communication failed"""
        
        connection_success = c2_metrics.get('connection_success_rate', 1.0)
        timeouts = c2_metrics.get('timeout_count', 0)
        
        if connection_success < 0.3:
            logger.error("[!] C2 COMMUNICATION FAILURE: Connection rate < 30%")
            return FailureType.C2_COMMUNICATION_FAILED
        
        if timeouts > 5:
            logger.error("[!] C2 COMMUNICATION FAILURE: Excessive timeouts")
            return FailureType.C2_COMMUNICATION_FAILED
        
        return None


class AdaptiveRecovery:
    """Adaptive recovery from operational failures"""
    
    def __init__(self, max_retry_attempts: int = 5):
        """Initialize adaptive recovery"""
        self.max_retry_attempts = max_retry_attempts
        self.recovery_history = []
    
    async def recover_from_failure(self, failure: FailureType, 
                                   context: Dict) -> RecoveryStrategy:
        """Determine and execute recovery strategy"""
        
        if failure == FailureType.IDS_IPS_TRIGGER:
            return await self._recover_from_ids_trigger(context)
        
        elif failure == FailureType.EXPLOITATION_FAILED:
            return await self._recover_from_exploitation_failure(context)
        
        elif failure == FailureType.PAYLOAD_EXECUTION_FAILED:
            return await self._recover_from_payload_failure(context)
        
        elif failure == FailureType.C2_COMMUNICATION_FAILED:
            return await self._recover_from_c2_failure(context)
        
        elif failure == FailureType.DETECTION_ALERT_TRIGGERED:
            return await self._recover_from_detection(context)
        
        else:
            return RecoveryStrategy.PAUSE_AND_RESUME
    
    async def _recover_from_ids_trigger(self, context: Dict) -> RecoveryStrategy:
        """Recover from IDS/IPS trigger"""
        
        logger.info("[*] RECOVERY: Pausing scanning, increasing evasion")
        
        # Step 1: Pause operations
        await self._pause_operations(duration=300)  # 5 minute pause
        
        # Step 2: Increase evasion level
        await self._increase_evasion_level(context)
        
        # Step 3: Switch to slower scan rate
        context['scan_rate'] = context.get('scan_rate', 1000) // 10
        
        # Step 4: Add randomization to timing
        context['randomize_timing'] = True
        
        logger.info("[+] RECOVERY: Resuming with increased stealth")
        return RecoveryStrategy.PAUSE_AND_RESUME
    
    async def _recover_from_exploitation_failure(self, context: Dict) -> RecoveryStrategy:
        """Recover from exploitation failure"""
        
        current_vector = context.get('current_vector')
        alternative_vectors = context.get('alternative_vectors', [])
        
        if alternative_vectors:
            logger.info(f"[*] RECOVERY: Switching from {current_vector} to alternative vector")
            context['current_vector'] = alternative_vectors[0]
            return RecoveryStrategy.SWITCH_VECTOR
        else:
            logger.warning("[!] RECOVERY: No alternative vectors, switching technique")
            context['current_technique'] = await self._select_alternative_technique(context)
            return RecoveryStrategy.SWITCH_TECHNIQUE
    
    async def _recover_from_payload_failure(self, context: Dict) -> RecoveryStrategy:
        """Recover from payload execution failure"""
        
        logger.info("[*] RECOVERY: Regenerating payload with obfuscation")
        
        # Regenerate payload with different obfuscation
        context['payload_obfuscation'] = 'advanced'
        context['payload_encoding'] = 'random'
        
        # Try alternative delivery method
        context['delivery_method'] = 'alternate'
        
        return RecoveryStrategy.SWITCH_TECHNIQUE
    
    async def _recover_from_c2_failure(self, context: Dict) -> RecoveryStrategy:
        """Recover from C2 communication failure"""
        
        logger.info("[*] RECOVERY: Switching to fallback C2 channel")
        
        c2_channels = ['https', 'dns', 'icmp', 'websocket', 'p2p']
        current_channel = context.get('c2_channel', 'https')
        
        # Switch to next available channel
        remaining_channels = [c for c in c2_channels if c != current_channel]
        if remaining_channels:
            context['c2_channel'] = remaining_channels[0]
            logger.info(f"[+] RECOVERY: C2 switched to {remaining_channels[0]}")
            return RecoveryStrategy.PIVOT_TO_FALLBACK
        else:
            logger.error("[-] RECOVERY: No C2 channels available")
            return RecoveryStrategy.ABORT_PHASE
    
    async def _recover_from_detection(self, context: Dict) -> RecoveryStrategy:
        """Recover from detection alert"""
        
        logger.warning("[!] RECOVERY: Detected by blue team, initiating counter-measures")
        
        # Step 1: Increase evasion
        await self._increase_evasion_level(context)
        
        # Step 2: Pause external activity
        await self._pause_operations(duration=600)  # 10 minute pause
        
        # Step 3: Inject false activity
        await self._inject_false_activity(context)
        
        # Step 4: Attempt counter-incident response interference
        await self._counter_ir_activity(context)
        
        return RecoveryStrategy.COUNTER_DETECT
    
    async def _pause_operations(self, duration: int):
        """Pause all external operations"""
        logger.info(f"[*] Operations paused for {duration} seconds")
        await asyncio.sleep(duration)
        logger.info("[+] Operations resumed")
    
    async def _increase_evasion_level(self, context: Dict):
        """Increase evasion sophistication"""
        current_level = context.get('evasion_level', 1)
        context['evasion_level'] = min(current_level + 2, 10)
        logger.info(f"[+] Evasion level increased to {context['evasion_level']}")
    
    async def _select_alternative_technique(self, context: Dict) -> str:
        """Select alternative exploitation technique"""
        
        failed_techniques = context.get('failed_techniques', [])
        available_techniques = [
            'sqli_union',
            'sqli_time_based',
            'sqli_blind',
            'xss_stored',
            'xss_reflected',
            'lfi_path_traversal'
        ]
        
        # Return first technique not yet tried
        for technique in available_techniques:
            if technique not in failed_techniques:
                return technique
        
        return 'rfi'  # Fallback
    
    async def _inject_false_activity(self, context: Dict):
        """Inject false activity to confuse blue team"""
        logger.info("[*] Injecting false activity (noise)")
        # Generate legitimate-looking activity that doesn't advance attack
    
    async def _counter_ir_activity(self, context: Dict):
        """Execute counter-IR activities"""
        logger.info("[*] Executing counter-IR measures")
        # Interfere with incident response (detailed in counter-IR module)


class OperationalContext:
    """Maintain operational context across phases"""
    
    def __init__(self):
        """Initialize context"""
        self.metrics = {}
        self.failures_encountered = []
        self.recoveries_executed = []
        self.techniques_available = {}
        self.techniques_exhausted = []
    
    async def execute_with_recovery(self, 
                                   operation: Callable,
                                   operation_name: str,
                                   failure_detector: FailureDetector,
                                   adaptive_recovery: AdaptiveRecovery) -> bool:
        """Execute operation with automatic failure detection and recovery"""
        
        attempt = 1
        
        while attempt <= 5:
            try:
                logger.info(f"[*] Executing {operation_name} (attempt {attempt})")
                
                result = await operation()
                
                # Check for failures in result
                if isinstance(result, dict):
                    failure = await self._detect_failure_in_result(result, failure_detector)
                    
                    if failure:
                        logger.error(f"[!] Operation failed: {failure.name}")
                        self.failures_encountered.append(failure)
                        
                        # Execute recovery
                        recovery = await adaptive_recovery.recover_from_failure(failure, self.metrics)
                        self.recoveries_executed.append(recovery)
                        
                        attempt += 1
                        continue
                
                logger.info(f"[+] {operation_name} completed successfully")
                return True
            
            except Exception as e:
                logger.error(f"[-] {operation_name} failed: {str(e)}")
                attempt += 1
        
        logger.error(f"[-] {operation_name} exhausted all recovery attempts")
        return False
    
    async def _detect_failure_in_result(self, result: Dict, 
                                       detector: FailureDetector) -> Optional[FailureType]:
        """Detect failure in operation result"""
        
        if 'scan_metrics' in result:
            return await detector.detect_scanning_activity(result['scan_metrics'])
        elif 'exploit_results' in result:
            return await detector.detect_exploitation_failure(result['exploit_results'])
        elif 'payload_execution' in result:
            return await detector.detect_payload_failure(result['payload_execution'])
        elif 'c2_metrics' in result:
            return await detector.detect_c2_failure(result['c2_metrics'])
        
        return None


# Integration with ARDF v2 Orchestrator
async def integrate_failure_recovery(orchestrator):
    """Add failure recovery to ARDF v2 orchestrator"""
    
    failure_detector = FailureDetector()
    adaptive_recovery = AdaptiveRecovery()
    detection_monitor = DetectionMonitor()
    context = OperationalContext()
    
    # Wrap each phase with failure detection
    original_scanning = orchestrator.scanning_phase
    
    async def scanning_with_recovery():
        return await context.execute_with_recovery(
            operation=original_scanning,
            operation_name="Scanning Phase",
            failure_detector=failure_detector,
            adaptive_recovery=adaptive_recovery
        )
    
    # Similar wrapping for other phases
    orchestrator.scanning_phase = scanning_with_recovery
    
    # Add real-time detection monitoring
    async def monitor_detections():
        while orchestrator.running:
            alerts = await detection_monitor.monitor_edr_alerts()
            siem_queries = await detection_monitor.monitor_siem_queries()
            
            if alerts or siem_queries:
                logger.warning(f"[!] Detection activity detected: {len(alerts)} EDR alerts, {len(siem_queries)} SIEM queries")
                
                # Trigger counter-measures
                await adaptive_recovery.recover_from_failure(
                    FailureType.DETECTION_ALERT_TRIGGERED,
                    context.metrics
                )
            
            await asyncio.sleep(30)  # Check every 30 seconds
    
    # Start detection monitoring
    orchestrator.monitoring_task = asyncio.create_task(monitor_detections())
    
    logger.info("[+] Failure recovery system initialized")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    # Offline smoke check — constructs the real detectors (no synthetic
    # events are fed in; production use goes through ops/jobs.py).
    detector = FailureDetector()
    recovery = AdaptiveRecovery()
    monitor = DetectionMonitor()
    print(f"FailureDetector ready: {len(getattr(detector, 'rules', []) or [])} rules loaded")
    print(f"AdaptiveRecovery ready: strategies={sorted(getattr(recovery, 'strategies', {}) or {})}")
    print(f"DetectionMonitor ready: {monitor.__class__.__name__}")
