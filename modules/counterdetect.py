#!/usr/bin/env python3
"""Threat detection and response orchestration module."""

import logging
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import json

__version__ = "2.1.0"
__all__ = ["ThreatDetector", "detect_threat", "respond_to_threat", "escalate_alert"]

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ResponseAction(Enum):
    """Automated response actions."""
    MONITOR = "monitor"
    BLOCK = "block"
    ISOLATE = "isolate"
    ALERT = "alert"
    ESCALATE = "escalate"


@dataclass
class Threat:
    """Detected threat."""
    threat_id: str
    name: str
    source: str
    target: str
    level: ThreatLevel
    signature: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    context: Dict[str, Any] = field(default_factory=dict)
    

@dataclass
class ThreatResponse:
    """Response to a threat."""
    threat_id: str
    action: ResponseAction
    status: str
    executed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    details: Dict[str, Any] = field(default_factory=dict)


class ThreatDetector:
    """Detects and responds to security threats."""
    
    def __init__(self):
        """Initialize threat detector."""
        self.threats: Dict[str, Threat] = {}
        self.responses: Dict[str, ThreatResponse] = {}
        self.response_handlers: Dict[ThreatLevel, Callable] = {
            ThreatLevel.LOW: self._handle_low,
            ThreatLevel.MEDIUM: self._handle_medium,
            ThreatLevel.HIGH: self._handle_high,
            ThreatLevel.CRITICAL: self._handle_critical,
        }
        self.logger = logging.getLogger("ThreatDetector")
    
    def detect(self, event: Dict[str, Any]) -> Optional[Threat]:
        """Detect threat from event."""
        threat_level = self._assess_threat_level(event)
        
        if threat_level == ThreatLevel.LOW:
            return None  # Don't track low-level events
        
        threat = Threat(
            threat_id=self._generate_threat_id(),
            name=event.get("name", "Unknown Threat"),
            source=event.get("source", "unknown"),
            target=event.get("target", "unknown"),
            level=threat_level,
            signature=event.get("signature", ""),
            context=event.get("context", {})
        )
        
        self.threats[threat.threat_id] = threat
        self.logger.warning(f"Threat detected: {threat.name} ({threat.level.name})")
        
        return threat
    
    def _assess_threat_level(self, event: Dict[str, Any]) -> ThreatLevel:
        """Assess threat level from event."""
        priority = event.get("priority", 0)
        
        if priority >= 8:
            return ThreatLevel.CRITICAL
        elif priority >= 6:
            return ThreatLevel.HIGH
        elif priority >= 3:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def respond(self, threat: Threat) -> ThreatResponse:
        """Generate response to threat."""
        handler = self.response_handlers.get(threat.level)
        
        if handler:
            action = handler(threat)
        else:
            action = ResponseAction.MONITOR
        
        response = ThreatResponse(
            threat_id=threat.threat_id,
            action=action,
            status="initiated",
            details={
                "threat_name": threat.name,
                "source": threat.source,
                "target": threat.target
            }
        )
        
        self.responses[threat.threat_id] = response
        self.logger.info(f"Response initiated: {threat.threat_id} - {action.value}")
        
        return response
    
    def _handle_low(self, threat: Threat) -> ResponseAction:
        """Handle low-level threat."""
        return ResponseAction.MONITOR
    
    def _handle_medium(self, threat: Threat) -> ResponseAction:
        """Handle medium-level threat."""
        return ResponseAction.ALERT
    
    def _handle_high(self, threat: Threat) -> ResponseAction:
        """Handle high-level threat."""
        return ResponseAction.BLOCK
    
    def _handle_critical(self, threat: Threat) -> ResponseAction:
        """Handle critical-level threat."""
        return ResponseAction.ISOLATE
    
    def get_threat(self, threat_id: str) -> Optional[Threat]:
        """Get threat by ID."""
        return self.threats.get(threat_id)
    
    def get_response(self, threat_id: str) -> Optional[ThreatResponse]:
        """Get response for threat."""
        return self.responses.get(threat_id)
    
    def list_active_threats(self) -> List[Threat]:
        """List all active threats."""
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        return [t for t in self.threats.values() if t.timestamp > cutoff]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat statistics."""
        threats = list(self.threats.values())
        return {
            "total_threats": len(threats),
            "by_level": {
                "critical": len([t for t in threats if t.level == ThreatLevel.CRITICAL]),
                "high": len([t for t in threats if t.level == ThreatLevel.HIGH]),
                "medium": len([t for t in threats if t.level == ThreatLevel.MEDIUM]),
                "low": len([t for t in threats if t.level == ThreatLevel.LOW]),
            },
            "responses_executed": len(self.responses),
            "detection_coverage": self._calc_coverage()
        }
    
    def _calc_coverage(self) -> float:
        """Calculate threat detection coverage."""
        if not self.threats:
            return 0.0
        detected_with_response = sum(1 for t in self.threats.values() if t.threat_id in self.responses)
        return (detected_with_response / len(self.threats)) * 100
    
    def _generate_threat_id(self) -> str:
        """Generate unique threat ID."""
        import hashlib
        data = f"{datetime.now().isoformat()}{len(self.threats)}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


# Module-level detector instance
_detector = None


def get_detector() -> ThreatDetector:
    """Get or create global threat detector."""
    global _detector
    if _detector is None:
        _detector = ThreatDetector()
    return _detector


def detect_threat(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Detect threat from event."""
    detector = get_detector()
    threat = detector.detect(event)
    
    if threat:
        return {
            "threat_id": threat.threat_id,
            "name": threat.name,
            "level": threat.level.name,
            "detected_at": threat.timestamp
        }
    return None


def respond_to_threat(threat_id: str) -> Optional[Dict[str, Any]]:
    """Execute response for threat."""
    detector = get_detector()
    threat = detector.get_threat(threat_id)
    
    if not threat:
        return None
    
    response = detector.respond(threat)
    return {
        "threat_id": response.threat_id,
        "action": response.action.value,
        "status": response.status,
        "executed_at": response.executed_at
    }


def escalate_alert(threat_id: str, severity: str = "HIGH") -> Dict[str, Any]:
    """Escalate threat alert."""
    detector = get_detector()
    threat = detector.get_threat(threat_id)
    
    if not threat:
        return {"error": "Threat not found"}
    
    return {
        "threat_id": threat_id,
        "escalated": True,
        "severity": severity,
        "escalated_at": datetime.now().isoformat(),
        "notification": f"Security team notified of {threat.name}"
    }


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    )
    
    detector = get_detector()
    
    # Test threat detection
    test_events = [
        {
            "name": "SQL Injection Attempt",
            "priority": 8,
            "source": "192.168.1.100",
            "target": "database",
            "signature": "sqli_pattern_1",
            "context": {"payload": "DROP TABLE users"}
        },
        {
            "name": "Brute Force Attack",
            "priority": 6,
            "source": "10.0.0.50",
            "target": "web_server",
            "signature": "brute_force_ssh",
            "context": {"attempts": 500}
        },
        {
            "name": "Port Scan",
            "priority": 2,
            "source": "203.0.113.10",
            "target": "network",
            "signature": "port_scan_detect",
            "context": {"ports_scanned": 1000}
        }
    ]
    
    print("=== Threat Detection & Response Test ===\n")
    
    for event in test_events:
        threat = detect_threat(event)
        if threat:
            print(f"Threat: {threat['name']} (Level: {threat['level']})")
            response = respond_to_threat(threat["threat_id"])
            print(f"Response: {response['action']}\n")
    
    stats = detector.get_statistics()
    print(f"\nStatistics: {json.dumps(stats, indent=2)}")


# ── ARDF wiring: counter-detection for offensive runs ─────────
# Feed HTTP response signals; get OPSEC advice when THEY react to us.

_HOSTILE = {403, 406, 429, 503}


class CounterWatch:
    """Tracks hostile response signals across an assessment."""

    def __init__(self):
        self.detector = ThreatDetector()
        self.hostile = 0
        self.total = 0

    def record(self, status: int, url: str = "", body: str = "") -> None:
        self.total += 1
        lowered = (body or "")[:2000].lower()
        captcha = "captcha" in lowered or "challenge" in lowered
        if status in _HOSTILE or captcha:
            self.hostile += 1
            self.detector.detect({
                "name": f"defense-reaction {status}",
                "source": "counterdetect",
                "target": url,
                "priority": 8 if status == 429 or captcha else 5,
                "signature": f"http-{status}",
                "context": {"url": url},
            })

    def advise(self) -> dict:
        """OPSEC recommendation based on hostile ratio."""
        if self.total == 0:
            return {"level": "none", "advice": "no signals yet"}
        ratio = self.hostile / max(self.total, 1)
        if ratio >= 0.5 or self.hostile >= 10:
            return {"level": "critical",
                    "advice": "PAUSE + switch OPSEC quiet + rotate egress (Tor NEWNYM)"}
        if ratio >= 0.2 or self.hostile >= 4:
            return {"level": "high",
                    "advice": "drop to OPSEC quiet, enable proxy rotation"}
        if self.hostile >= 1:
            return {"level": "medium",
                    "advice": "watch: some blocking detected, keep pace low"}
        return {"level": "low", "advice": "no defense reaction observed"}

    def summary(self) -> dict:
        return {"total": self.total, "hostile": self.hostile,
                **self.advise()}


_watch = None


def get_watch() -> CounterWatch:
    global _watch
    if _watch is None:
        _watch = CounterWatch()
    return _watch
