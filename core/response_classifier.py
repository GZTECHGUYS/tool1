"""
core/response_classifier.py
───────────────────────────
Response classifier for ARDF.

Enhanced with Cloudflare-aware classification:
  - Detects Cloudflare challenge pages
  - Classifies WAF block responses
  - Identifies origin vs. CDN responses
  - Categorizes error responses
  - Extracts rate-limit information

The classifier analyses tool outputs and HTTP responses
to determine the nature of the response and suggest actions.
"""

import re
import json
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from modules.logger import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Response Types
# ─────────────────────────────────────────────────────────────

class ResponseType(Enum):
    """Type of response received."""
    SUCCESS = "success"
    CLOUDFLARE_CHALLENGE = "cloudflare_challenge"
    CLOUDFLARE_BLOCK = "cloudflare_block"
    WAF_BLOCK = "waf_block"
    RATE_LIMITED = "rate_limited"
    SERVER_ERROR = "server_error"
    CLIENT_ERROR = "client_error"
    REDIRECT = "redirect"
    TIMEOUT = "timeout"
    EMPTY = "empty"
    MALFORMED = "malformed"
    ORIGIN = "origin"
    CACHED = "cached"
    AUTH_REQUIRED = "auth_required"
    UNKNOWN = "unknown"


@dataclass
class ClassifiedResponse:
    """Classified response with metadata."""
    response_type: ResponseType
    confidence: float
    evidence: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    status_code: Optional[int] = None
    waf_type: Optional[str] = None
    rate_limit_info: Optional[Dict] = None
    redirect_url: Optional[str] = None
    challenge_type: Optional[str] = None  # js, captcha, etc.
    origin_ip: Optional[str] = None
    is_cached: bool = False
    suggested_action: str = ""


# ─────────────────────────────────────────────────────────────
# Response Classifier
# ─────────────────────────────────────────────────────────────

class ResponseClassifier:
    """
    Classify HTTP responses and tool outputs with Cloudflare awareness.
    """

    def __init__(self, logger: Optional[ARDFLogger] = None):
        self.logger = logger or get_logger("classifier")
        self._patterns = self._init_patterns()

    def _init_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Initialize regex patterns for classification."""
        return {
            "cloudflare": [
                re.compile(r"Cloudflare", re.I),
                re.compile(r"cf-", re.I),
                re.compile(r"cdn-cgi", re.I),
                re.compile(r"challenge-platform", re.I),
                re.compile(r"ray-id", re.I),
                re.compile(r"x-robot-tag", re.I)
            ],
            "waf": [
                re.compile(r"ModSecurity", re.I),
                re.compile(r"Web Application Firewall", re.I),
                re.compile(r"WAF", re.I),
                re.compile(r"Akamai", re.I),
                re.compile(r"CloudFront", re.I),
                re.compile(r"Imperva", re.I),
                re.compile(r"Incapsula", re.I)
            ],
            "rate_limit": [
                re.compile(r"rate limit", re.I),
                re.compile(r"too many requests", re.I),
                re.compile(r"429", re.I),
                re.compile(r"x-ratelimit", re.I),
                re.compile(r"retry-after", re.I)
            ],
            "challenge": [
                re.compile(r"captcha", re.I),
                re.compile(r"security check", re.I),
                re.compile(r"verifying", re.I),
                re.compile(r"please wait", re.I),
                re.compile(r"browser check", re.I)
            ],
            "error": [
                re.compile(r"error", re.I),
                re.compile(r"exception", re.I),
                re.compile(r"fatal", re.I),
                re.compile(r"panic", re.I)
            ]
        }

    # ── Classification methods ──────────────────────────────

    def classify_http_response(
        self,
        content: str,
        headers: Dict[str, str],
        status_code: int,
        url: str = ""
    ) -> ClassifiedResponse:
        """
        Classify an HTTP response.
        """
        evidence = []
        response_type = ResponseType.UNKNOWN
        confidence = 0.0
        waf_type = None
        challenge_type = None
        rate_limit_info = None
        redirect_url = None
        is_cached = False
        origin_ip = None
        suggested_action = ""

        # Check status code first
        if status_code >= 500:
            response_type = ResponseType.SERVER_ERROR
            confidence = 0.9
            suggested_action = "Retry with backoff"
        elif status_code == 429:
            response_type = ResponseType.RATE_LIMITED
            confidence = 0.95
            suggested_action = "Increase delay between requests"
            if "retry-after" in headers:
                try:
                    rate_limit_info = {"retry_after": int(headers["retry-after"])}
                except ValueError:
                    pass
        elif status_code == 403:
            # Check if Cloudflare block
            for pattern in self._patterns["cloudflare"]:
                if pattern.search(content or ""):
                    response_type = ResponseType.CLOUDFLARE_BLOCK
                    confidence = 0.9
                    waf_type = "cloudflare"
                    suggested_action = "Try bypass techniques"
                    break
            if response_type == ResponseType.UNKNOWN:
                response_type = ResponseType.WAF_BLOCK
                confidence = 0.7
                suggested_action = "Check WAF rules or try different vectors"
        elif status_code == 302:
            response_type = ResponseType.REDIRECT
            confidence = 0.9
            redirect_url = headers.get("location", "")
            suggested_action = f"Follow redirect to {redirect_url[:50]}"

        # Check content for Cloudflare
        if response_type == ResponseType.UNKNOWN:
            for pattern in self._patterns["cloudflare"]:
                if pattern.search(content or ""):
                    response_type = ResponseType.CLOUDFLARE_CHALLENGE
                    confidence = 0.8
                    waf_type = "cloudflare"
                    evidence.append("Cloudflare signature found")
                    # Check challenge type
                    if "captcha" in (content or "").lower():
                        challenge_type = "captcha"
                    elif "browser" in (content or "").lower():
                        challenge_type = "js_challenge"
                    suggested_action = "Solve challenge or use bypass"
                    break

        # Check for rate limiting
        if response_type == ResponseType.UNKNOWN:
            for pattern in self._patterns["rate_limit"]:
                if pattern.search(content or ""):
                    response_type = ResponseType.RATE_LIMITED
                    confidence = 0.8
                    suggested_action = "Increase delay"
                    break

        # Check for WAF
        if response_type == ResponseType.UNKNOWN:
            for pattern in self._patterns["waf"]:
                if pattern.search(content or ""):
                    response_type = ResponseType.WAF_BLOCK
                    confidence = 0.7
                    waf_type = pattern.pattern
                    suggested_action = "Bypass WAF or use different vector"
                    break

        # Check if origin response (not CF)
        if response_type == ResponseType.UNKNOWN and status_code < 400:
            if "server" in headers:
                if "cloudflare" not in headers.get("server", "").lower():
                    response_type = ResponseType.ORIGIN
                    confidence = 0.7
                    suggested_action = "Direct origin attack possible"
                    # Try to extract origin IP from headers
                    if "x-forwarded-for" in headers:
                        origin_ip = headers["x-forwarded-for"].split(",")[0].strip()

        # Cache detection
        if "cf-cache-status" in headers:
            is_cached = True
            if response_type == ResponseType.UNKNOWN:
                response_type = ResponseType.CACHED
                confidence = 0.6

        # Default success
        if response_type == ResponseType.UNKNOWN and status_code < 400:
            response_type = ResponseType.SUCCESS
            confidence = 0.7
            suggested_action = "Proceed"

        return ClassifiedResponse(
            response_type=response_type,
            confidence=confidence,
            evidence=evidence,
            headers=headers,
            status_code=status_code,
            waf_type=waf_type,
            rate_limit_info=rate_limit_info,
            redirect_url=redirect_url,
            challenge_type=challenge_type,
            origin_ip=origin_ip,
            is_cached=is_cached,
            suggested_action=suggested_action
        )

    def classify_http(self, status_code: int, content: str = "", headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Compatibility method used by the orchestration layer tests."""
        headers = headers or {}
        result = {
            "success": status_code < 400 and status_code != 0,
            "status_class": "success" if status_code < 400 and status_code != 0 else "error",
            "status_code": status_code,
            "rate_limited": status_code == 429,
            "timed_out": status_code == 0,
            "auth_required": status_code == 403,
            "waf_detected": "cloudflare" in str(content).lower() or "cloudflare" in str(headers).lower(),
            "waf_type": "cloudflare" if "cloudflare" in str(content).lower() else None,
            "failure_type": None,
            "has_findings": "vulnerable" in str(content).lower() or "found" in str(content).lower() or "injectable" in str(content).lower(),
        }
        if status_code == 429:
            result["failure_type"] = "rate_limited"
        elif status_code == 0:
            result["failure_type"] = "timeout"
        elif status_code == 403:
            result["failure_type"] = "auth_required"
        elif status_code >= 400:
            result["failure_type"] = "http_error"
        return result

    def classify_tool_output(self, stdout: str, stderr: str) -> ClassifiedResponse:
        """
        Classify tool output (stdout/stderr).
        """
        combined = f"{stdout}\n{stderr}"
        evidence = []
        response_type = ResponseType.UNKNOWN
        confidence = 0.5

        # Check for error patterns
        for pattern in self._patterns["error"]:
            if pattern.search(combined):
                response_type = ResponseType.CLIENT_ERROR
                confidence = 0.8
                evidence.append(f"Error pattern: {pattern.pattern}")
                break

        # Check for Cloudflare in output
        for pattern in self._patterns["cloudflare"]:
            if pattern.search(combined):
                if response_type == ResponseType.UNKNOWN:
                    response_type = ResponseType.CLOUDFLARE_CHALLENGE
                    confidence = 0.7
                evidence.append(f"Cloudflare pattern: {pattern.pattern}")
                break

        # Check for rate limiting
        for pattern in self._patterns["rate_limit"]:
            if pattern.search(combined):
                response_type = ResponseType.RATE_LIMITED
                confidence = 0.8
                evidence.append(f"Rate limit pattern: {pattern.pattern}")
                break

        # Empty output
        if not combined.strip():
            response_type = ResponseType.EMPTY
            confidence = 0.9
            evidence.append("Empty output")

        # Success if no errors
        if response_type == ResponseType.UNKNOWN and stdout.strip():
            response_type = ResponseType.SUCCESS
            confidence = 0.7
            evidence.append("Non-empty stdout")

        return ClassifiedResponse(
            response_type=response_type,
            confidence=confidence,
            evidence=evidence,
            suggested_action=self._get_action_for_type(response_type)
        )

    def _get_action_for_type(self, response_type: ResponseType) -> str:
        """Get suggested action for response type."""
        actions = {
            ResponseType.CLOUDFLARE_CHALLENGE: "Use Cloudflare bypass techniques",
            ResponseType.CLOUDFLARE_BLOCK: "IP is blocked by Cloudflare. Use proxy or rotation",
            ResponseType.WAF_BLOCK: "WAF detected. Try obfuscation or different vector",
            ResponseType.RATE_LIMITED: "Increase delay, add jitter, or rotate IP",
            ResponseType.SERVER_ERROR: "Retry with backoff (exponential)",
            ResponseType.ORIGIN: "Direct origin access possible",
            ResponseType.CACHED: "Cache hit — may need to bypass cache",
            ResponseType.REDIRECT: "Follow redirect",
            ResponseType.SUCCESS: "Proceed",
            ResponseType.EMPTY: "Check tool configuration",
            ResponseType.TIMEOUT: "Increase timeout or check network",
            ResponseType.AUTH_REQUIRED: "Add authentication",
            ResponseType.MALFORMED: "Check input format"
        }
        return actions.get(response_type, "Analyze manually")

    # ── Combined classification ──────────────────────────────

    def classify(
        self,
        stdout: str = "",
        stderr: str = "",
        return_code: int = 0,
        http_status: int = 0,
        http_headers: Dict = None,
        http_content: str = "",
        url: str = ""
    ) -> Dict[str, Any]:
        """
        Classify combined HTTP response and tool output.
        Compatibility wrapper accepts both the legacy and new call shapes.
        """
        if isinstance(stdout, dict):
            # Backward-compat input shape if someone passed a dict-like object
            stdout = stdout.get("stdout", "")
            stderr = stdout.get("stderr", "")
            return_code = stdout.get("return_code", 0)

        if http_status == 0 and return_code != 0 and ("cloudflare" in (stderr or stdout).lower() or "403" in (stderr or stdout)):
            http_status = 403

        http_result = self.classify_http_response(
            http_content,
            http_headers or {},
            http_status,
            url
        )
        tool_result = self.classify_tool_output(stdout, stderr)

        combined_type = http_result.response_type
        if combined_type == ResponseType.UNKNOWN:
            combined_type = tool_result.response_type

        evidence = list(set(http_result.evidence + tool_result.evidence))
        cloudflare_involved = (
            combined_type in [
                ResponseType.CLOUDFLARE_CHALLENGE,
                ResponseType.CLOUDFLARE_BLOCK
            ] or
            any("cloudflare" in e.lower() for e in evidence) or
            http_result.waf_type == "cloudflare"
        )

        combined_text = (stdout + stderr).lower()
        waf_text = "cloudflare" if "cloudflare" in combined_text else "modsecurity" if "mod_security" in combined_text or "modsecurity" in combined_text else "waf" if "waf" in combined_text else None
        result = {
            "response_type": combined_type.value,
            "confidence": max(http_result.confidence, tool_result.confidence),
            "evidence": evidence,
            "status_code": http_result.status_code,
            "waf_type": http_result.waf_type or waf_text,
            "cloudflare_involved": cloudflare_involved or waf_text == "cloudflare",
            "rate_limit_info": http_result.rate_limit_info,
            "origin_ip": http_result.origin_ip,
            "is_cached": http_result.is_cached,
            "suggested_action": http_result.suggested_action or tool_result.suggested_action,
            "headers": http_result.headers,
            "redirect_url": http_result.redirect_url,
            "challenge_type": http_result.challenge_type,
            "waf_detected": cloudflare_involved or http_result.waf_type is not None or waf_text is not None,
            "rate_limited": combined_type == ResponseType.RATE_LIMITED or "rate limit" in combined_text or "429" in combined_text or "too many requests" in combined_text,
            "timed_out": "timed out" in combined_text or return_code == 124,
            "auth_required": "401" in combined_text or "unauthorized" in combined_text or "403" in combined_text,
            "binary_missing": "command not found" in combined_text or return_code == 127,
            "failure_type": "rate_limited" if "429" in combined_text or "rate limit" in combined_text or "too many requests" in combined_text else (
                "timeout" if "timed out" in combined_text or return_code == 124 else (
                    "binary_missing" if "command not found" in combined_text or return_code == 127 else (
                        "auth_required" if "unauthorized" in combined_text or "401" in combined_text or "403" in combined_text else None
                    )
                )
            ),
            "success": combined_type in {ResponseType.SUCCESS, ResponseType.ORIGIN, ResponseType.CACHED} or "vulnerable" in combined_text or "found" in combined_text or "[+]" in combined_text,
            "has_findings": "vulnerable" in combined_text or "found" in combined_text or "injectable" in combined_text or "[+]" in combined_text,
            "no_results": not combined_text.strip() and return_code == 0,
        }
        return result

    def summarise(self, result: Dict[str, Any]) -> str:
        """Legacy summary wrapper for the test suite."""
        if result.get("waf_detected"):
            return "WAF detected in the response or output."
        if result.get("has_findings") or result.get("success"):
            return "Findings were detected successfully."
        if result.get("rate_limited"):
            return "The endpoint is rate limited."
        if result.get("timed_out"):
            return "The request timed out."
        if result.get("binary_missing"):
            return "A required binary is missing."
        return "No actionable result was detected."

    def classify_http(self, status_code: int, content: str = "", headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Legacy alias used by tests and compatibility callers."""
        return self.classify_http_response(content, headers or {}, status_code).asdict() if hasattr(self.classify_http_response(content, headers or {}, status_code), "asdict") else {
            "success": status_code < 400 and status_code != 0,
            "status_class": "success" if status_code < 400 and status_code != 0 else "error",
            "status_code": status_code,
            "rate_limited": status_code == 429,
            "timed_out": status_code == 0,
            "auth_required": status_code in (401, 403),
            "waf_detected": "cloudflare" in str(content).lower() or "cloudflare" in str(headers or {}).lower(),
            "waf_type": "cloudflare" if "cloudflare" in str(content).lower() else None,
            "failure_type": "rate_limited" if status_code == 429 else ("timeout" if status_code == 0 else ("auth_required" if status_code in (401, 403) else None)),
        }


# ─────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────

def classify_response(
    content: str = "",
    headers: Dict = None,
    status_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    url: str = "",
    logger: Optional[ARDFLogger] = None
) -> Dict[str, Any]:
    """
    Convenience function to classify a response.
    """
    if logger is None:
        logger = get_logger("classifier")

    classifier = ResponseClassifier(logger)
    result = classifier.classify(content, headers, status_code, stdout, stderr, url)

    logger.info(
        f"Classified as {result['response_type']} "
        f"(confidence: {result['confidence']:.2f}, "
        f"CF: {result['cloudflare_involved']})"
    )

    return result