#!/usr/bin/env python3
"""Comprehensive input validation and sanitization module."""

import re
import logging
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass
from enum import Enum

__version__ = "2.1.0"
__all__ = ["InputValidator", "validate_input", "sanitize_input", "detect_injection"]

logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """Validation outcome."""
    VALID = "valid"
    INVALID = "invalid"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class ValidationReport:
    """Result of input validation."""
    input_data: str
    result: ValidationResult
    errors: List[str]
    warnings: List[str]
    score: float  # 0.0 (safe) to 1.0 (dangerous)


class InputValidator:
    """Comprehensive input validation engine."""
    
    # SQL Injection patterns
    SQL_PATTERNS = [
        r"('|\")\s*(OR|AND)\s*('|\")?",
        r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)",
        r"(--|#|/\*)",  # SQL comments
        r";\s*(DROP|DELETE|UPDATE|INSERT)",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<\s*script",
        r"javascript:",
        r"on\w+\s*=",  # Event handlers
        r"<\s*iframe",
        r"<\s*object",
        r"<\s*embed",
    ]
    
    # Command injection patterns
    CMD_PATTERNS = [
        r"([;&|`])",
        r"\$\(",  # Command substitution
        r">\s*/dev/",  # Redirection to device
    ]
    
    # Path traversal patterns
    PATH_PATTERNS = [
        r"\.\./",
        r"\.\.",
        r"%2e%2e",
        r"\.\.%2f",
    ]
    
    def __init__(self):
        """Initialize validator."""
        self.logger = logging.getLogger("InputValidator")
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Pre-compile regex patterns."""
        return {
            "sql": [re.compile(p, re.IGNORECASE) for p in self.SQL_PATTERNS],
            "xss": [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS],
            "cmd": [re.compile(p) for p in self.CMD_PATTERNS],
            "path": [re.compile(p, re.IGNORECASE) for p in self.PATH_PATTERNS],
        }
    
    def validate(self, input_data: str, input_type: str = "generic") -> ValidationReport:
        """Validate input data."""
        errors = []
        warnings = []
        risk_score = 0.0
        
        # Check length
        if len(input_data) > 10000:
            warnings.append("Input exceeds 10KB")
            risk_score += 0.1
        
        # Check for null bytes
        if "\x00" in input_data:
            errors.append("Null bytes detected")
            risk_score += 0.3
        
        # Run pattern-based checks
        sql_matches = self._check_pattern("sql", input_data)
        if sql_matches:
            errors.append(f"SQL injection patterns detected: {sql_matches}")
            risk_score += 0.4
        
        xss_matches = self._check_pattern("xss", input_data)
        if xss_matches:
            errors.append(f"XSS patterns detected: {xss_matches}")
            risk_score += 0.35
        
        cmd_matches = self._check_pattern("cmd", input_data)
        if cmd_matches:
            errors.append(f"Command injection patterns detected")
            risk_score += 0.4
        
        path_matches = self._check_pattern("path", input_data)
        if path_matches:
            errors.append(f"Path traversal patterns detected")
            risk_score += 0.35
        
        # Input type-specific checks
        if input_type == "email":
            if not self._is_valid_email(input_data):
                errors.append("Invalid email format")
                risk_score += 0.2
        
        elif input_type == "url":
            if not self._is_valid_url(input_data):
                errors.append("Invalid URL format")
                risk_score += 0.2
        
        elif input_type == "json":
            if not self._is_valid_json(input_data):
                errors.append("Invalid JSON structure")
                risk_score += 0.2
        
        # Determine overall result
        if risk_score >= 0.5:
            result = ValidationResult.MALICIOUS
        elif errors:
            result = ValidationResult.INVALID
        elif warnings:
            result = ValidationResult.SUSPICIOUS
        else:
            result = ValidationResult.VALID
        
        self.logger.info(f"Validation: {input_type} - {result.value} (score: {risk_score:.2f})")
        
        return ValidationReport(
            input_data=input_data[:100],  # Truncate for report
            result=result,
            errors=errors,
            warnings=warnings,
            score=min(risk_score, 1.0)
        )
    
    def _check_pattern(self, pattern_type: str, data: str) -> List[str]:
        """Check data against pattern type."""
        matches = []
        for pattern in self.compiled_patterns.get(pattern_type, []):
            if pattern.search(data):
                matches.append(pattern.pattern[:30])
        return matches
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url, re.IGNORECASE))
    
    def _is_valid_json(self, data: str) -> bool:
        """Validate JSON structure."""
        try:
            import json
            json.loads(data)
            return True
        except:
            return False
    
    def sanitize(self, input_data: str, sanitize_type: str = "html") -> str:
        """Sanitize input data."""
        if sanitize_type == "html":
            return self._sanitize_html(input_data)
        elif sanitize_type == "sql":
            return self._sanitize_sql(input_data)
        elif sanitize_type == "cmd":
            return self._sanitize_cmd(input_data)
        else:
            return input_data
    
    def _sanitize_html(self, data: str) -> str:
        """Remove HTML/script tags."""
        dangerous = [
            (r"<\s*script[^>]*>.*?</\s*script\s*>", "", re.IGNORECASE | re.DOTALL),
            (r"javascript:", "", re.IGNORECASE),
            (r"on\w+\s*=", "", re.IGNORECASE),
        ]
        
        result = data
        for pattern, replacement, flags in dangerous:
            result = re.sub(pattern, replacement, result, flags=flags)
        
        return result
    
    def _sanitize_sql(self, data: str) -> str:
        """Escape SQL special characters."""
        # Single quote escape
        result = data.replace("'", "''")
        # Remove/escape comments
        result = result.replace("--", "")
        result = result.replace("/*", "")
        return result
    
    def _sanitize_cmd(self, data: str) -> str:
        """Escape shell special characters."""
        dangerous_chars = "&;|`$()\\\"'"
        result = ""
        for char in data:
            if char in dangerous_chars:
                result += f"\\{char}"
            else:
                result += char
        return result
    
    def detect_injection(self, input_data: str) -> Dict[str, Any]:
        """Detect injection attacks."""
        report = self.validate(input_data)
        
        return {
            "input_sample": input_data[:50],
            "injection_detected": report.result in [ValidationResult.MALICIOUS, ValidationResult.INVALID],
            "attack_type": self._identify_attack_type(report.errors),
            "risk_score": report.score,
            "details": report.errors
        }
    
    def _identify_attack_type(self, errors: List[str]) -> Optional[str]:
        """Identify type of attack from errors."""
        for error in errors:
            if "SQL" in error:
                return "SQL Injection"
            elif "XSS" in error:
                return "Cross-Site Scripting"
            elif "Command" in error:
                return "Command Injection"
            elif "Path" in error:
                return "Path Traversal"
        return None


# Module-level validator instance
_validator = None


def get_validator() -> InputValidator:
    """Get or create global validator."""
    global _validator
    if _validator is None:
        _validator = InputValidator()
    return _validator


def validate_input(data: str, input_type: str = "generic") -> Dict[str, Any]:
    """Validate input data."""
    validator = get_validator()
    report = validator.validate(data, input_type)
    
    return {
        "result": report.result.value,
        "errors": report.errors,
        "warnings": report.warnings,
        "risk_score": report.score,
        "valid": report.result == ValidationResult.VALID
    }


def sanitize_input(data: str, sanitize_type: str = "html") -> str:
    """Sanitize input data."""
    validator = get_validator()
    return validator.sanitize(data, sanitize_type)


def detect_injection(data: str) -> Dict[str, Any]:
    """Detect injection attacks."""
    validator = get_validator()
    return validator.detect_injection(data)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s"
    )
    
    validator = get_validator()
    
    test_inputs = [
        ("test@example.com", "email"),
        ("admin' OR '1'='1", "generic"),
        ("<script>alert('xss')</script>", "generic"),
        ("../../etc/passwd", "generic"),
        ("https://example.com", "url"),
    ]
    
    print("=== Input Validation Test ===\n")
    
    for data, input_type in test_inputs:
        report = validator.validate(data, input_type)
        print(f"Input: {data}")
        print(f"Type: {input_type}")
        print(f"Result: {report.result.value} (Score: {report.score:.2f})")
        if report.errors:
            print(f"Errors: {', '.join(report.errors)}")
        print()
