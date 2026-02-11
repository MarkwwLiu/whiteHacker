"""Information Disclosure security test module."""

import logging
import re

import requests

from whitehats.models.target import Target
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

# Patterns that may indicate information disclosure
SENSITIVE_PATTERNS = {
    "email_address": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "severity": Severity.INFO,
        "description": "Email address found in response",
    },
    "ip_address": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "severity": Severity.LOW,
        "description": "Internal IP address found in response",
    },
    "stack_trace": {
        "pattern": r"(?:Traceback \(most recent call last\)|at [\w.]+\([\w]+\.java:\d+\)|Exception in thread|Fatal error:.*on line \d+)",
        "severity": Severity.MEDIUM,
        "description": "Stack trace or error details found in response",
    },
    "api_key_pattern": {
        "pattern": r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?[\w\-]{16,}",
        "severity": Severity.HIGH,
        "description": "Possible API key found in response",
    },
    "debug_mode": {
        "pattern": r"(?:DEBUG\s*=\s*True|debug\s*mode|DJANGO_DEBUG|APP_DEBUG)",
        "severity": Severity.MEDIUM,
        "description": "Debug mode indicator found in response",
    },
    "database_info": {
        "pattern": r"(?:mysql://|postgres://|mongodb://|sqlite:///|jdbc:)",
        "severity": Severity.HIGH,
        "description": "Database connection string found in response",
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "Private key found in response",
    },
}


class InfoDisclosureModule(BaseModule):
    name = "info_disclosure"
    description = "Checks for information disclosure in responses"

    def run(
        self, target: Target, baseline_response: requests.Response
    ) -> list[Vulnerability]:
        findings = []

        findings.extend(self._check_sensitive_data(target, baseline_response))
        findings.extend(self._check_error_pages(target))

        return findings

    def _check_sensitive_data(
        self, target: Target, response: requests.Response
    ) -> list[Vulnerability]:
        """Scan response body for sensitive data patterns."""
        findings = []
        body = response.text

        for pattern_name, info in SENSITIVE_PATTERNS.items():
            matches = re.findall(info["pattern"], body, re.IGNORECASE)
            if matches:
                # Deduplicate and limit evidence
                unique_matches = list(set(matches))[:5]
                findings.append(
                    Vulnerability(
                        name=f"Information Disclosure: {pattern_name}",
                        severity=info["severity"],
                        module=self.name,
                        description=info["description"],
                        target_url=target.url,
                        evidence=f"Found {len(matches)} match(es): {unique_matches}",
                        remediation="Remove sensitive data from responses. Implement proper error handling.",
                        cwe_id="CWE-200",
                    )
                )

        return findings

    def _check_error_pages(self, target: Target) -> list[Vulnerability]:
        """Check if error pages reveal sensitive information."""
        findings = []

        # Request a non-existent path to trigger error page
        from urllib.parse import urljoin

        error_url = urljoin(target.url, "/whitehat_test_nonexistent_path_404")
        resp = self._send(method="GET", url=error_url)

        if resp and resp.status_code >= 400:
            body = resp.text
            # Check for verbose error information
            for pattern_name, info in SENSITIVE_PATTERNS.items():
                if pattern_name in ("stack_trace", "debug_mode", "database_info"):
                    matches = re.findall(info["pattern"], body, re.IGNORECASE)
                    if matches:
                        findings.append(
                            Vulnerability(
                                name=f"Verbose Error Page: {pattern_name}",
                                severity=Severity.MEDIUM,
                                module=self.name,
                                description=f"Error page reveals {pattern_name.replace('_', ' ')}.",
                                target_url=error_url,
                                evidence=f"Found in error response: {matches[:3]}",
                                remediation="Configure custom error pages that do not reveal internal details.",
                                cwe_id="CWE-209",
                            )
                        )

        return findings
