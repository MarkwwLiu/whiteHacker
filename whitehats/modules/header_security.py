"""Security Headers check module."""

import logging

import requests

from whitehats.models.target import Target
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

# Required security headers and their expected values
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "description": "HTTP Strict Transport Security (HSTS) header is missing.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
        "cwe_id": "CWE-319",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "expected": "nosniff",
        "description": "X-Content-Type-Options header is missing or incorrect.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "cwe_id": "CWE-16",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header is missing, risk of clickjacking.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
        "cwe_id": "CWE-1021",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "Content-Security-Policy header is missing.",
        "remediation": "Implement a Content-Security-Policy header to prevent XSS and data injection.",
        "cwe_id": "CWE-16",
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "X-XSS-Protection header is missing.",
        "remediation": "Add 'X-XSS-Protection: 1; mode=block' header (or rely on CSP).",
        "cwe_id": "CWE-79",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header is missing.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "cwe_id": "CWE-116",
    },
    "Permissions-Policy": {
        "severity": Severity.INFO,
        "description": "Permissions-Policy header is missing.",
        "remediation": "Add Permissions-Policy header to control browser feature access.",
        "cwe_id": None,
    },
}


class HeaderSecurityModule(BaseModule):
    name = "header_security"
    description = "Checks for missing or misconfigured security headers"

    def run(
        self, target: Target, baseline_response: requests.Response
    ) -> list[Vulnerability]:
        findings = []

        for header_name, info in SECURITY_HEADERS.items():
            header_value = baseline_response.headers.get(header_name)

            if header_value is None:
                findings.append(
                    Vulnerability(
                        name=f"Missing Security Header: {header_name}",
                        severity=info["severity"],
                        module=self.name,
                        description=info["description"],
                        target_url=target.url,
                        evidence=f"Header '{header_name}' not found in response.",
                        remediation=info["remediation"],
                        cwe_id=info.get("cwe_id"),
                    )
                )
            elif "expected" in info and header_value.lower() != info["expected"].lower():
                findings.append(
                    Vulnerability(
                        name=f"Misconfigured Security Header: {header_name}",
                        severity=Severity.LOW,
                        module=self.name,
                        description=f"Header '{header_name}' has unexpected value: '{header_value}'.",
                        target_url=target.url,
                        evidence=f"{header_name}: {header_value}",
                        remediation=info["remediation"],
                        cwe_id=info.get("cwe_id"),
                    )
                )

        # Check for information-leaking headers
        for dangerous_header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
            value = baseline_response.headers.get(dangerous_header)
            if value:
                findings.append(
                    Vulnerability(
                        name=f"Information Disclosure via Header: {dangerous_header}",
                        severity=Severity.INFO,
                        module=self.name,
                        description=f"Server exposes '{dangerous_header}' header with value '{value}'.",
                        target_url=target.url,
                        evidence=f"{dangerous_header}: {value}",
                        remediation=f"Remove or suppress the '{dangerous_header}' header.",
                        cwe_id="CWE-200",
                    )
                )

        return findings
