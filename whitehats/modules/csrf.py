"""CSRF (Cross-Site Request Forgery) security test module."""

import logging

import requests

from whitehats.models.target import APITarget, Target
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.modules.base_module import BaseModule

logger = logging.getLogger(__name__)


class CSRFModule(BaseModule):
    name = "csrf"
    description = "Tests for Cross-Site Request Forgery vulnerabilities"

    def run(
        self, target: Target, baseline_response: requests.Response
    ) -> list[Vulnerability]:
        findings = []

        if not isinstance(target, APITarget):
            return findings

        # CSRF is primarily a concern for state-changing methods
        if target.method.value in ("GET", "HEAD", "OPTIONS"):
            return findings

        findings.extend(self._check_csrf_token(target, baseline_response))
        findings.extend(self._check_samesite_cookie(baseline_response, target))

        return findings

    def _check_csrf_token(
        self, target: APITarget, baseline_response: requests.Response
    ) -> list[Vulnerability]:
        """Check if state-changing endpoints require CSRF tokens."""
        findings = []

        # Try the request without any CSRF-related headers
        headers_without_csrf = dict(target.get_request_headers())
        for key in list(headers_without_csrf.keys()):
            if "csrf" in key.lower() or "xsrf" in key.lower():
                del headers_without_csrf[key]

        resp = self._send(
            method=target.method.value,
            url=target.url,
            headers=headers_without_csrf,
            params=target.params,
            json_data=target.body,
        )

        if resp and resp.status_code < 400:
            # Request succeeded without CSRF token - potential vulnerability
            findings.append(
                Vulnerability(
                    name="Missing CSRF Protection",
                    severity=Severity.MEDIUM,
                    module=self.name,
                    description=f"State-changing endpoint ({target.method.value}) accepts requests without CSRF token.",
                    target_url=target.url,
                    evidence=f"Request without CSRF token returned status {resp.status_code}",
                    remediation="Implement CSRF tokens for all state-changing requests. Use SameSite cookie attribute.",
                    cwe_id="CWE-352",
                )
            )

        return findings

    def _check_samesite_cookie(
        self, response: requests.Response, target: APITarget
    ) -> list[Vulnerability]:
        """Check if cookies have proper SameSite attribute."""
        findings = []

        for cookie_header in response.headers.get("Set-Cookie", "").split(","):
            if not cookie_header.strip():
                continue

            cookie_lower = cookie_header.lower()
            if "samesite" not in cookie_lower:
                cookie_name = cookie_header.split("=")[0].strip()
                findings.append(
                    Vulnerability(
                        name=f"Cookie missing SameSite attribute: {cookie_name}",
                        severity=Severity.LOW,
                        module=self.name,
                        description=f"Cookie '{cookie_name}' does not have a SameSite attribute set.",
                        target_url=target.url,
                        evidence=f"Set-Cookie: {cookie_header.strip()[:200]}",
                        remediation="Set SameSite=Strict or SameSite=Lax on all cookies.",
                        cwe_id="CWE-1275",
                    )
                )

        return findings
