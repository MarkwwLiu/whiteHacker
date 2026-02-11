"""CORS Misconfiguration security test module."""

import logging

import requests

from whitehats.models.target import Target
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.modules.base_module import BaseModule

logger = logging.getLogger(__name__)


class CORSMisconfigModule(BaseModule):
    name = "cors_misconfig"
    description = "Tests for CORS misconfiguration vulnerabilities"

    def run(
        self, target: Target, baseline_response: requests.Response
    ) -> list[Vulnerability]:
        findings = []

        findings.extend(self._check_wildcard_origin(target))
        findings.extend(self._check_origin_reflection(target))
        findings.extend(self._check_null_origin(target))

        return findings

    def _check_wildcard_origin(self, target: Target) -> list[Vulnerability]:
        """Check if server allows wildcard (*) origin."""
        findings = []
        resp = self._send(
            method="GET",
            url=target.url,
            headers={"Origin": "https://evil.example.com"},
        )
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                findings.append(
                    Vulnerability(
                        name="CORS Wildcard Origin",
                        severity=Severity.MEDIUM,
                        module=self.name,
                        description="Server allows any origin via wildcard (*) CORS policy.",
                        target_url=target.url,
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation="Restrict Access-Control-Allow-Origin to specific trusted domains.",
                        cwe_id="CWE-942",
                    )
                )
                # Check if credentials are also allowed (critical combination)
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acac.lower() == "true":
                    findings.append(
                        Vulnerability(
                            name="CORS Wildcard with Credentials",
                            severity=Severity.HIGH,
                            module=self.name,
                            description="Server allows wildcard origin AND credentials. This is a critical CORS misconfiguration.",
                            target_url=target.url,
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            remediation="Never use wildcard origin with credentials. Whitelist specific origins.",
                            cwe_id="CWE-942",
                        )
                    )
        return findings

    def _check_origin_reflection(self, target: Target) -> list[Vulnerability]:
        """Check if server reflects arbitrary Origin headers."""
        findings = []
        evil_origin = "https://attacker.evil.com"
        resp = self._send(
            method="GET",
            url=target.url,
            headers={"Origin": evil_origin},
        )
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == evil_origin:
                severity = Severity.MEDIUM
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acac.lower() == "true":
                    severity = Severity.HIGH

                findings.append(
                    Vulnerability(
                        name="CORS Origin Reflection",
                        severity=severity,
                        module=self.name,
                        description="Server reflects arbitrary Origin header in Access-Control-Allow-Origin.",
                        target_url=target.url,
                        evidence=f"Sent Origin: {evil_origin}, Received ACAO: {acao}",
                        remediation="Validate Origin against a whitelist of trusted domains.",
                        cwe_id="CWE-942",
                    )
                )
        return findings

    def _check_null_origin(self, target: Target) -> list[Vulnerability]:
        """Check if server accepts null origin."""
        findings = []
        resp = self._send(
            method="GET",
            url=target.url,
            headers={"Origin": "null"},
        )
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "null":
                findings.append(
                    Vulnerability(
                        name="CORS Null Origin Allowed",
                        severity=Severity.MEDIUM,
                        module=self.name,
                        description="Server accepts 'null' origin, which can be exploited via sandboxed iframes.",
                        target_url=target.url,
                        evidence=f"Sent Origin: null, Received ACAO: {acao}",
                        remediation="Do not allow 'null' as a valid origin in CORS policy.",
                        cwe_id="CWE-942",
                    )
                )
        return findings
