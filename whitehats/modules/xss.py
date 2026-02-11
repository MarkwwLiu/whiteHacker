"""Cross-Site Scripting (XSS) security test module."""

import logging
from pathlib import Path

import requests

from whitehats.models.target import APITarget, Target, URLTarget
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

PAYLOADS_FILE = Path(__file__).parent.parent / "payloads" / "xss_payloads.txt"


class XSSModule(BaseModule):
    name = "xss"
    description = "Tests for Cross-Site Scripting (XSS) vulnerabilities"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> list[str]:
        if PAYLOADS_FILE.exists():
            return [
                line.strip()
                for line in PAYLOADS_FILE.read_text().splitlines()
                if line.strip()
            ]
        return ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

    def run(
        self, target: Target, baseline_response: requests.Response
    ) -> list[Vulnerability]:
        findings = []

        if isinstance(target, APITarget):
            findings.extend(self._test_api_params(target))
            findings.extend(self._test_api_body(target))
        elif isinstance(target, URLTarget):
            findings.extend(self._test_url_params(target))

        return findings

    def _test_api_params(self, target: APITarget) -> list[Vulnerability]:
        findings = []
        for param_name in target.params:
            for payload in self.payloads:
                injected_params = dict(target.params)
                injected_params[param_name] = payload

                resp = self._send(
                    method=target.method.value,
                    url=target.url,
                    headers=target.get_request_headers(),
                    params=injected_params,
                    json_data=target.body,
                )
                if resp and self._detect_xss(resp, payload):
                    findings.append(
                        Vulnerability(
                            name=f"Reflected XSS in parameter: {param_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=f"XSS payload reflected in response for parameter '{param_name}'.",
                            target_url=target.url,
                            evidence=f"Payload: {payload}",
                            request_detail=f"{target.method.value} {target.url}?{param_name}={payload}",
                            response_detail=resp.text[:500],
                            remediation="Encode all user-supplied output. Use Content-Security-Policy headers.",
                            cwe_id="CWE-79",
                        )
                    )
                    break
        return findings

    def _test_api_body(self, target: APITarget) -> list[Vulnerability]:
        findings = []
        if not target.body or not isinstance(target.body, dict):
            return findings

        for field_name, field_value in target.body.items():
            if not isinstance(field_value, str):
                continue
            for payload in self.payloads:
                injected_body = dict(target.body)
                injected_body[field_name] = payload

                resp = self._send(
                    method=target.method.value,
                    url=target.url,
                    headers=target.get_request_headers(),
                    params=target.params,
                    json_data=injected_body,
                )
                if resp and self._detect_xss(resp, payload):
                    findings.append(
                        Vulnerability(
                            name=f"Reflected XSS in body field: {field_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=f"XSS payload reflected in response for body field '{field_name}'.",
                            target_url=target.url,
                            evidence=f"Payload: {payload}",
                            request_detail=f"{target.method.value} {target.url} body[{field_name}]={payload}",
                            response_detail=resp.text[:500],
                            remediation="Encode all user-supplied output. Use Content-Security-Policy headers.",
                            cwe_id="CWE-79",
                        )
                    )
                    break
        return findings

    def _test_url_params(self, target: URLTarget) -> list[Vulnerability]:
        findings = []
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            for payload in self.payloads:
                injected = dict(params)
                injected[param_name] = [payload]
                new_query = urlencode(injected, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = self._send(method="GET", url=test_url, headers=dict(target.headers))
                if resp and self._detect_xss(resp, payload):
                    findings.append(
                        Vulnerability(
                            name=f"Reflected XSS in URL parameter: {param_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=f"XSS payload reflected in response for URL parameter '{param_name}'.",
                            target_url=target.url,
                            evidence=f"Payload: {payload}",
                            request_detail=f"GET {test_url}",
                            response_detail=resp.text[:500],
                            remediation="Encode all user-supplied output. Use Content-Security-Policy headers.",
                            cwe_id="CWE-79",
                        )
                    )
                    break
        return findings

    def _detect_xss(self, response: requests.Response, payload: str) -> bool:
        """Check if the XSS payload is reflected unencoded in the response."""
        content_type = response.headers.get("Content-Type", "")
        body = response.text

        # Check if payload appears unencoded in the response body
        if payload in body:
            # Only flag if response is HTML-like (not pure JSON API responses)
            if "html" in content_type or "text" in content_type:
                return True
            # Even in JSON, reflected payloads can be dangerous if rendered
            if payload in body and "<script" in payload.lower():
                return True

        return False
