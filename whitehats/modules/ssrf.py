"""Server-Side Request Forgery (SSRF) security test module."""

import logging
import re
from pathlib import Path

import requests

from whitehats.models.target import APITarget, Target, URLTarget
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

PAYLOADS_FILE = Path(__file__).parent.parent / "payloads" / "ssrf_payloads.txt"

# Patterns that indicate a successful SSRF (internal content leaked)
SSRF_INDICATORS = [
    r"root:.*:0:0:",  # /etc/passwd content
    r"ami-id",  # AWS metadata
    r"instance-id",  # Cloud metadata
    r"local-hostname",  # Cloud metadata
    r"computeMetadata",  # GCP metadata
    r"SSH-\d",  # SSH banner
    r"REDIS",  # Redis banner
    r"elasticsearch",  # Elasticsearch
    r"MongoDB",  # MongoDB
]


class SSRFModule(BaseModule):
    name = "ssrf"
    description = "Tests for Server-Side Request Forgery (SSRF) vulnerabilities"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> list[str]:
        """Load SSRF payloads from file."""
        if PAYLOADS_FILE.exists():
            return [
                line.strip()
                for line in PAYLOADS_FILE.read_text().splitlines()
                if line.strip()
            ]
        return [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
        ]

    def run(
        self, target: Target, baseline_response: requests.Response
    ) -> list[Vulnerability]:
        findings = []
        baseline_length = len(baseline_response.content)

        if isinstance(target, APITarget):
            findings.extend(self._test_api_params(target, baseline_length))
            findings.extend(self._test_api_body(target, baseline_length))
        elif isinstance(target, URLTarget):
            findings.extend(self._test_url_params(target, baseline_length))

        return findings

    def _test_api_params(
        self, target: APITarget, baseline_length: int
    ) -> list[Vulnerability]:
        """Test query parameters for SSRF."""
        findings = []
        url_like_params = self._find_url_like_params(target.params)

        for param_name in url_like_params:
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
                if resp and self._detect_ssrf(resp, baseline_length):
                    findings.append(
                        Vulnerability(
                            name=f"SSRF in parameter: {param_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=(
                                f"Possible SSRF detected in query parameter '{param_name}'. "
                                "The server may be making requests to internal resources."
                            ),
                            target_url=target.url,
                            evidence=f"Payload: {payload} | Status: {resp.status_code}",
                            request_detail=f"{target.method.value} {target.url}?{param_name}={payload}",
                            response_detail=resp.text[:500],
                            remediation=(
                                "Validate and sanitize all URLs. Use an allowlist of permitted domains. "
                                "Block requests to internal/private IP ranges. "
                                "Disable unnecessary URL schemes."
                            ),
                            cwe_id="CWE-918",
                        )
                    )
                    break
        return findings

    def _test_api_body(
        self, target: APITarget, baseline_length: int
    ) -> list[Vulnerability]:
        """Test request body fields for SSRF."""
        findings = []
        if not target.body or not isinstance(target.body, dict):
            return findings

        url_like_fields = self._find_url_like_params(target.body)

        for field_name in url_like_fields:
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
                if resp and self._detect_ssrf(resp, baseline_length):
                    findings.append(
                        Vulnerability(
                            name=f"SSRF in body field: {field_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=(
                                f"Possible SSRF detected in body field '{field_name}'. "
                                "The server may be making requests to internal resources."
                            ),
                            target_url=target.url,
                            evidence=f"Payload: {payload} | Status: {resp.status_code}",
                            request_detail=f"{target.method.value} {target.url} body[{field_name}]={payload}",
                            response_detail=resp.text[:500],
                            remediation=(
                                "Validate and sanitize all URLs. Use an allowlist of permitted domains. "
                                "Block requests to internal/private IP ranges."
                            ),
                            cwe_id="CWE-918",
                        )
                    )
                    break
        return findings

    def _test_url_params(
        self, target: URLTarget, baseline_length: int
    ) -> list[Vulnerability]:
        """Test URL query parameters for SSRF."""
        findings = []
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        url_like_params = self._find_url_like_params(
            {k: v[0] if v else "" for k, v in params.items()}
        )

        for param_name in url_like_params:
            for payload in self.payloads:
                injected = dict(params)
                injected[param_name] = [payload]
                new_query = urlencode(injected, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = self._send(method="GET", url=test_url, headers=dict(target.headers))
                if resp and self._detect_ssrf(resp, baseline_length):
                    findings.append(
                        Vulnerability(
                            name=f"SSRF in URL parameter: {param_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=f"Possible SSRF detected in URL parameter '{param_name}'.",
                            target_url=target.url,
                            evidence=f"Payload: {payload} | Status: {resp.status_code}",
                            request_detail=f"GET {test_url}",
                            response_detail=resp.text[:500],
                            remediation="Validate and sanitize all URLs. Use an allowlist of permitted domains.",
                            cwe_id="CWE-918",
                        )
                    )
                    break
        return findings

    def _find_url_like_params(self, params: dict) -> list[str]:
        """Identify parameters that likely contain URLs or paths."""
        url_keywords = [
            "url", "uri", "path", "dest", "redirect", "target", "link",
            "goto", "next", "return", "callback", "fetch", "load", "src",
            "source", "file", "page", "ref", "domain", "host", "endpoint",
            "webhook", "proxy", "image", "img",
        ]
        result = []
        for name, value in params.items():
            name_lower = name.lower()
            # Check if param name suggests a URL
            if any(kw in name_lower for kw in url_keywords):
                result.append(name)
            # Check if param value looks like a URL
            elif isinstance(value, str) and (
                value.startswith("http") or value.startswith("/")
            ):
                result.append(name)
        # If no URL-like params found, test all params
        if not result:
            result = list(params.keys())
        return result

    def _detect_ssrf(self, response: requests.Response, baseline_length: int) -> bool:
        """Detect potential SSRF based on response analysis."""
        body = response.text

        # Check for internal content indicators
        for pattern in SSRF_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                return True

        # Significant response change may indicate internal content
        if baseline_length > 0:
            ratio = len(response.content) / baseline_length
            if ratio > 3.0 and response.status_code == 200:
                return True

        return False
