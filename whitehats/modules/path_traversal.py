"""Path Traversal / Local File Inclusion (LFI) security test module."""

import logging
import re
from pathlib import Path

import requests

from whitehats.models.target import APITarget, Target, URLTarget
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

PAYLOADS_FILE = Path(__file__).parent.parent / "payloads" / "path_traversal_payloads.txt"

# Patterns indicating successful file read
FILE_CONTENT_PATTERNS = [
    r"root:.*:0:0:",  # /etc/passwd
    r"daemon:.*:/usr/sbin",  # /etc/passwd
    r"bin:.*:/bin",  # /etc/passwd
    r"\[extensions\]",  # win.ini
    r"\[fonts\]",  # win.ini
    r";\s*for 16-bit app support",  # win.ini
    r"127\.0\.0\.1\s+localhost",  # /etc/hosts
    r"::1\s+localhost",  # /etc/hosts
]


class PathTraversalModule(BaseModule):
    name = "path_traversal"
    description = "Tests for Path Traversal / Local File Inclusion (LFI) vulnerabilities"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> list[str]:
        """Load path traversal payloads from file."""
        if PAYLOADS_FILE.exists():
            return [
                line.strip()
                for line in PAYLOADS_FILE.read_text().splitlines()
                if line.strip()
            ]
        return [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
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
        """Test query parameters for path traversal."""
        findings = []
        path_like_params = self._find_path_like_params(target.params)

        for param_name in path_like_params:
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
                if resp and self._detect_traversal(resp, baseline_length):
                    findings.append(
                        Vulnerability(
                            name=f"Path Traversal in parameter: {param_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=(
                                f"Possible path traversal / LFI detected in parameter '{param_name}'. "
                                "An attacker may read arbitrary files from the server."
                            ),
                            target_url=target.url,
                            evidence=f"Payload: {payload} | Status: {resp.status_code}",
                            request_detail=f"{target.method.value} {target.url}?{param_name}={payload}",
                            response_detail=resp.text[:500],
                            remediation=(
                                "Validate file paths against an allowlist. "
                                "Use chroot or sandboxed file access. "
                                "Never pass user input directly to file system APIs."
                            ),
                            cwe_id="CWE-22",
                        )
                    )
                    break
        return findings

    def _test_api_body(
        self, target: APITarget, baseline_length: int
    ) -> list[Vulnerability]:
        """Test request body fields for path traversal."""
        findings = []
        if not target.body or not isinstance(target.body, dict):
            return findings

        path_like_fields = self._find_path_like_params(target.body)

        for field_name in path_like_fields:
            if not isinstance(target.body.get(field_name), str):
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
                if resp and self._detect_traversal(resp, baseline_length):
                    findings.append(
                        Vulnerability(
                            name=f"Path Traversal in body field: {field_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=(
                                f"Possible path traversal / LFI detected in body field '{field_name}'."
                            ),
                            target_url=target.url,
                            evidence=f"Payload: {payload} | Status: {resp.status_code}",
                            request_detail=f"{target.method.value} {target.url} body[{field_name}]={payload}",
                            response_detail=resp.text[:500],
                            remediation=(
                                "Validate file paths against an allowlist. "
                                "Never pass user input directly to file system APIs."
                            ),
                            cwe_id="CWE-22",
                        )
                    )
                    break
        return findings

    def _test_url_params(
        self, target: URLTarget, baseline_length: int
    ) -> list[Vulnerability]:
        """Test URL query parameters for path traversal."""
        findings = []
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

        parsed = urlparse(target.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        path_like_params = self._find_path_like_params(
            {k: v[0] if v else "" for k, v in params.items()}
        )

        for param_name in path_like_params:
            for payload in self.payloads:
                injected = dict(params)
                injected[param_name] = [payload]
                new_query = urlencode(injected, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                resp = self._send(method="GET", url=test_url, headers=dict(target.headers))
                if resp and self._detect_traversal(resp, baseline_length):
                    findings.append(
                        Vulnerability(
                            name=f"Path Traversal in URL parameter: {param_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=f"Possible path traversal detected in URL parameter '{param_name}'.",
                            target_url=target.url,
                            evidence=f"Payload: {payload} | Status: {resp.status_code}",
                            request_detail=f"GET {test_url}",
                            response_detail=resp.text[:500],
                            remediation="Validate file paths against an allowlist.",
                            cwe_id="CWE-22",
                        )
                    )
                    break
        return findings

    def _find_path_like_params(self, params: dict) -> list[str]:
        """Identify parameters that likely contain file paths."""
        path_keywords = [
            "file", "path", "name", "filename", "filepath", "dir", "folder",
            "doc", "document", "template", "page", "include", "load", "read",
            "view", "download", "attachment", "img", "image", "src", "source",
            "lang", "language", "locale",
        ]
        result = []
        for name, value in params.items():
            name_lower = name.lower()
            if any(kw in name_lower for kw in path_keywords):
                result.append(name)
            elif isinstance(value, str) and (
                "/" in value or "\\" in value or value.endswith((".txt", ".html", ".xml", ".json", ".log", ".cfg", ".ini"))
            ):
                result.append(name)
        if not result:
            result = list(params.keys())
        return result

    def _detect_traversal(
        self, response: requests.Response, baseline_length: int
    ) -> bool:
        """Detect potential path traversal based on response analysis."""
        body = response.text

        for pattern in FILE_CONTENT_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True

        return False
