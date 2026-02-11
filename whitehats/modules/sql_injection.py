"""SQL Injection security test module."""

import logging
import re
from pathlib import Path

import requests

from whitehats.models.target import APITarget, Target, URLTarget
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.modules.base_module import BaseModule

logger = logging.getLogger(__name__)

PAYLOADS_FILE = Path(__file__).parent.parent / "payloads" / "sql_payloads.txt"

# Common SQL error patterns indicating potential injection
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySqlException",
    r"valid MySQL result",
    r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.*SQL[\-\_\ ]*Server",
    r"OLE DB.*SQL Server",
    r"(\bORA-\d{5})",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*oci_",
    r"Warning.*ora_",
    r"Microsoft Access Driver",
    r"JET Database Engine",
    r"Access Database Engine",
    r"ODBC Microsoft Access",
    r"Syntax error \(missing operator\) in query expression",
    r"SQLite/JQl",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_",
    r"Warning.*SQLite3::",
    r"\[SQLITE_ERROR\]",
    r"SQLSTATE\[",
    r"Syntax error or access violation",
]


class SQLInjectionModule(BaseModule):
    name = "sql_injection"
    description = "Tests for SQL Injection vulnerabilities"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.payloads = self._load_payloads()

    def _load_payloads(self) -> list[str]:
        """Load SQL injection payloads from file."""
        if PAYLOADS_FILE.exists():
            return [
                line.strip()
                for line in PAYLOADS_FILE.read_text().splitlines()
                if line.strip()
            ]
        return ["' OR '1'='1", '" OR "1"="1', "' OR 1=1 --"]

    def run(
        self, target: Target, baseline_response: requests.Response
    ) -> list[Vulnerability]:
        findings = []
        baseline_length = len(baseline_response.content)
        baseline_status = baseline_response.status_code

        if isinstance(target, APITarget):
            findings.extend(
                self._test_api_params(target, baseline_length, baseline_status)
            )
            findings.extend(
                self._test_api_body(target, baseline_length, baseline_status)
            )
        elif isinstance(target, URLTarget):
            findings.extend(
                self._test_url_params(target, baseline_length, baseline_status)
            )

        return findings

    def _test_api_params(
        self, target: APITarget, baseline_length: int, baseline_status: int
    ) -> list[Vulnerability]:
        """Test query parameters for SQL injection."""
        findings = []
        for param_name, param_value in target.params.items():
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
                if resp and self._detect_sqli(resp, baseline_length, baseline_status):
                    findings.append(
                        Vulnerability(
                            name=f"SQL Injection in parameter: {param_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=f"Possible SQL injection detected in query parameter '{param_name}'.",
                            target_url=target.url,
                            evidence=f"Payload: {payload} | Status: {resp.status_code}",
                            request_detail=f"{target.method.value} {target.url}?{param_name}={payload}",
                            response_detail=resp.text[:500],
                            remediation="Use parameterized queries or prepared statements. Validate and sanitize all user inputs.",
                            cwe_id="CWE-89",
                        )
                    )
                    break  # One finding per parameter is enough
        return findings

    def _test_api_body(
        self, target: APITarget, baseline_length: int, baseline_status: int
    ) -> list[Vulnerability]:
        """Test request body fields for SQL injection."""
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
                if resp and self._detect_sqli(resp, baseline_length, baseline_status):
                    findings.append(
                        Vulnerability(
                            name=f"SQL Injection in body field: {field_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=f"Possible SQL injection detected in request body field '{field_name}'.",
                            target_url=target.url,
                            evidence=f"Payload: {payload} | Status: {resp.status_code}",
                            request_detail=f"{target.method.value} {target.url} body[{field_name}]={payload}",
                            response_detail=resp.text[:500],
                            remediation="Use parameterized queries or prepared statements. Validate and sanitize all user inputs.",
                            cwe_id="CWE-89",
                        )
                    )
                    break
        return findings

    def _test_url_params(
        self, target: URLTarget, baseline_length: int, baseline_status: int
    ) -> list[Vulnerability]:
        """Test URL query parameters for SQL injection."""
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
                if resp and self._detect_sqli(resp, baseline_length, baseline_status):
                    findings.append(
                        Vulnerability(
                            name=f"SQL Injection in URL parameter: {param_name}",
                            severity=Severity.HIGH,
                            module=self.name,
                            description=f"Possible SQL injection detected in URL parameter '{param_name}'.",
                            target_url=target.url,
                            evidence=f"Payload: {payload} | Status: {resp.status_code}",
                            request_detail=f"GET {test_url}",
                            response_detail=resp.text[:500],
                            remediation="Use parameterized queries or prepared statements.",
                            cwe_id="CWE-89",
                        )
                    )
                    break
        return findings

    def _detect_sqli(
        self, response: requests.Response, baseline_length: int, baseline_status: int
    ) -> bool:
        """Detect potential SQL injection based on response analysis."""
        body = response.text

        # Check for SQL error messages in response
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return True

        # Significant response size change might indicate data leakage
        if baseline_length > 0:
            ratio = len(response.content) / baseline_length
            if ratio > 3.0:
                return True

        return False
