"""Unit tests for data models."""

import pytest
from datetime import datetime

from whitehats.models.target import (
    APITarget,
    HTTPMethod,
    Target,
    TargetType,
    URLTarget,
)
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.models.test_case import TestCase


@pytest.mark.unit
@pytest.mark.model
class TestTargetModels:
    """Tests for Target, APITarget, URLTarget."""

    def test_target_defaults(self):
        t = Target(url="https://example.com")
        assert t.url == "https://example.com"
        assert t.target_type == TargetType.URL
        assert t.name == "https://example.com"  # auto-filled

    def test_target_custom_name(self):
        t = Target(url="https://example.com", name="My Target")
        assert t.name == "My Target"

    def test_api_target_defaults(self):
        t = APITarget(url="https://example.com/api/users")
        assert t.target_type == TargetType.API
        assert t.method == HTTPMethod.GET
        assert t.params == {}
        assert t.headers == {}
        assert t.body is None
        assert t.auth_token is None
        assert t.content_type == "application/json"

    def test_api_target_request_headers(self):
        t = APITarget(
            url="https://example.com/api",
            auth_token="my-token",
            headers={"X-Custom": "value"},
        )
        h = t.get_request_headers()
        assert h["Authorization"] == "Bearer my-token"
        assert h["Content-Type"] == "application/json"
        assert h["X-Custom"] == "value"

    def test_api_target_no_auth(self):
        t = APITarget(url="https://example.com/api")
        h = t.get_request_headers()
        assert "Authorization" not in h

    def test_url_target_defaults(self):
        t = URLTarget(url="https://example.com")
        assert t.target_type == TargetType.URL
        assert t.headers == {}
        assert t.cookies == {}

    def test_http_method_enum(self):
        assert HTTPMethod.GET.value == "GET"
        assert HTTPMethod.POST.value == "POST"
        assert HTTPMethod.PUT.value == "PUT"
        assert HTTPMethod.PATCH.value == "PATCH"
        assert HTTPMethod.DELETE.value == "DELETE"

    def test_http_method_options_and_head(self):
        assert HTTPMethod.OPTIONS.value == "OPTIONS"
        assert HTTPMethod.HEAD.value == "HEAD"

    def test_target_with_description(self):
        t = Target(url="https://example.com", description="Production API")
        assert t.description == "Production API"

    def test_api_target_with_body_and_params(self):
        t = APITarget(
            url="https://example.com/api",
            method=HTTPMethod.POST,
            params={"q": "search"},
            body={"username": "admin"},
        )
        assert t.params == {"q": "search"}
        assert t.body == {"username": "admin"}
        assert t.method == HTTPMethod.POST

    def test_api_target_custom_content_type(self):
        t = APITarget(url="https://example.com/api", content_type="text/xml")
        h = t.get_request_headers()
        assert h["Content-Type"] == "text/xml"

    def test_url_target_with_cookies(self):
        t = URLTarget(
            url="https://example.com",
            cookies={"session_id": "abc123", "lang": "zh-TW"},
        )
        assert t.cookies == {"session_id": "abc123", "lang": "zh-TW"}

    def test_url_target_with_headers(self):
        t = URLTarget(
            url="https://example.com",
            headers={"Accept-Language": "zh-TW"},
        )
        assert t.headers["Accept-Language"] == "zh-TW"


@pytest.mark.unit
@pytest.mark.model
class TestVulnerabilityModel:
    """Tests for Vulnerability model."""

    def test_vulnerability_creation(self):
        v = Vulnerability(
            name="Test Vuln",
            severity=Severity.HIGH,
            module="test_module",
            description="Test description",
            target_url="https://example.com",
        )
        assert v.name == "Test Vuln"
        assert v.severity == Severity.HIGH
        assert v.evidence == ""
        assert v.cwe_id is None

    def test_vulnerability_to_dict(self):
        v = Vulnerability(
            name="SQL Injection",
            severity=Severity.CRITICAL,
            module="sql_injection",
            description="Found SQLi",
            target_url="https://example.com/api",
            evidence="payload triggered error",
            cwe_id="CWE-89",
        )
        d = v.to_dict()
        assert d["name"] == "SQL Injection"
        assert d["severity"] == "critical"
        assert d["cwe_id"] == "CWE-89"
        assert "timestamp" in d

    def test_severity_values(self):
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_vulnerability_all_optional_fields(self):
        v = Vulnerability(
            name="Full Vuln",
            severity=Severity.MEDIUM,
            module="test",
            description="desc",
            target_url="https://example.com",
            evidence="payload output",
            request_detail="GET /api?id=1",
            response_detail="200 OK with error",
            remediation="Use parameterized queries",
            cwe_id="CWE-89",
        )
        d = v.to_dict()
        assert d["request_detail"] == "GET /api?id=1"
        assert d["response_detail"] == "200 OK with error"
        assert d["remediation"] == "Use parameterized queries"
        assert d["evidence"] == "payload output"

    def test_vulnerability_timestamp_format(self):
        v = Vulnerability(
            name="Test",
            severity=Severity.LOW,
            module="test",
            description="desc",
            target_url="https://example.com",
        )
        # timestamp should be ISO format parseable
        dt = datetime.fromisoformat(v.timestamp)
        assert isinstance(dt, datetime)

    def test_vulnerability_defaults_in_to_dict(self):
        v = Vulnerability(
            name="Test",
            severity=Severity.INFO,
            module="test",
            description="desc",
            target_url="https://example.com",
        )
        d = v.to_dict()
        assert d["evidence"] == ""
        assert d["request_detail"] is None
        assert d["response_detail"] is None
        assert d["remediation"] == ""
        assert d["cwe_id"] is None


@pytest.mark.unit
@pytest.mark.model
class TestTestCaseModel:
    """Tests for TestCase model."""

    def test_test_case_creation(self):
        tc = TestCase(
            test_id="tc-001",
            name="SQL Injection Test",
            module="sql_injection",
            target_url="https://example.com/api",
            method="POST",
            payload="' OR '1'='1",
        )
        assert tc.test_id == "tc-001"
        assert tc.method == "POST"

    def test_test_case_to_dict(self):
        tc = TestCase(
            test_id="tc-002",
            name="XSS Test",
            module="xss",
            target_url="https://example.com",
        )
        d = tc.to_dict()
        assert d["test_id"] == "tc-002"
        assert d["method"] == "GET"
        assert d["params"] == {}

    def test_test_case_all_fields(self):
        tc = TestCase(
            test_id="tc-003",
            name="SSRF Test",
            module="ssrf",
            target_url="https://example.com/api/fetch",
            method="POST",
            headers={"Authorization": "Bearer token"},
            params={"url": "http://internal"},
            body={"data": "payload"},
            payload="http://169.254.169.254",
            expected_behavior="Should block internal requests",
            description="SSRF via url parameter",
        )
        d = tc.to_dict()
        assert d["method"] == "POST"
        assert d["headers"]["Authorization"] == "Bearer token"
        assert d["params"]["url"] == "http://internal"
        assert d["body"] == {"data": "payload"}
        assert d["payload"] == "http://169.254.169.254"
        assert d["expected_behavior"] == "Should block internal requests"
        assert d["description"] == "SSRF via url parameter"

    def test_test_case_defaults(self):
        tc = TestCase(
            test_id="tc-004",
            name="Basic",
            module="test",
            target_url="https://example.com",
        )
        assert tc.method == "GET"
        assert tc.headers == {}
        assert tc.params == {}
        assert tc.body is None
        assert tc.payload == ""
        assert tc.expected_behavior == ""
        assert tc.description == ""
