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
