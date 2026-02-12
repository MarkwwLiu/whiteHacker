"""Unit tests for security testing modules."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from whitehats.models.target import APITarget, HTTPMethod, URLTarget
from whitehats.models.vulnerability import Severity
from whitehats.modules.sql_injection import SQLInjectionModule, SQL_ERROR_PATTERNS
from whitehats.modules.xss import XSSModule
from whitehats.modules.csrf import CSRFModule
from whitehats.modules.header_security import HeaderSecurityModule
from whitehats.modules.cors_misconfig import CORSMisconfigModule
from whitehats.modules.info_disclosure import InfoDisclosureModule
from whitehats.modules.ssrf import SSRFModule
from whitehats.modules.path_traversal import PathTraversalModule


def _make_module(cls, config=None):
    """Helper to create a module with mocked scanner."""
    if config is None:
        config = {"modules": {cls.name: {"enabled": True, "level": 1}}}
    scanner = MagicMock()
    scanner.send_request = MagicMock(return_value=None)
    return cls(config=config, scanner=scanner)


def _make_response(text="", status_code=200, headers=None, content=None):
    """Helper to create a mock response."""
    resp = MagicMock(spec=requests.Response)
    resp.text = text
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.content = content if content is not None else text.encode()
    return resp


@pytest.mark.unit
@pytest.mark.module
@pytest.mark.sql_injection
class TestSQLInjectionModule:
    def test_init_loads_payloads(self):
        mod = _make_module(SQLInjectionModule)
        assert len(mod.payloads) > 0

    def test_detect_sqli_with_error_pattern(self):
        mod = _make_module(SQLInjectionModule)
        resp = _make_response("Warning: mysql_fetch_array()")
        assert mod._detect_sqli(resp, baseline_length=100, baseline_status=200)

    def test_detect_sqli_no_match(self):
        mod = _make_module(SQLInjectionModule)
        resp = _make_response("Normal response body")
        assert not mod._detect_sqli(resp, baseline_length=100, baseline_status=200)

    def test_detect_sqli_size_change(self):
        mod = _make_module(SQLInjectionModule)
        # Response 4x larger than baseline suggests data leakage
        resp = _make_response("x" * 400)
        assert mod._detect_sqli(resp, baseline_length=100, baseline_status=200)

    def test_run_api_no_params_no_body(self):
        mod = _make_module(SQLInjectionModule)
        target = APITarget(url="https://example.com/api")
        baseline = _make_response("ok")
        findings = mod.run(target, baseline)
        assert findings == []

    def test_run_api_with_params(self):
        mod = _make_module(SQLInjectionModule)
        # Make scanner return a response with SQL error
        sql_error_resp = _make_response("Warning: mysql_fetch_array()")
        mod.scanner.send_request.return_value = sql_error_resp

        target = APITarget(
            url="https://example.com/api",
            params={"id": "1"},
        )
        baseline = _make_response("ok", content=b"ok")
        findings = mod.run(target, baseline)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert "CWE-89" == findings[0].cwe_id


@pytest.mark.unit
@pytest.mark.module
@pytest.mark.xss
class TestXSSModule:
    def test_init_loads_payloads(self):
        mod = _make_module(XSSModule)
        assert len(mod.payloads) > 0

    def test_detect_xss_reflected(self):
        mod = _make_module(XSSModule)
        payload = "<script>alert('XSS')</script>"
        resp = _make_response(
            f"<html><body>{payload}</body></html>",
            headers={"Content-Type": "text/html"},
        )
        assert mod._detect_xss(resp, payload)

    def test_detect_xss_not_reflected(self):
        mod = _make_module(XSSModule)
        payload = "<script>alert('XSS')</script>"
        resp = _make_response(
            "<html><body>Safe content</body></html>",
            headers={"Content-Type": "text/html"},
        )
        assert not mod._detect_xss(resp, payload)

    def test_detect_xss_json_response(self):
        mod = _make_module(XSSModule)
        payload = "not-a-script"
        resp = _make_response(
            '{"data": "not-a-script"}',
            headers={"Content-Type": "application/json"},
        )
        # Non-script payloads in JSON should NOT flag
        assert not mod._detect_xss(resp, payload)


@pytest.mark.unit
@pytest.mark.module
@pytest.mark.csrf
class TestCSRFModule:
    def test_init(self):
        mod = _make_module(CSRFModule)
        assert mod.name == "csrf"

    def test_skip_get_requests(self):
        mod = _make_module(CSRFModule)
        target = APITarget(url="https://example.com/api", method=HTTPMethod.GET)
        baseline = _make_response("ok")
        findings = mod.run(target, baseline)
        # GET requests shouldn't need CSRF checks
        assert len(findings) == 0


@pytest.mark.unit
@pytest.mark.module
@pytest.mark.header_security
class TestHeaderSecurityModule:
    def test_missing_headers_detected(self):
        mod = _make_module(HeaderSecurityModule)
        # Response with NO security headers
        resp = _make_response("ok", headers={"Content-Type": "text/html"})
        mod.scanner.send_request.return_value = resp

        target = APITarget(url="https://example.com/api")
        findings = mod.run(target, resp)
        # Should find missing headers
        assert len(findings) > 0

    def test_all_headers_present(self):
        mod = _make_module(HeaderSecurityModule)
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        resp = _make_response("ok", headers=headers)
        target = APITarget(url="https://example.com/api")
        findings = mod.run(target, resp)
        # Filter only "missing header" findings
        missing = [f for f in findings if "Missing" in f.name or "missing" in f.name.lower()]
        assert len(missing) == 0


@pytest.mark.unit
@pytest.mark.module
@pytest.mark.cors
class TestCORSMisconfigModule:
    def test_wildcard_origin(self):
        mod = _make_module(CORSMisconfigModule)
        resp = _make_response(
            "ok",
            headers={"Access-Control-Allow-Origin": "*"},
        )
        mod.scanner.send_request.return_value = resp
        target = APITarget(url="https://example.com/api")
        findings = mod.run(target, resp)
        wildcard_findings = [f for f in findings if "wildcard" in f.name.lower() or "*" in f.evidence]
        assert len(wildcard_findings) > 0

    def test_no_cors_headers(self):
        mod = _make_module(CORSMisconfigModule)
        resp = _make_response("ok", headers={})
        mod.scanner.send_request.return_value = resp
        target = APITarget(url="https://example.com/api")
        findings = mod.run(target, resp)
        # No CORS headers means no CORS misconfiguration
        assert len(findings) == 0


@pytest.mark.unit
@pytest.mark.module
@pytest.mark.info_disclosure
class TestInfoDisclosureModule:
    def test_detect_email(self):
        mod = _make_module(InfoDisclosureModule)
        resp = _make_response("Contact us at admin@internal.corp for help")
        target = APITarget(url="https://example.com/api")
        findings = mod.run(target, resp)
        email_findings = [f for f in findings if "email" in f.name.lower() or "email" in f.description.lower()]
        assert len(email_findings) > 0

    def test_detect_internal_ip(self):
        mod = _make_module(InfoDisclosureModule)
        resp = _make_response("Server at 192.168.1.100:8080")
        target = APITarget(url="https://example.com/api")
        findings = mod.run(target, resp)
        ip_findings = [f for f in findings if "ip" in f.name.lower() or "internal" in f.name.lower()]
        assert len(ip_findings) > 0

    def test_clean_response(self):
        mod = _make_module(InfoDisclosureModule)
        resp = _make_response('{"status": "ok", "data": []}')
        target = APITarget(url="https://example.com/api")
        findings = mod.run(target, resp)
        assert len(findings) == 0


@pytest.mark.unit
@pytest.mark.module
@pytest.mark.ssrf
class TestSSRFModule:
    def test_init_loads_payloads(self):
        mod = _make_module(SSRFModule)
        assert len(mod.payloads) > 0

    def test_find_url_like_params(self):
        mod = _make_module(SSRFModule)
        params = {"callback_url": "https://example.com", "name": "test"}
        result = mod._find_url_like_params(params)
        assert "callback_url" in result

    def test_find_url_like_params_by_value(self):
        mod = _make_module(SSRFModule)
        params = {"data": "http://some-url.com"}
        result = mod._find_url_like_params(params)
        assert "data" in result

    def test_detect_ssrf_with_metadata(self):
        mod = _make_module(SSRFModule)
        resp = _make_response("ami-id: ami-12345\ninstance-id: i-abc")
        assert mod._detect_ssrf(resp, baseline_length=50)

    def test_detect_ssrf_with_etc_passwd(self):
        mod = _make_module(SSRFModule)
        resp = _make_response("root:x:0:0:root:/root:/bin/bash")
        assert mod._detect_ssrf(resp, baseline_length=50)

    def test_detect_ssrf_normal_response(self):
        mod = _make_module(SSRFModule)
        resp = _make_response("Normal API response")
        assert not mod._detect_ssrf(resp, baseline_length=50)

    def test_run_api_with_url_param(self):
        mod = _make_module(SSRFModule)
        ssrf_resp = _make_response("ami-id: ami-12345\ninstance-id: i-abc")
        mod.scanner.send_request.return_value = ssrf_resp

        target = APITarget(
            url="https://example.com/api/fetch",
            params={"url": "https://external.com"},
        )
        baseline = _make_response("ok", content=b"ok")
        findings = mod.run(target, baseline)
        assert len(findings) >= 1
        assert findings[0].cwe_id == "CWE-918"

    def test_run_api_no_params(self):
        mod = _make_module(SSRFModule)
        target = APITarget(url="https://example.com/api")
        baseline = _make_response("ok")
        findings = mod.run(target, baseline)
        assert findings == []


@pytest.mark.unit
@pytest.mark.module
@pytest.mark.path_traversal
class TestPathTraversalModule:
    def test_init_loads_payloads(self):
        mod = _make_module(PathTraversalModule)
        assert len(mod.payloads) > 0

    def test_find_path_like_params(self):
        mod = _make_module(PathTraversalModule)
        params = {"filename": "report.pdf", "id": "123"}
        result = mod._find_path_like_params(params)
        assert "filename" in result

    def test_find_path_like_params_by_value(self):
        mod = _make_module(PathTraversalModule)
        params = {"data": "/var/log/app.log"}
        result = mod._find_path_like_params(params)
        assert "data" in result

    def test_detect_traversal_etc_passwd(self):
        mod = _make_module(PathTraversalModule)
        resp = _make_response("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        assert mod._detect_traversal(resp, baseline_length=50)

    def test_detect_traversal_win_ini(self):
        mod = _make_module(PathTraversalModule)
        resp = _make_response("; for 16-bit app support\n[fonts]\n[extensions]")
        assert mod._detect_traversal(resp, baseline_length=50)

    def test_detect_traversal_normal_response(self):
        mod = _make_module(PathTraversalModule)
        resp = _make_response('{"data": "normal response"}')
        assert not mod._detect_traversal(resp, baseline_length=50)

    def test_run_api_with_file_param(self):
        mod = _make_module(PathTraversalModule)
        traversal_resp = _make_response("root:x:0:0:root:/root:/bin/bash")
        mod.scanner.send_request.return_value = traversal_resp

        target = APITarget(
            url="https://example.com/api/download",
            params={"file": "report.pdf"},
        )
        baseline = _make_response("ok", content=b"ok")
        findings = mod.run(target, baseline)
        assert len(findings) >= 1
        assert findings[0].cwe_id == "CWE-22"

    def test_run_api_no_params(self):
        mod = _make_module(PathTraversalModule)
        target = APITarget(url="https://example.com/api")
        baseline = _make_response("ok")
        findings = mod.run(target, baseline)
        assert findings == []
