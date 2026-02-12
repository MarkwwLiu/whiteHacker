"""Unit tests for scanners."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from whitehats.models.target import APITarget, HTTPMethod, URLTarget
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.scanner.api_scanner import APIScanner
from whitehats.scanner.url_scanner import URLScanner
from whitehats.scanner.base_scanner import BaseScanner
from whitehats.modules.base_module import BaseModule


def _default_config():
    return {
        "scan": {
            "timeout": 5,
            "request_delay": 0,
            "verify_ssl": False,
            "follow_redirects": True,
            "user_agent": "TestAgent/1.0",
        },
        "modules": {
            "sql_injection": {"enabled": True, "level": 1},
            "xss": {"enabled": True, "level": 1},
        },
        "report": {"format": "json", "output_dir": "reports"},
    }


@pytest.mark.unit
@pytest.mark.scanner
class TestBaseScanner:
    def test_init_config(self):
        config = _default_config()
        scanner = APIScanner(config=config)
        assert scanner.timeout == 5
        assert scanner.request_delay == 0
        assert scanner.user_agent == "TestAgent/1.0"

    def test_add_vulnerability(self):
        scanner = APIScanner(config=_default_config())
        vuln = Vulnerability(
            name="Test",
            severity=Severity.LOW,
            module="test",
            description="desc",
            target_url="https://example.com",
        )
        scanner.add_vulnerability(vuln)
        assert len(scanner.get_results()) == 1

    def test_clear_results(self):
        scanner = APIScanner(config=_default_config())
        vuln = Vulnerability(
            name="Test",
            severity=Severity.LOW,
            module="test",
            description="desc",
            target_url="https://example.com",
        )
        scanner.add_vulnerability(vuln)
        scanner.clear_results()
        assert len(scanner.get_results()) == 0


@pytest.mark.unit
@pytest.mark.scanner
class TestAPIScanner:
    def test_scan_wrong_target_type(self):
        scanner = APIScanner(config=_default_config())
        url_target = URLTarget(url="https://example.com")
        results = scanner.scan(url_target)
        assert results == []

    @patch.object(BaseScanner, "send_request")
    def test_scan_unreachable(self, mock_send):
        mock_send.return_value = None
        scanner = APIScanner(config=_default_config())
        target = APITarget(url="https://example.com/api")
        results = scanner.scan(target)
        assert results == []

    @patch.object(BaseScanner, "send_request")
    def test_scan_with_modules(self, mock_send):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.content = b"ok"
        resp.text = "ok"
        resp.headers = {}
        mock_send.return_value = resp

        # Use a mock module
        mock_module_cls = MagicMock()
        mock_module_cls.name = "test_mod"
        mock_instance = MagicMock()
        mock_instance.run.return_value = []
        mock_module_cls.return_value = mock_instance

        config = _default_config()
        config["modules"]["test_mod"] = {"enabled": True}
        scanner = APIScanner(config=config, modules=[mock_module_cls])
        target = APITarget(url="https://example.com/api")
        scanner.scan(target)
        mock_instance.run.assert_called_once()


@pytest.mark.unit
@pytest.mark.scanner
class TestURLScanner:
    def test_scan_wrong_target_type(self):
        scanner = URLScanner(config=_default_config())
        api_target = APITarget(url="https://example.com/api")
        results = scanner.scan(api_target)
        assert results == []

    @patch.object(BaseScanner, "send_request")
    def test_scan_unreachable(self, mock_send):
        mock_send.return_value = None
        scanner = URLScanner(config=_default_config())
        target = URLTarget(url="https://example.com")
        results = scanner.scan(target)
        assert results == []
