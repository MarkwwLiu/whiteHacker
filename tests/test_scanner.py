"""Unit tests for scanners."""

from unittest.mock import MagicMock, patch, call

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
class TestBaseScannerInit:
    """Tests for BaseScanner.__init__ config extraction."""

    def test_default_values_no_scan_section(self):
        scanner = APIScanner(config={"modules": {}})
        assert scanner.timeout == 10
        assert scanner.request_delay == 0.5
        assert scanner.verify_ssl is True
        assert scanner.follow_redirects is True
        assert scanner.user_agent == "WhiteHats-SecurityScanner/1.0"

    def test_verify_ssl_config(self):
        config = _default_config()
        scanner = APIScanner(config=config)
        assert scanner.verify_ssl is False

    def test_follow_redirects_config(self):
        config = _default_config()
        scanner = APIScanner(config=config)
        assert scanner.follow_redirects is True

    def test_session_user_agent_header(self):
        config = _default_config()
        scanner = APIScanner(config=config)
        assert scanner.session.headers["User-Agent"] == "TestAgent/1.0"

    def test_vulnerabilities_starts_empty(self):
        scanner = APIScanner(config=_default_config())
        assert scanner.get_results() == []


@pytest.mark.unit
@pytest.mark.scanner
class TestBaseScannerSendRequest:
    """Tests for BaseScanner.send_request."""

    @patch("whitehats.scanner.base_scanner.time.sleep")
    def test_send_request_success(self, mock_sleep):
        config = _default_config()
        scanner = APIScanner(config=config)

        mock_resp = MagicMock(spec=requests.Response)
        mock_resp.status_code = 200
        with patch.object(scanner.session, "request", return_value=mock_resp):
            result = scanner.send_request("GET", "https://example.com")

        assert result is mock_resp

    @patch("whitehats.scanner.base_scanner.time.sleep")
    def test_send_request_passes_all_params(self, mock_sleep):
        config = _default_config()
        scanner = APIScanner(config=config)

        with patch.object(scanner.session, "request") as mock_request:
            mock_request.return_value = MagicMock(spec=requests.Response)
            scanner.send_request(
                method="POST",
                url="https://example.com/api",
                headers={"X-Custom": "val"},
                params={"key": "val"},
                data={"form": "data"},
                json_data={"json": "body"},
            )
            mock_request.assert_called_once_with(
                method="POST",
                url="https://example.com/api",
                headers={"X-Custom": "val"},
                params={"key": "val"},
                data={"form": "data"},
                json={"json": "body"},
                timeout=5,
                verify=False,
                allow_redirects=True,
            )

    @patch("whitehats.scanner.base_scanner.time.sleep")
    def test_send_request_exception_returns_none(self, mock_sleep):
        config = _default_config()
        scanner = APIScanner(config=config)

        with patch.object(
            scanner.session, "request", side_effect=requests.ConnectionError("fail")
        ):
            result = scanner.send_request("GET", "https://unreachable.com")

        assert result is None

    @patch("whitehats.scanner.base_scanner.time.sleep")
    def test_send_request_timeout_returns_none(self, mock_sleep):
        config = _default_config()
        scanner = APIScanner(config=config)

        with patch.object(
            scanner.session, "request", side_effect=requests.Timeout("timeout")
        ):
            result = scanner.send_request("GET", "https://slow.com")

        assert result is None

    @patch("whitehats.scanner.base_scanner.time.sleep")
    def test_send_request_respects_delay(self, mock_sleep):
        config = _default_config()
        config["scan"]["request_delay"] = 2.0
        scanner = APIScanner(config=config)

        with patch.object(scanner.session, "request") as mock_request:
            mock_request.return_value = MagicMock(spec=requests.Response)
            scanner.send_request("GET", "https://example.com")

        mock_sleep.assert_called_once_with(2.0)


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
class TestAPIScannerDisabledModule:
    """Tests for APIScanner module loading edge cases."""

    @patch.object(BaseScanner, "send_request")
    def test_disabled_module_not_loaded(self, mock_send):
        mock_module_cls = MagicMock()
        mock_module_cls.name = "disabled_mod"

        config = _default_config()
        config["modules"]["disabled_mod"] = {"enabled": False}
        scanner = APIScanner(config=config, modules=[mock_module_cls])
        assert len(scanner.modules) == 0

    @patch.object(BaseScanner, "send_request")
    def test_module_exception_doesnt_crash_scan(self, mock_send):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.content = b"ok"
        resp.text = "ok"
        resp.headers = {}
        mock_send.return_value = resp

        mock_module_cls = MagicMock()
        mock_module_cls.name = "boom_mod"
        mock_instance = MagicMock()
        mock_instance.run.side_effect = RuntimeError("Module crashed!")
        mock_module_cls.return_value = mock_instance

        config = _default_config()
        config["modules"]["boom_mod"] = {"enabled": True}
        scanner = APIScanner(config=config, modules=[mock_module_cls])
        target = APITarget(url="https://example.com/api")
        results = scanner.scan(target)
        # Should not raise, returns empty (module findings skipped)
        assert results == []

    @patch.object(BaseScanner, "send_request")
    def test_scan_no_modules(self, mock_send):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.content = b"ok"
        resp.text = "ok"
        resp.headers = {}
        mock_send.return_value = resp

        scanner = APIScanner(config=_default_config())
        target = APITarget(url="https://example.com/api")
        results = scanner.scan(target)
        assert results == []


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

    @patch.object(BaseScanner, "send_request")
    def test_scan_with_modules(self, mock_send):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.content = b"ok"
        resp.text = "ok"
        resp.headers = {}
        mock_send.return_value = resp

        mock_module_cls = MagicMock()
        mock_module_cls.name = "test_mod"
        mock_instance = MagicMock()
        mock_instance.run.return_value = []
        mock_module_cls.return_value = mock_instance

        config = _default_config()
        config["modules"]["test_mod"] = {"enabled": True}
        scanner = URLScanner(config=config, modules=[mock_module_cls])
        target = URLTarget(url="https://example.com")
        scanner.scan(target)
        mock_instance.run.assert_called_once()

    @patch.object(BaseScanner, "send_request")
    def test_disabled_module_not_loaded(self, mock_send):
        mock_module_cls = MagicMock()
        mock_module_cls.name = "disabled_mod"

        config = _default_config()
        config["modules"]["disabled_mod"] = {"enabled": False}
        scanner = URLScanner(config=config, modules=[mock_module_cls])
        assert len(scanner.modules) == 0

    @patch.object(BaseScanner, "send_request")
    def test_module_exception_doesnt_crash_scan(self, mock_send):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.content = b"ok"
        resp.text = "ok"
        resp.headers = {}
        mock_send.return_value = resp

        mock_module_cls = MagicMock()
        mock_module_cls.name = "boom_mod"
        mock_instance = MagicMock()
        mock_instance.run.side_effect = RuntimeError("Boom!")
        mock_module_cls.return_value = mock_instance

        config = _default_config()
        config["modules"]["boom_mod"] = {"enabled": True}
        scanner = URLScanner(config=config, modules=[mock_module_cls])
        target = URLTarget(url="https://example.com")
        results = scanner.scan(target)
        assert results == []
