"""Unit tests for concurrent scanner."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from whitehats.models.target import APITarget, URLTarget
from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.scanner.concurrent_scanner import ConcurrentScanner
from whitehats.scanner.base_scanner import BaseScanner


def _default_config():
    return {
        "scan": {
            "timeout": 5,
            "request_delay": 0,
            "max_concurrent": 3,
            "verify_ssl": False,
            "follow_redirects": True,
            "user_agent": "TestAgent/1.0",
        },
        "modules": {},
        "report": {"format": "json", "output_dir": "reports"},
    }


class TestConcurrentScanner:
    def test_init_max_workers(self):
        scanner = ConcurrentScanner(config=_default_config())
        assert scanner.max_workers == 3

    def test_scan_empty_targets(self):
        scanner = ConcurrentScanner(config=_default_config())
        results = scanner.scan([])
        assert results == {}

    @patch.object(BaseScanner, "send_request")
    def test_scan_single_target(self, mock_send):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.content = b"ok"
        resp.text = "ok"
        resp.headers = {}
        mock_send.return_value = resp

        scanner = ConcurrentScanner(config=_default_config())
        targets = [APITarget(url="https://example.com/api")]
        results = scanner.scan(targets)
        assert "https://example.com/api" in results

    @patch.object(BaseScanner, "send_request")
    def test_scan_multiple_targets(self, mock_send):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.content = b"ok"
        resp.text = "ok"
        resp.headers = {}
        mock_send.return_value = resp

        scanner = ConcurrentScanner(config=_default_config())
        targets = [
            APITarget(url="https://example.com/api/1"),
            URLTarget(url="https://example.com/page"),
            APITarget(url="https://example.com/api/2"),
        ]
        results = scanner.scan(targets)
        assert len(results) == 3

    @patch.object(BaseScanner, "send_request")
    def test_progress_callback(self, mock_send):
        resp = MagicMock(spec=requests.Response)
        resp.status_code = 200
        resp.content = b"ok"
        resp.text = "ok"
        resp.headers = {}
        mock_send.return_value = resp

        callback_calls = []

        def on_progress(url, vulns, idx, total):
            callback_calls.append((url, idx, total))

        scanner = ConcurrentScanner(config=_default_config())
        targets = [
            APITarget(url="https://example.com/api/1"),
            URLTarget(url="https://example.com/page"),
        ]
        scanner.scan(targets, progress_callback=on_progress)
        assert len(callback_calls) == 2
        # All should report total=2
        for _, _, total in callback_calls:
            assert total == 2
