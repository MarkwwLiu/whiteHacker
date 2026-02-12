"""Unit tests for report generators."""

import json
import os
import tempfile

import pytest

from whitehats.models.vulnerability import Severity, Vulnerability
from whitehats.reporter.json_reporter import JSONReporter
from whitehats.reporter.html_reporter import HTMLReporter


def _sample_vulns():
    return [
        Vulnerability(
            name="SQL Injection",
            severity=Severity.HIGH,
            module="sql_injection",
            description="Found SQLi in param id",
            target_url="https://example.com/api",
            evidence="Payload: ' OR '1'='1",
            cwe_id="CWE-89",
        ),
        Vulnerability(
            name="Missing HSTS",
            severity=Severity.MEDIUM,
            module="header_security",
            description="Strict-Transport-Security header missing",
            target_url="https://example.com",
        ),
    ]


def _target_info():
    return {
        "url": "https://example.com",
        "urls": ["https://example.com"],
        "scan_type": "single-target",
    }


@pytest.mark.unit
@pytest.mark.reporter
class TestJSONReporter:
    def test_generate_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {"report": {"output_dir": tmpdir, "include_details": True}}
            reporter = JSONReporter(config)
            path = reporter.generate(_sample_vulns(), _target_info())
            assert os.path.exists(path)
            assert path.endswith(".json")

    def test_json_report_content(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {"report": {"output_dir": tmpdir, "include_details": True}}
            reporter = JSONReporter(config)
            path = reporter.generate(_sample_vulns(), _target_info())
            with open(path) as f:
                data = json.load(f)
            assert data["summary"]["total_findings"] == 2
            assert "high" in data["summary"]["severity_breakdown"]
            assert len(data["vulnerabilities"]) == 2

    def test_empty_vulnerabilities(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {"report": {"output_dir": tmpdir, "include_details": True}}
            reporter = JSONReporter(config)
            path = reporter.generate([], _target_info())
            with open(path) as f:
                data = json.load(f)
            assert data["summary"]["total_findings"] == 0


@pytest.mark.unit
@pytest.mark.reporter
class TestHTMLReporter:
    def test_generate_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {"report": {"output_dir": tmpdir, "include_details": True}}
            reporter = HTMLReporter(config)
            path = reporter.generate(_sample_vulns(), _target_info())
            assert os.path.exists(path)
            assert path.endswith(".html")

    def test_html_contains_vuln_names(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {"report": {"output_dir": tmpdir, "include_details": True}}
            reporter = HTMLReporter(config)
            path = reporter.generate(_sample_vulns(), _target_info())
            with open(path) as f:
                html = f.read()
            assert "SQL Injection" in html
            assert "Missing HSTS" in html

    def test_empty_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {"report": {"output_dir": tmpdir, "include_details": True}}
            reporter = HTMLReporter(config)
            path = reporter.generate([], _target_info())
            with open(path) as f:
                html = f.read()
            assert "No vulnerabilities found" in html
