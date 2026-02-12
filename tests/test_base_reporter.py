"""Unit tests for BaseReporter abstract class."""

import pytest

from whitehats.reporter.base_reporter import BaseReporter
from whitehats.models.vulnerability import Vulnerability


class ConcreteReporter(BaseReporter):
    """Concrete implementation for testing the abstract base."""

    def generate(self, vulnerabilities, target_info):
        return "fake_path.json"


@pytest.mark.unit
@pytest.mark.base_reporter
class TestBaseReporterInit:
    """Tests for BaseReporter.__init__."""

    def test_default_output_dir(self):
        reporter = ConcreteReporter(config={})
        assert reporter.output_dir == "reports"

    def test_default_include_details(self):
        reporter = ConcreteReporter(config={})
        assert reporter.include_details is True

    def test_custom_output_dir(self):
        config = {"report": {"output_dir": "/tmp/custom_reports"}}
        reporter = ConcreteReporter(config=config)
        assert reporter.output_dir == "/tmp/custom_reports"

    def test_custom_include_details_false(self):
        config = {"report": {"include_details": False}}
        reporter = ConcreteReporter(config=config)
        assert reporter.include_details is False

    def test_stores_full_config(self):
        config = {"report": {"output_dir": "out", "include_details": True}, "extra": 1}
        reporter = ConcreteReporter(config=config)
        assert reporter.config is config

    def test_missing_report_section_uses_defaults(self):
        reporter = ConcreteReporter(config={"other": True})
        assert reporter.output_dir == "reports"
        assert reporter.include_details is True
