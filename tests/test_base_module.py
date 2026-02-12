"""Unit tests for BaseModule abstract class."""

from unittest.mock import MagicMock

import pytest
import requests

from whitehats.modules.base_module import BaseModule
from whitehats.models.target import Target
from whitehats.models.vulnerability import Vulnerability


class ConcreteModule(BaseModule):
    """Concrete implementation for testing the abstract base."""

    name = "test_module"
    description = "A test module"

    def run(self, target, baseline_response):
        return []


def _make_scanner():
    scanner = MagicMock()
    scanner.send_request = MagicMock(return_value=None)
    return scanner


@pytest.mark.unit
@pytest.mark.base_module
class TestBaseModuleInit:
    """Tests for BaseModule.__init__."""

    def test_extracts_level_from_config(self):
        config = {"modules": {"test_module": {"enabled": True, "level": 3}}}
        mod = ConcreteModule(config=config, scanner=_make_scanner())
        assert mod.level == 3

    def test_default_level_when_missing(self):
        config = {"modules": {"test_module": {"enabled": True}}}
        mod = ConcreteModule(config=config, scanner=_make_scanner())
        assert mod.level == 1

    def test_default_level_when_no_module_config(self):
        config = {"modules": {}}
        mod = ConcreteModule(config=config, scanner=_make_scanner())
        assert mod.level == 1

    def test_default_level_when_no_modules_section(self):
        config = {}
        mod = ConcreteModule(config=config, scanner=_make_scanner())
        assert mod.level == 1

    def test_stores_config_and_scanner(self):
        config = {"modules": {"test_module": {"enabled": True}}}
        scanner = _make_scanner()
        mod = ConcreteModule(config=config, scanner=scanner)
        assert mod.config is config
        assert mod.scanner is scanner

    def test_name_and_description(self):
        mod = ConcreteModule(config={}, scanner=_make_scanner())
        assert mod.name == "test_module"
        assert mod.description == "A test module"


@pytest.mark.unit
@pytest.mark.base_module
class TestBaseModuleSend:
    """Tests for BaseModule._send convenience method."""

    def test_send_delegates_to_scanner(self):
        scanner = _make_scanner()
        resp = MagicMock(spec=requests.Response)
        scanner.send_request.return_value = resp

        mod = ConcreteModule(config={}, scanner=scanner)
        result = mod._send("GET", "https://example.com", params={"q": "1"})

        scanner.send_request.assert_called_once_with(
            method="GET", url="https://example.com", params={"q": "1"}
        )
        assert result is resp

    def test_send_returns_none_on_failure(self):
        scanner = _make_scanner()
        scanner.send_request.return_value = None

        mod = ConcreteModule(config={}, scanner=scanner)
        result = mod._send("POST", "https://example.com")
        assert result is None

    def test_send_passes_all_kwargs(self):
        scanner = _make_scanner()
        mod = ConcreteModule(config={}, scanner=scanner)

        mod._send(
            "POST",
            "https://example.com/api",
            headers={"X-Token": "abc"},
            params={"id": "1"},
            data={"key": "val"},
            json={"field": "value"},
        )

        scanner.send_request.assert_called_once_with(
            method="POST",
            url="https://example.com/api",
            headers={"X-Token": "abc"},
            params={"id": "1"},
            data={"key": "val"},
            json={"field": "value"},
        )
