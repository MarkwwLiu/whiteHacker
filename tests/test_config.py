"""Unit tests for configuration loader."""

import os
import tempfile

import pytest
import yaml

from whitehats.config import load_config, _deep_merge


class TestDeepMerge:
    """Tests for _deep_merge helper."""

    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"scan": {"timeout": 10, "delay": 0.5}}
        override = {"scan": {"timeout": 30}}
        result = _deep_merge(base, override)
        assert result["scan"]["timeout"] == 30
        assert result["scan"]["delay"] == 0.5

    def test_deep_nested_merge(self):
        base = {"a": {"b": {"c": 1, "d": 2}}}
        override = {"a": {"b": {"c": 99}}}
        result = _deep_merge(base, override)
        assert result["a"]["b"]["c"] == 99
        assert result["a"]["b"]["d"] == 2

    def test_override_non_dict(self):
        base = {"a": {"b": 1}}
        override = {"a": "replaced"}
        result = _deep_merge(base, override)
        assert result["a"] == "replaced"


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_default_config(self):
        config = load_config()
        assert "scan" in config
        assert "modules" in config
        assert "report" in config
        assert "generator" in config

    def test_default_scan_settings(self):
        config = load_config()
        assert config["scan"]["timeout"] == 10
        assert config["scan"]["request_delay"] == 0.5
        assert config["scan"]["max_concurrent"] == 5

    def test_default_modules_enabled(self):
        config = load_config()
        modules = config["modules"]
        assert modules["sql_injection"]["enabled"] is True
        assert modules["xss"]["enabled"] is True
        assert modules["csrf"]["enabled"] is True

    def test_load_with_user_override(self):
        user_config = {
            "scan": {"timeout": 30},
            "modules": {"sql_injection": {"enabled": False}},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(user_config, f)
            tmp_path = f.name

        try:
            config = load_config(tmp_path)
            assert config["scan"]["timeout"] == 30
            assert config["scan"]["request_delay"] == 0.5  # default preserved
            assert config["modules"]["sql_injection"]["enabled"] is False
            assert config["modules"]["xss"]["enabled"] is True  # default preserved
        finally:
            os.unlink(tmp_path)

    def test_load_nonexistent_user_config(self):
        config = load_config("/nonexistent/path.yaml")
        # Should fallback to defaults
        assert config["scan"]["timeout"] == 10
