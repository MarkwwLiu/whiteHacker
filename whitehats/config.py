"""Configuration loader for the WhiteHats framework."""

import os
from pathlib import Path

import yaml


DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "default_config.yaml"


def load_config(config_path: str = None) -> dict:
    """Load configuration from YAML file, merging with defaults."""
    # Load defaults
    with open(DEFAULT_CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    # Override with user config if provided
    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            user_config = yaml.safe_load(f)
        if user_config:
            _deep_merge(config, user_config)

    return config


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base dict."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base
