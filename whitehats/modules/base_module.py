"""Abstract base module for security tests."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import requests

from whitehats.models.target import Target
from whitehats.models.vulnerability import Vulnerability

if TYPE_CHECKING:
    from whitehats.scanner.base_scanner import BaseScanner


class BaseModule(ABC):
    """Base class for all security test modules."""

    name: str = "base"
    description: str = ""

    def __init__(self, config: dict, scanner: "BaseScanner"):
        self.config = config
        self.scanner = scanner
        module_cfg = config.get("modules", {}).get(self.name, {})
        self.level = module_cfg.get("level", 1)

    @abstractmethod
    def run(
        self, target: Target, baseline_response: requests.Response
    ) -> list[Vulnerability]:
        """Execute security tests against the target.

        Args:
            target: The target to test.
            baseline_response: The normal response from the target.

        Returns:
            List of discovered vulnerabilities.
        """

    def _send(self, method: str, url: str, **kwargs) -> requests.Response | None:
        """Convenience wrapper around scanner's send_request."""
        return self.scanner.send_request(method=method, url=url, **kwargs)
