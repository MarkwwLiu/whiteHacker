"""Abstract base scanner for security testing."""

import logging
import time
from abc import ABC, abstractmethod
from typing import Optional

import requests

from whitehats.models.target import Target
from whitehats.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """Base class for all scanners."""

    def __init__(self, config: dict):
        self.config = config
        scan_cfg = config.get("scan", {})
        self.timeout = scan_cfg.get("timeout", 10)
        self.request_delay = scan_cfg.get("request_delay", 0.5)
        self.verify_ssl = scan_cfg.get("verify_ssl", True)
        self.follow_redirects = scan_cfg.get("follow_redirects", True)
        self.user_agent = scan_cfg.get("user_agent", "WhiteHats-SecurityScanner/1.0")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self.vulnerabilities: list[Vulnerability] = []

    def send_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> Optional[requests.Response]:
        """Send an HTTP request with configured settings."""
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json_data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=self.follow_redirects,
            )
            time.sleep(self.request_delay)
            return response
        except requests.RequestException as e:
            logger.error("Request failed for %s: %s", url, e)
            return None

    def add_vulnerability(self, vuln: Vulnerability):
        """Record a discovered vulnerability."""
        self.vulnerabilities.append(vuln)
        logger.warning(
            "[%s] %s found at %s", vuln.severity.value.upper(), vuln.name, vuln.target_url
        )

    @abstractmethod
    def scan(self, target: Target) -> list[Vulnerability]:
        """Execute scan against a target. Must be implemented by subclasses."""

    def get_results(self) -> list[Vulnerability]:
        """Return all discovered vulnerabilities."""
        return self.vulnerabilities

    def clear_results(self):
        """Clear stored vulnerabilities."""
        self.vulnerabilities = []
