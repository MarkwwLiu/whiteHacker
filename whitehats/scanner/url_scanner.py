"""URL (web page) scanner."""

import logging
from typing import Optional

from whitehats.models.target import Target, URLTarget
from whitehats.models.vulnerability import Vulnerability
from whitehats.modules.base_module import BaseModule
from whitehats.scanner.base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class URLScanner(BaseScanner):
    """Scanner specialized for web page URLs."""

    def __init__(self, config: dict, modules: Optional[list[type[BaseModule]]] = None):
        super().__init__(config)
        self.modules: list[BaseModule] = []
        if modules:
            self._load_modules(modules)

    def _load_modules(self, module_classes: list[type[BaseModule]]):
        """Instantiate and load security test modules."""
        modules_cfg = self.config.get("modules", {})
        for cls in module_classes:
            module_name = cls.name
            mod_cfg = modules_cfg.get(module_name, {})
            if mod_cfg.get("enabled", True):
                self.modules.append(cls(config=self.config, scanner=self))
                logger.info("Loaded module: %s", module_name)

    def scan(self, target: Target) -> list[Vulnerability]:
        """Run all enabled modules against a URL target."""
        if not isinstance(target, URLTarget):
            logger.error("URLScanner requires a URLTarget, got %s", type(target).__name__)
            return []

        logger.info("Starting URL scan on: %s", target.url)

        headers = {"User-Agent": self.user_agent}
        headers.update(target.headers)

        baseline = self.send_request(
            method="GET",
            url=target.url,
            headers=headers,
        )

        if baseline is None:
            logger.error("Cannot reach target: %s", target.url)
            return []

        logger.info("Baseline response: %d (%d bytes)", baseline.status_code, len(baseline.content))

        for module in self.modules:
            logger.info("Running module: %s", module.name)
            try:
                findings = module.run(target, baseline_response=baseline)
                for vuln in findings:
                    self.add_vulnerability(vuln)
            except Exception as e:
                logger.error("Module %s failed: %s", module.name, e)

        return self.vulnerabilities
