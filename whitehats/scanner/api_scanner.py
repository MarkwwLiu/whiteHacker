"""API endpoint scanner."""

import logging
from typing import Optional

from whitehats.models.target import APITarget, Target
from whitehats.models.vulnerability import Vulnerability
from whitehats.modules.base_module import BaseModule
from whitehats.scanner.base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class APIScanner(BaseScanner):
    """Scanner specialized for API endpoints."""

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
        """Run all enabled modules against an API target."""
        if not isinstance(target, APITarget):
            logger.error("APIScanner requires an APITarget, got %s", type(target).__name__)
            return []

        logger.info("Starting API scan on: %s [%s]", target.url, target.method.value)

        # First, do a baseline request
        baseline = self.send_request(
            method=target.method.value,
            url=target.url,
            headers=target.get_request_headers(),
            params=target.params,
            json_data=target.body,
        )

        if baseline is None:
            logger.error("Cannot reach target: %s", target.url)
            return []

        logger.info("Baseline response: %d (%d bytes)", baseline.status_code, len(baseline.content))

        # Run each security module
        for module in self.modules:
            logger.info("Running module: %s", module.name)
            try:
                findings = module.run(target, baseline_response=baseline)
                for vuln in findings:
                    self.add_vulnerability(vuln)
            except Exception as e:
                logger.error("Module %s failed: %s", module.name, e)

        return self.vulnerabilities
