"""Concurrent scanner for parallel multi-target scanning."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from whitehats.models.target import APITarget, Target, URLTarget
from whitehats.models.vulnerability import Vulnerability
from whitehats.modules.base_module import BaseModule
from whitehats.scanner.api_scanner import APIScanner
from whitehats.scanner.url_scanner import URLScanner

logger = logging.getLogger(__name__)


class ConcurrentScanner:
    """Scans multiple targets concurrently using a thread pool."""

    def __init__(
        self,
        config: dict,
        modules: Optional[list[type[BaseModule]]] = None,
    ):
        self.config = config
        self.modules = modules
        scan_cfg = config.get("scan", {})
        self.max_workers = scan_cfg.get("max_concurrent", 5)

    def _scan_single_target(self, target: Target) -> list[Vulnerability]:
        """Scan a single target with the appropriate scanner."""
        if isinstance(target, APITarget):
            scanner = APIScanner(config=self.config, modules=self.modules)
        elif isinstance(target, URLTarget):
            scanner = URLScanner(config=self.config, modules=self.modules)
        else:
            logger.error("Unknown target type: %s", type(target).__name__)
            return []

        try:
            return scanner.scan(target)
        except Exception as e:
            logger.error("Scan failed for %s: %s", target.url, e)
            return []

    def scan(
        self,
        targets: list[Target],
        progress_callback=None,
    ) -> dict[str, list[Vulnerability]]:
        """Scan multiple targets concurrently.

        Args:
            targets: List of targets to scan.
            progress_callback: Optional callback(target_url, vulns, index, total)
                               called when each target completes.

        Returns:
            Dict mapping target URL to list of vulnerabilities found.
        """
        results: dict[str, list[Vulnerability]] = {}
        total = len(targets)

        if total == 0:
            return results

        # For a single target, skip the overhead of thread pool
        if total == 1:
            target = targets[0]
            vulns = self._scan_single_target(target)
            results[target.url] = vulns
            if progress_callback:
                progress_callback(target.url, vulns, 1, total)
            return results

        logger.info(
            "Starting concurrent scan of %d targets (max_workers=%d)",
            total,
            self.max_workers,
        )

        completed = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(self._scan_single_target, target): target
                for target in targets
            }

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                completed += 1
                try:
                    vulns = future.result()
                    results[target.url] = vulns
                    logger.info(
                        "[%d/%d] Completed: %s (%d findings)",
                        completed,
                        total,
                        target.url,
                        len(vulns),
                    )
                    if progress_callback:
                        progress_callback(target.url, vulns, completed, total)
                except Exception as e:
                    logger.error("[%d/%d] Failed: %s - %s", completed, total, target.url, e)
                    results[target.url] = []

        return results
