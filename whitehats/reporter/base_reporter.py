"""Abstract base reporter."""

from abc import ABC, abstractmethod

from whitehats.models.vulnerability import Vulnerability


class BaseReporter(ABC):
    """Base class for all reporters."""

    def __init__(self, config: dict):
        self.config = config
        report_cfg = config.get("report", {})
        self.output_dir = report_cfg.get("output_dir", "reports")
        self.include_details = report_cfg.get("include_details", True)

    @abstractmethod
    def generate(
        self, vulnerabilities: list[Vulnerability], target_info: dict
    ) -> str:
        """Generate a report and return the output file path."""
