"""JSON report generator."""

import json
import os
from datetime import datetime

from whitehats.models.vulnerability import Vulnerability
from whitehats.reporter.base_reporter import BaseReporter


class JSONReporter(BaseReporter):
    """Generates JSON format security reports."""

    def generate(
        self, vulnerabilities: list[Vulnerability], target_info: dict
    ) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        # Build summary
        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "framework": "WhiteHats Security Testing Framework",
                "version": "1.0.0",
            },
            "target": target_info,
            "summary": {
                "total_findings": len(vulnerabilities),
                "severity_breakdown": severity_counts,
            },
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        }

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return filepath
