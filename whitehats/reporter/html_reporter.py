"""HTML report generator."""

import os
from datetime import datetime

from jinja2 import Template

from whitehats.models.vulnerability import Vulnerability
from whitehats.reporter.base_reporter import BaseReporter

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WhiteHats Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #1a1a2e; margin-bottom: 10px; }
        .meta { color: #666; margin-bottom: 30px; }
        .summary { display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap; }
        .summary-card { background: white; border-radius: 8px; padding: 20px; min-width: 150px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .summary-card .count { font-size: 2em; font-weight: bold; }
        .critical { color: #d32f2f; border-left: 4px solid #d32f2f; }
        .high { color: #f57c00; border-left: 4px solid #f57c00; }
        .medium { color: #fbc02d; border-left: 4px solid #fbc02d; }
        .low { color: #388e3c; border-left: 4px solid #388e3c; }
        .info { color: #1976d2; border-left: 4px solid #1976d2; }
        .vuln-card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .vuln-card h3 { margin-bottom: 10px; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; color: white; margin-right: 10px; }
        .badge.critical { background: #d32f2f; color: white; }
        .badge.high { background: #f57c00; color: white; }
        .badge.medium { background: #fbc02d; color: #333; }
        .badge.low { background: #388e3c; color: white; }
        .badge.info { background: #1976d2; color: white; }
        .detail { margin-top: 10px; padding: 10px; background: #f9f9f9; border-radius: 4px; font-family: monospace; font-size: 0.9em; white-space: pre-wrap; word-break: break-all; }
        .field { margin-top: 8px; }
        .field-label { font-weight: bold; color: #555; }
    </style>
</head>
<body>
    <div class="container">
        <h1>WhiteHats Security Report</h1>
        <p class="meta">Generated: {{ generated_at }} | Target: {{ target_url }}</p>

        <div class="summary">
            <div class="summary-card">
                <div class="count">{{ total }}</div>
                <div>Total Findings</div>
            </div>
            {% for sev, count in severity_counts.items() %}
            <div class="summary-card {{ sev }}">
                <div class="count">{{ count }}</div>
                <div>{{ sev | upper }}</div>
            </div>
            {% endfor %}
        </div>

        {% for vuln in vulnerabilities %}
        <div class="vuln-card {{ vuln.severity }}">
            <h3><span class="badge {{ vuln.severity }}">{{ vuln.severity | upper }}</span>{{ vuln.name }}</h3>
            <div class="field"><span class="field-label">Module:</span> {{ vuln.module }}</div>
            <div class="field"><span class="field-label">Description:</span> {{ vuln.description }}</div>
            <div class="field"><span class="field-label">Target:</span> {{ vuln.target_url }}</div>
            {% if vuln.evidence %}
            <div class="field"><span class="field-label">Evidence:</span></div>
            <div class="detail">{{ vuln.evidence }}</div>
            {% endif %}
            {% if vuln.remediation %}
            <div class="field"><span class="field-label">Remediation:</span> {{ vuln.remediation }}</div>
            {% endif %}
            {% if vuln.cwe_id %}
            <div class="field"><span class="field-label">CWE:</span> {{ vuln.cwe_id }}</div>
            {% endif %}
        </div>
        {% endfor %}

        {% if not vulnerabilities %}
        <div class="vuln-card">
            <h3>No vulnerabilities found.</h3>
        </div>
        {% endif %}
    </div>
</body>
</html>"""


class HTMLReporter(BaseReporter):
    """Generates HTML format security reports."""

    def generate(
        self, vulnerabilities: list[Vulnerability], target_info: dict
    ) -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        severity_counts = {}
        for vuln in vulnerabilities:
            sev = vuln.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        template = Template(HTML_TEMPLATE)
        html = template.render(
            generated_at=datetime.now().isoformat(),
            target_url=target_info.get("url", "N/A"),
            total=len(vulnerabilities),
            severity_counts=severity_counts,
            vulnerabilities=[v.to_dict() for v in vulnerabilities],
        )

        with open(filepath, "w") as f:
            f.write(html)

        return filepath
