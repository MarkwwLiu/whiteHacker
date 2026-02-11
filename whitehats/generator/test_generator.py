"""Auto-generates pytest-style security test cases from targets."""

import logging
import os
from pathlib import Path

from whitehats.generator.template_engine import TemplateEngine
from whitehats.models.target import APITarget, Target, TargetType, URLTarget

logger = logging.getLogger(__name__)


class TestGenerator:
    """Generates decoupled pytest test files from API/URL targets."""

    def __init__(self, config: dict):
        self.config = config
        gen_cfg = config.get("generator", {})
        self.output_dir = Path(gen_cfg.get("output_dir", "test_cases"))
        self.template_engine = TemplateEngine()

    def generate(self, targets: list[Target]) -> list[str]:
        """Generate test files for all provided targets.

        Returns list of generated file paths.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        generated_files = []

        for target in targets:
            file_path = self._generate_for_target(target)
            if file_path:
                generated_files.append(file_path)
                logger.info("Generated test file: %s", file_path)

        # Generate conftest.py for shared fixtures
        conftest_path = self._generate_conftest(targets)
        if conftest_path:
            generated_files.append(conftest_path)

        return generated_files

    def _generate_for_target(self, target: Target) -> str | None:
        """Generate a test file for a single target."""
        # Create a safe filename from the URL
        safe_name = self._url_to_filename(target.url)
        file_path = self.output_dir / f"test_security_{safe_name}.py"

        if target.target_type == TargetType.API:
            content = self.template_engine.render_api_test(target)
        else:
            content = self.template_engine.render_url_test(target)

        file_path.write_text(content)
        return str(file_path)

    def _generate_conftest(self, targets: list[Target]) -> str | None:
        """Generate conftest.py with shared fixtures."""
        file_path = self.output_dir / "conftest.py"
        content = self.template_engine.render_conftest(targets)
        file_path.write_text(content)
        return str(file_path)

    def _url_to_filename(self, url: str) -> str:
        """Convert a URL to a safe filename."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        name = parsed.netloc + parsed.path
        # Replace non-alphanumeric characters with underscores
        safe = "".join(c if c.isalnum() else "_" for c in name)
        # Collapse multiple underscores
        while "__" in safe:
            safe = safe.replace("__", "_")
        return safe.strip("_").lower()[:80]
