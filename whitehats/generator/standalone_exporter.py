"""Standalone script exporter.

Bundles a generated test file into a single self-contained Python script
that can be run anywhere with only ``requests`` and ``pytest`` installed.
"""

import os
import re
import textwrap
from datetime import datetime
from pathlib import Path


# Inline conftest / fixtures that get embedded into every exported script
_STANDALONE_HEADER = '''\
#!/usr/bin/env python3
"""
Standalone security test script — exported by WhiteHats Framework.
Generated: {timestamp}
Source: {source_file}

Usage:
    pip install requests pytest   # only dependencies needed
    pytest {output_filename} -v
"""
import pytest
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse


# ---------------------------------------------------------------------------
# Inline fixture (replaces conftest.py)
# ---------------------------------------------------------------------------
@pytest.fixture
def security_session():
    """Create a requests session for security testing."""
    session = requests.Session()
    session.headers.update({{
        "User-Agent": "WhiteHats-SecurityScanner/1.0 (standalone)",
    }})
    yield session
    session.close()

'''


class StandaloneExporter:
    """Exports a generated test file into a fully self-contained script."""

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    def export(
        self,
        source_path: str,
        output_path: str | None = None,
    ) -> str:
        """Export a test file as a standalone script.

        Args:
            source_path: Path to the generated test file to export.
            output_path: Where to write the standalone script.
                         Defaults to ``standalone_<original_name>.py``.

        Returns:
            The path of the exported standalone script.
        """
        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"Source test file not found: {source_path}")

        source_code = source.read_text()

        # Strip original header comments / docstrings and imports that we will
        # provide in the standalone header.
        body = self._strip_header(source_code)

        # Build standalone output
        out_filename = self._resolve_output_filename(source, output_path)
        header = _STANDALONE_HEADER.format(
            timestamp=datetime.now().isoformat(),
            source_file=source.name,
            output_filename=Path(out_filename).name,
        )
        standalone = header + body

        # Ensure output directory exists
        out_path = Path(out_filename)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(standalone)

        return str(out_path)

    def list_exportable(self, test_dir: str = "test_cases") -> list[str]:
        """List test files that can be exported.

        Returns:
            List of file paths under *test_dir* that match
            ``test_security_*.py``.
        """
        d = Path(test_dir)
        if not d.is_dir():
            return []
        return sorted(
            str(p) for p in d.glob("test_security_*.py")
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _strip_header(self, code: str) -> str:
        """Remove original imports / docstring that we replace.

        Strategy: walk forward through lines, skipping the docstring,
        imports, and surrounding blank lines.  Return everything from the
        first "real code" line onward.
        """
        lines = code.splitlines(keepends=True)
        i = 0
        n = len(lines)

        # 1. Skip leading blank lines
        while i < n and lines[i].strip() == "":
            i += 1

        # 2. Skip module-level docstring if present
        if i < n:
            stripped = lines[i].strip()
            for quote in ('"""', "'''"):
                if stripped.startswith(quote):
                    if stripped.count(quote) >= 2:
                        # Single-line docstring (e.g. """my doc""")
                        i += 1
                    else:
                        # Multi-line docstring — advance past closing quote
                        i += 1
                        while i < n:
                            if quote in lines[i]:
                                i += 1
                                break
                            i += 1
                    break  # done with docstring

        # 3. Skip import lines and blank lines that follow
        while i < n:
            stripped = lines[i].strip()
            if stripped == "" or self._is_header_import(stripped):
                i += 1
            else:
                break

        return "".join(lines[i:])

    @staticmethod
    def _is_header_import(line: str) -> bool:
        """Return True if the line is an import we embed in the header."""
        replaceable = [
            "import pytest",
            "import requests",
            "from urllib.parse import",
        ]
        return any(line.startswith(prefix) for prefix in replaceable)

    @staticmethod
    def _resolve_output_filename(source: Path, output_path: str | None) -> str:
        if output_path:
            return output_path
        name = source.stem  # e.g. test_security_examplecom
        return str(source.parent / f"standalone_{name}.py")
