"""
tests/test_cli.py
~~~~~~~~~~~~~~~~~
Smoke tests for the autotimeliner CLI — verifies argparse wiring
without requiring Volatility3 or a real memory image.
"""

from __future__ import annotations

import subprocess
import sys


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "autotimeliner.cli"] + list(args),
        capture_output=True,
        text=True,
    )


class TestCli:
    def test_help_exits_zero(self):
        result = _run("--help")
        assert result.returncode == 0
        assert "--imagefile" in result.stdout

    def test_version_flag(self):
        result = _run("--version")
        assert result.returncode == 0
        assert "autotimeliner" in result.stdout

    def test_missing_imagefile_exits_nonzero(self):
        result = _run("--timeframe", "2023-01-01..2023-12-31")
        assert result.returncode != 0

    def test_nonexistent_glob_exits_nonzero(self):
        result = _run("-f", "/tmp/no_such_file_xyzzy.raw")
        assert result.returncode == 1
        assert "No files matched" in result.stderr
