"""
tests/test_cli.py
~~~~~~~~~~~~~~~~~
Smoke tests for the autotimeliner CLI — verifies argparse wiring
without requiring Volatility3 or a real memory image.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from autotimeliner import cli


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


class TestProcessImageOsAwareSelection:
    def test_linux_image_enables_linux_plugins(self, monkeypatch):
        captured: dict[str, object] = {}

        def fake_identify_memory_profile(_image_path):
            return {"os": "linux", "profile": "linux:fake", "probe_plugin": "linux.banners.Banners"}

        def fake_create_timeline(**kwargs):
            captured.update(kwargs)
            return []

        monkeypatch.setattr(cli, "identify_memory_profile", fake_identify_memory_profile)
        monkeypatch.setattr(cli, "create_timeline", fake_create_timeline)

        cli.process_image(
            image_path=Path("/tmp/sample-linux.mem"),
            timeframe=None,
            output=None,
            use_mactime=False,
            skip_timeliner=False,
            skip_mftscan=False,
            skip_shellbags=False,
            skip_psscan=False,
            skip_cmdline=False,
            skip_netscan=False,
            skip_userassist=False,
            with_dlllist=True,
            skip_svcscan=False,
            with_filescan=True,
            skip_malfind=False,
            with_handles=True,
            with_envars=True,
        )

        assert captured["os_family"] == "linux"
        assert captured["run_timeliner"] is True
        assert captured["run_mftscan"] is False
        assert captured["run_shellbags"] is False
        assert captured["run_psscan"] is False
        assert captured["run_cmdline"] is False
        assert captured["run_netscan"] is False
        assert captured["run_userassist"] is False
        assert captured["run_dlllist"] is False
        assert captured["run_svcscan"] is False
        assert captured["run_filescan"] is False
        assert captured["run_malfind"] is False
        assert captured["run_handles"] is False
        assert captured["run_envars"] is False
        assert captured["run_linux_pslist"] is True
        assert captured["run_linux_bash"] is True
        assert captured["run_linux_lsof"] is True
        assert captured["run_mac_pslist"] is False
        assert captured["run_mac_bash"] is False
        assert captured["run_mac_lsof"] is False

    def test_macos_image_enables_macos_plugins(self, monkeypatch):
        captured: dict[str, object] = {}

        def fake_identify_memory_profile(_image_path):
            return {"os": "mac", "profile": "mac", "probe_plugin": "mac.pslist.PsList"}

        def fake_create_timeline(**kwargs):
            captured.update(kwargs)
            return []

        monkeypatch.setattr(cli, "identify_memory_profile", fake_identify_memory_profile)
        monkeypatch.setattr(cli, "create_timeline", fake_create_timeline)

        cli.process_image(
            image_path=Path("/tmp/sample-macos.mem"),
            timeframe=None,
            output=None,
            use_mactime=False,
            skip_timeliner=False,
            skip_mftscan=False,
            skip_shellbags=False,
            skip_psscan=False,
            skip_cmdline=False,
            skip_netscan=False,
            skip_userassist=False,
            with_dlllist=False,
            skip_svcscan=False,
            with_filescan=False,
            skip_malfind=False,
            with_handles=False,
            with_envars=False,
        )

        assert captured["os_family"] == "mac"
        assert captured["run_timeliner"] is True
        assert captured["run_mac_pslist"] is True
        assert captured["run_mac_bash"] is True
        assert captured["run_mac_lsof"] is True
        assert captured["run_linux_pslist"] is False
        assert captured["run_linux_bash"] is False
        assert captured["run_linux_lsof"] is False
        assert captured["run_mftscan"] is False
        assert captured["run_psscan"] is False

    def test_os_hint_skips_identification_and_enables_linux_plugins(self, monkeypatch):
        captured: dict[str, object] = {}

        def fail_identify(_image_path):
            raise AssertionError("identify_memory_profile should not be called when --os-hint is used")

        def fake_create_timeline(**kwargs):
            captured.update(kwargs)
            return []

        monkeypatch.setattr(cli, "identify_memory_profile", fail_identify)
        monkeypatch.setattr(cli, "create_timeline", fake_create_timeline)

        cli.process_image(
            image_path=Path("/tmp/sample-hinted.mem"),
            timeframe=None,
            output=None,
            use_mactime=False,
            skip_timeliner=False,
            skip_mftscan=False,
            skip_shellbags=False,
            skip_psscan=False,
            skip_cmdline=False,
            skip_netscan=False,
            skip_userassist=False,
            with_dlllist=False,
            skip_svcscan=False,
            with_filescan=False,
            skip_malfind=False,
            with_handles=False,
            with_envars=False,
            os_hint="linux",
        )

        assert captured["os_family"] == "linux"
        assert captured["run_linux_pslist"] is True
        assert captured["run_linux_bash"] is True
        assert captured["run_linux_lsof"] is True
        assert captured["run_mftscan"] is False
        assert captured["run_psscan"] is False
