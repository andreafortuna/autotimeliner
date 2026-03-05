"""
cli.py
~~~~~~
Command-line entry point for AutoTimeliner.

Installed as the ``autotimeliner`` script via pyproject.toml:
    [tool.poetry.scripts]
    autotimeliner = "autotimeliner.cli:main"
"""

from __future__ import annotations

import logging
import sys
import textwrap
from glob import glob
from pathlib import Path
from typing import Optional

from autotimeliner import __version__
from autotimeliner.timeliner import create_timeline
from autotimeliner.exporter import export_csv, export_mactime
from autotimeliner.vol3_runner import identify_memory_profile

ASCII_LOGO = r"""
                _     _______ _                _ _                 
     /\        | |   |__   __(_)              | (_)                
    /  \  _   _| |_ ___ | |   _ _ __ ___   ___| |_ _ __   ___ _ __ 
   / /\ \| | | | __/ _ \| |  | | '_ ` _ \ / _ \ | | '_ \ / _ \ '__|
  / ____ \ |_| | || (_) | |  | | | | | | |  __/ | | | | |  __/ |   
 /_/    \_\__,_|\__\___/|_|  |_|_| |_| |_|\___|_|_|_| |_|\___|_|                                                                       
                            Memory Timeline Extraction
"""

SUCCESS_LEVEL = 25

_OS_HINT_MAP = {
    "windows": "windows",
    "win": "windows",
    "linux": "linux",
    "mac": "mac",
    "macos": "mac",
    "darwin": "mac",
}


class _MalhuntStyleFormatter(logging.Formatter):
    _RESET = "\033[0m"
    _LEVEL_COLORS = {
        "DEBUG": "\033[37m",
        "INFO": "\033[36m",
        "SUCCESS": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[1;31m",
    }

    def __init__(self, use_colors: bool) -> None:
        super().__init__("%(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s")
        self.use_colors = use_colors

    def format(self, record: logging.LogRecord) -> str:
        if not self.use_colors:
            return super().format(record)

        level = record.levelname
        color = self._LEVEL_COLORS.get(level, "")
        if color:
            record.levelname = f"{color}{level}{self._RESET}"
        try:
            return super().format(record)
        finally:
            record.levelname = level


def _install_success_level() -> None:
    logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

    if hasattr(logging.Logger, "success"):
        return

    def _success(self: logging.Logger, message: str, *args: object, **kwargs: object) -> None:
        if self.isEnabledFor(SUCCESS_LEVEL):
            self._log(SUCCESS_LEVEL, message, args, **kwargs)

    logging.Logger.success = _success  # type: ignore[attr-defined]


def _render_banner(version: str) -> str:
    title = f"AUTOTIMELINER v{version} - Timeline Extraction with Volatility3"
    top = "╔" + "═" * (len(title) + 4) + "╗"
    middle = f"║  {title}  ║"
    bottom = "╚" + "═" * (len(title) + 4) + "╝"

    return textwrap.dedent(
        f"""\
        {top}
        {middle}
        {bottom}

        {ASCII_LOGO}
        Extract timelines from memory dumps with Volatility3!

        Andrea Fortuna
        andrea@andreafortuna.org
        https://andreafortuna.org
        """
    )


def _setup_logging(verbose: bool) -> None:
    _install_success_level()
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_MalhuntStyleFormatter(use_colors=sys.stderr.isatty()))

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    root.addHandler(handler)

    # Volatility may emit YARA availability messages even when YARA-based
    # plugins are not used by AutoTimeliner.
    logging.getLogger("volatility3.plugins.yarascan").setLevel(logging.ERROR)


def _bold(text: str) -> str:
    return f"\033[1m{text}\033[0m"


def _normalize_os_family(value: Optional[str]) -> str:
    if not value:
        return "unknown"
    return _OS_HINT_MAP.get(value.strip().lower(), "unknown")


def process_image(
    image_path: Path,
    timeframe: Optional[str],
    output: Optional[Path],
    use_mactime: bool,
    skip_timeliner: bool,
    skip_mftscan: bool,
    skip_shellbags: bool,
    skip_psscan: bool,
    skip_cmdline: bool,
    skip_netscan: bool,
    skip_userassist: bool,
    with_dlllist: bool,
    skip_svcscan: bool,
    with_filescan: bool,
    skip_malfind: bool,
    with_handles: bool,
    with_envars: bool,
    os_hint: Optional[str] = None,
) -> None:
    log = logging.getLogger(__name__)
    out_path = output or image_path.parent / (image_path.name + "-timeline.csv")

    log.info("=" * 70)
    log.info("Processing image: %s", image_path)
    log.info("=" * 70)

    normalized_hint = _normalize_os_family(os_hint)
    if normalized_hint != "unknown":
        log.info("Using --os-hint=%s: skipping automatic OS identification", normalized_hint)
        os_family = normalized_hint
        profile_hint = f"hint:{normalized_hint}"
        probe = "user-hint"
    else:
        log.info("Identifying memory dump OS and version...")
        log.info("OS identification may take some time while Volatility automagics initialize")
        profile = identify_memory_profile(image_path)
        os_family = profile.get("os") or "unknown"
        profile_hint = profile.get("profile") or "n/a"
        probe = profile.get("probe_plugin") or "n/a"
    log.info(
        "OS identification result -> os=%s, profile=%s, probe=%s",
        os_family,
        profile_hint,
        probe,
    )
    log.log(
        SUCCESS_LEVEL,
        "Memory OS: %s | profile hint: %s | probe: %s",
        os_family,
        profile_hint,
        probe,
    )

    effective_os_family = _normalize_os_family(os_family)

    effective_skip_mftscan = skip_mftscan
    effective_skip_shellbags = skip_shellbags
    effective_skip_psscan = skip_psscan
    effective_skip_cmdline = skip_cmdline
    effective_skip_netscan = skip_netscan
    effective_skip_userassist = skip_userassist
    effective_with_dlllist = with_dlllist
    effective_skip_svcscan = skip_svcscan
    effective_with_filescan = with_filescan
    effective_skip_malfind = skip_malfind
    effective_with_handles = with_handles
    effective_with_envars = with_envars

    run_linux_pslist = False
    run_linux_bash = False
    run_linux_lsof = False
    run_mac_pslist = False
    run_mac_bash = False
    run_mac_lsof = False

    if effective_os_family == "windows":
        log.info("Windows image detected: Windows forensic plugin set enabled")
    elif effective_os_family == "linux":
        # Disable Windows-only plugin set and enable Linux-specific collectors.
        effective_skip_mftscan = True
        effective_skip_shellbags = True
        effective_skip_psscan = True
        effective_skip_cmdline = True
        effective_skip_netscan = True
        effective_skip_userassist = True
        effective_with_dlllist = False
        effective_skip_svcscan = True
        effective_with_filescan = False
        effective_skip_malfind = True
        effective_with_handles = False
        effective_with_envars = False

        run_linux_pslist = True
        run_linux_bash = True
        run_linux_lsof = True
        log.info("Linux image detected: enabling linux.pslist/linux.bash/linux.lsof")
    elif effective_os_family == "mac":
        # Disable Windows-only plugin set and enable macOS-specific collectors.
        effective_skip_mftscan = True
        effective_skip_shellbags = True
        effective_skip_psscan = True
        effective_skip_cmdline = True
        effective_skip_netscan = True
        effective_skip_userassist = True
        effective_with_dlllist = False
        effective_skip_svcscan = True
        effective_with_filescan = False
        effective_skip_malfind = True
        effective_with_handles = False
        effective_with_envars = False

        run_mac_pslist = True
        run_mac_bash = True
        run_mac_lsof = True
        log.info("macOS image detected: enabling mac.pslist/mac.bash/mac.lsof")
    else:
        # Unknown images fall back to generic timeline extraction.
        effective_skip_mftscan = True
        effective_skip_shellbags = True
        effective_skip_psscan = True
        effective_skip_cmdline = True
        effective_skip_netscan = True
        effective_skip_userassist = True
        effective_with_dlllist = False
        effective_skip_svcscan = True
        effective_with_filescan = False
        effective_skip_malfind = True
        effective_with_handles = False
        effective_with_envars = False
        log.warning("Unknown image family '%s': running generic plugins only", os_family)

    if effective_os_family != "windows":
        unsupported_requested: list[str] = []
        if with_dlllist:
            unsupported_requested.append("--with-dlllist")
        if with_filescan:
            unsupported_requested.append("--with-filescan")
        if with_handles:
            unsupported_requested.append("--with-handles")
        if with_envars:
            unsupported_requested.append("--with-envars")
        if unsupported_requested:
            log.warning(
                "Ignored Windows-only flags for %s image: %s",
                effective_os_family,
                ", ".join(unsupported_requested),
            )

    planned_plugins: list[str] = []
    if not skip_timeliner:
        planned_plugins.append("timeliner.Timeliner")

    if effective_os_family == "windows":
        if not effective_skip_mftscan:
            planned_plugins.append("windows.mftscan.MFTScan")
        if not effective_skip_shellbags:
            planned_plugins.append("windows.shellbags.ShellBags")
        if not effective_skip_psscan:
            planned_plugins.append("windows.psscan.PsScan")
        if not effective_skip_cmdline:
            planned_plugins.append("windows.cmdline.CmdLine")
        if not effective_skip_netscan:
            planned_plugins.append("windows.netscan.NetScan")
        if not effective_skip_userassist:
            planned_plugins.append("windows.registry.userassist.UserAssist")
        if effective_with_dlllist:
            planned_plugins.append("windows.dlllist.DllList")
        if not effective_skip_svcscan:
            planned_plugins.append("windows.svcscan.SvcScan")
        if effective_with_filescan:
            planned_plugins.append("windows.filescan.FileScan")
        if not effective_skip_malfind:
            planned_plugins.append("windows.malfind.Malfind")
        if effective_with_handles:
            planned_plugins.append("windows.handles.Handles")
        if effective_with_envars:
            planned_plugins.append("windows.envars.Envars")
    elif effective_os_family == "linux":
        if run_linux_pslist:
            planned_plugins.append("linux.pslist.PsList")
        if run_linux_bash:
            planned_plugins.append("linux.bash.Bash")
        if run_linux_lsof:
            planned_plugins.append("linux.lsof.Lsof")
    elif effective_os_family == "mac":
        if run_mac_pslist:
            planned_plugins.append("mac.pslist.PsList")
        if run_mac_bash:
            planned_plugins.append("mac.bash.Bash")
        if run_mac_lsof:
            planned_plugins.append("mac.lsof.Lsof")

    if planned_plugins:
        log.info(
            "Plugins scheduled for execution (%d): %s",
            len(planned_plugins),
            ", ".join(planned_plugins),
        )
    else:
        log.warning("No plugins scheduled for execution with current options")

    log.info("Collecting timeline data from Volatility3 plugins...")
    records = create_timeline(
        image_path=image_path,
        os_family=effective_os_family,
        run_timeliner=not skip_timeliner,
        run_mftscan=not effective_skip_mftscan,
        run_shellbags=not effective_skip_shellbags,
        run_psscan=not effective_skip_psscan,
        run_cmdline=not effective_skip_cmdline,
        run_netscan=not effective_skip_netscan,
        run_userassist=not effective_skip_userassist,
        run_dlllist=effective_with_dlllist,
        run_svcscan=not effective_skip_svcscan,
        run_filescan=effective_with_filescan,
        run_malfind=not effective_skip_malfind,
        run_handles=effective_with_handles,
        run_envars=effective_with_envars,
        run_linux_pslist=run_linux_pslist,
        run_linux_bash=run_linux_bash,
        run_linux_lsof=run_linux_lsof,
        run_mac_pslist=run_mac_pslist,
        run_mac_bash=run_mac_bash,
        run_mac_lsof=run_mac_lsof,
    )

    if not records:
        log.warning(
            "No records collected - verify Volatility support/symbols for this %s memory image",
            effective_os_family,
        )
        return

    log.log(SUCCESS_LEVEL, "%d records collected. Writing output...", len(records))

    if use_mactime:
        log.info("Legacy mode enabled: using external mactime binary")
        result = export_mactime(records, out_path, timeframe)
    else:
        result = export_csv(records, out_path, timeframe)

    log.log(SUCCESS_LEVEL, "Timeline saved to: %s", result)


def main() -> None:
    import argparse

    print(_render_banner(__version__))

    parser = argparse.ArgumentParser(
        prog="autotimeliner",
        description="Automagically extract forensic timeline from volatile memory dumps (Volatility3).",
    )
    parser.add_argument(
        "-f", "--imagefile",
        required=True,
        help="Memory dump file or glob pattern (e.g. '*.raw')",
        metavar="IMAGEFILE",
    )
    parser.add_argument(
        "-t", "--timeframe",
        required=False,
        default=None,
        help="Filter output to a date range: YYYY-MM-DD..YYYY-MM-DD",
        metavar="TIMEFRAME",
    )
    parser.add_argument(
        "-o", "--output",
        required=False,
        default=None,
        help="Output CSV path (default: <imagefile>-timeline.csv)",
        metavar="OUTPUT",
    )
    parser.add_argument(
        "-p", "--customprofile",
        required=False,
        default=None,
        help="[DEPRECATED] Volatility2 profiles are not used in Volatility3. "
             "OS detection is automatic. This flag is ignored.",
        metavar="PROFILE",
    )
    parser.add_argument(
        "--os-hint",
        required=False,
        default=None,
        choices=["windows", "linux", "mac", "macos", "darwin", "win"],
        help="Optional OS hint to skip auto-identification and speed up startup",
        metavar="OS",
    )
    parser.add_argument(
        "--skip-timeliner",
        action="store_true",
        help="Skip the timeliner plugin",
    )
    parser.add_argument(
        "--skip-mftscan",
        action="store_true",
        help="Skip the mftscan (mftparser) plugin",
    )
    parser.add_argument(
        "--skip-shellbags",
        action="store_true",
        help="Skip the shellbags plugin",
    )
    parser.add_argument(
        "--skip-psscan",
        action="store_true",
        help="Skip the psscan plugin (process scanning)",
    )
    parser.add_argument(
        "--skip-cmdline",
        action="store_true",
        help="Skip the cmdline plugin (command line arguments)",
    )
    parser.add_argument(
        "--skip-netscan",
        action="store_true",
        help="Skip the netscan plugin (network connections)",
    )
    parser.add_argument(
        "--skip-userassist",
        action="store_true",
        help="Skip the userassist plugin (program execution evidence)",
    )
    parser.add_argument(
        "--with-dlllist",
        action="store_true",
        help="Enable dlllist plugin (DLL analysis - can be slow)",
    )
    parser.add_argument(
        "--skip-svcscan",
        action="store_true",
        help="Skip the svcscan plugin (Windows services)",
    )
    parser.add_argument(
        "--with-filescan",
        action="store_true",
        help="Enable filescan plugin (open files - generates many records)",
    )
    parser.add_argument(
        "--skip-malfind",
        action="store_true",
        help="Skip the malfind plugin (malware/injection detection)",
    )
    parser.add_argument(
        "--with-handles",
        action="store_true",
        help="Enable handles plugin (open handles - generates many records)",
    )
    parser.add_argument(
        "--with-envars",
        action="store_true",
        help="Enable envars plugin (environment variables)",
    )
    parser.add_argument(
        "--use-mactime",
        action="store_true",
        help="Legacy mode: use the external mactime binary (requires SleuthKit)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"autotimeliner {__version__}",
    )

    args = parser.parse_args()
    _setup_logging(args.verbose)

    if args.customprofile:
        logging.getLogger(__name__).warning(
            "--customprofile is a Volatility2 concept and is ignored in this version. "
            "Volatility3 identifies the memory profile/OS via automagic and symbol tables."
        )

    image_files = glob(args.imagefile)
    if not image_files:
        logging.getLogger(__name__).error("No files matched: %s", args.imagefile)
        sys.exit(1)

    output = Path(args.output) if args.output else None

    for image_file in sorted(image_files):
        try:
            process_image(
                image_path=Path(image_file),
                timeframe=args.timeframe,
                output=output,
                use_mactime=args.use_mactime,
                skip_timeliner=args.skip_timeliner,
                skip_mftscan=args.skip_mftscan,
                skip_shellbags=args.skip_shellbags,
                skip_psscan=args.skip_psscan,
                skip_cmdline=args.skip_cmdline,
                skip_netscan=args.skip_netscan,
                skip_userassist=args.skip_userassist,
                with_dlllist=args.with_dlllist,
                skip_svcscan=args.skip_svcscan,
                with_filescan=args.with_filescan,
                skip_malfind=args.skip_malfind,
                with_handles=args.with_handles,
                with_envars=args.with_envars,
                os_hint=args.os_hint,
            )
        except Exception as exc:  # noqa: BLE001
            logging.getLogger(__name__).error("Failed to process %s: %s", image_file, exc, exc_info=args.verbose)
            sys.exit(1)


if __name__ == "__main__":
    main()
