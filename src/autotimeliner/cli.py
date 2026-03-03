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
     _         _        _______ _                _ _
    / \  _   _| |_ ___ |__   __(_)              | (_)
   / _ \| | | | __/ _ \   | |   _ _ __ ___   ___| |_ _ __   ___ _ __
  / ___ \ |_| | || (_) |  | |  | | '_ ` _ \ / _ \ | | '_ \ / _ \ '__|
 /_/   \_\__,_|\__\___/   |_|  |_|_| |_| |_|\___|_|_|_| |_|\___|_|
"""

SUCCESS_LEVEL = 25


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


def process_image(
    image_path: Path,
    timeframe: Optional[str],
    output: Optional[Path],
    use_mactime: bool,
    skip_timeliner: bool,
    skip_mftscan: bool,
    skip_shellbags: bool,
) -> None:
    log = logging.getLogger(__name__)
    out_path = output or image_path.parent / (image_path.name + "-timeline.csv")

    log.info("=" * 70)
    log.info("Processing image: %s", image_path)
    log.info("=" * 70)

    log.info("Identifying memory dump OS and version...")
    profile = identify_memory_profile(image_path)
    os_family = profile.get("os") or "unknown"
    profile_hint = profile.get("profile") or "n/a"
    probe = profile.get("probe_plugin") or "n/a"
    log.log(
        SUCCESS_LEVEL,
        "Memory OS: %s | profile hint: %s | probe: %s",
        os_family,
        profile_hint,
        probe,
    )

    effective_skip_mftscan = skip_mftscan
    effective_skip_shellbags = skip_shellbags
    if os_family != "windows":
        # mftscan/shellbags are Windows plugins
        effective_skip_mftscan = True
        effective_skip_shellbags = True
        log.warning("Detected non-Windows image (%s): forcing --skip-mftscan and --skip-shellbags", os_family)

    log.info("Collecting timeline data from Volatility3 plugins...")
    records = create_timeline(
        image_path=image_path,
        run_timeliner=not skip_timeliner,
        run_mftscan=not effective_skip_mftscan,
        run_shellbags=not effective_skip_shellbags,
    )

    if not records:
        log.warning("No records collected - check that the image is a supported Windows memory dump")
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
            )
        except Exception as exc:  # noqa: BLE001
            logging.getLogger(__name__).error("Failed to process %s: %s", image_file, exc, exc_info=args.verbose)
            sys.exit(1)


if __name__ == "__main__":
    main()
