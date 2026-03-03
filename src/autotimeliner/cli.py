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
from glob import glob
from pathlib import Path
from typing import Optional

from autotimeliner import __version__
from autotimeliner.timeliner import create_timeline
from autotimeliner.exporter import export_csv, export_mactime

BANNER = r"""
            _     _______ _                _ _
 /\        | |   |__   __(_)              | (_)
/  \  _   _| |_ ___ | |   _ _ __ ___   ___| |_ _ __   ___ _ __
/ /\ \| | | | __/ _ \| |  | | '_ ` _ \ / _ \ | | '_ \ / _ \ '__|
/ ____ \ |_| | || (_) | |  | | | | | | |  __/ | | | | |  __/ |
/_/    \_\__,_|\__\___/|_|  |_|_| |_| |_|\___|_|_|_| |_|\___|_|

  Automagically extract forensic timeline from volatile memory dump
  Version {version}  —  Andrea Fortuna <andrea@andreafortuna.org>
"""


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )


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

    print(_bold(f"\n*** Processing image: {image_path}"))
    print("    " + "-" * 50)

    print(_bold("*** Collecting timeline data from Volatility3 plugins…"))
    records = create_timeline(
        image_path=image_path,
        run_timeliner=not skip_timeliner,
        run_mftscan=not skip_mftscan,
        run_shellbags=not skip_shellbags,
    )

    if not records:
        print(_bold("*** WARNING: No records collected — check that the image is a supported Windows memory dump."))
        return

    print(_bold(f"*** {len(records)} records collected. Writing output…"))

    if use_mactime:
        print(_bold("*** Legacy mode: using external mactime binary…"))
        result = export_mactime(records, out_path, timeframe)
    else:
        result = export_csv(records, out_path, timeframe)

    print(_bold(f"*** Timeline saved to: {result}"))


def main() -> None:
    import argparse

    print(BANNER.format(version=__version__))

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
            "Volatility3 detects the OS automatically."
        )

    image_files = glob(args.imagefile)
    if not image_files:
        print(f"[ERROR] No files matched: {args.imagefile}", file=sys.stderr)
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
