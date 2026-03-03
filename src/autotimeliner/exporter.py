"""
exporter.py
~~~~~~~~~~~
Merge, filter, and export timeline records to CSV.

Two modes are supported:
  1. Pure-Python  (default): filter by timeframe in Python, write CSV with
     the ``csv`` stdlib module — no external tools required.
  2. Legacy mactime (--use-mactime): write intermediate body files and call
     the ``mactime`` binary from SleuthKit via subprocess (opt-in only).
"""

from __future__ import annotations

import csv
import logging
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .timeliner import TimelineRecord

log = logging.getLogger(__name__)

# Body-file field order used for mactime interop
_BODY_HEADER = ["MD5", "name", "inode", "mode_as_string", "UID", "GID",
                 "size", "atime", "mtime", "ctime", "crtime"]

# CSV output columns (human-friendly)
CSV_COLUMNS = ["Timestamp (UTC)", "Source", "Description", "Detail",
               "Inode", "UID", "GID", "Size", "Mode"]


# ---------------------------------------------------------------------------
# Timeframe parsing
# ---------------------------------------------------------------------------

def parse_timeframe(timeframe: str) -> tuple[datetime, datetime]:
    """Parse a ``YYYY-MM-DD..YYYY-MM-DD`` timeframe string.

    Returns a (start, end) pair of timezone-aware UTC datetimes where *end*
    is the last second of the given day (23:59:59 UTC).

    Raises ValueError if the format is invalid.
    """
    try:
        start_str, end_str = timeframe.split("..")
        start = datetime.strptime(start_str.strip(), "%Y-%m-%d").replace(
            hour=0, minute=0, second=0, tzinfo=timezone.utc
        )
        end = datetime.strptime(end_str.strip(), "%Y-%m-%d").replace(
            hour=23, minute=59, second=59, tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid timeframe '{timeframe}'. Expected format: YYYY-MM-DD..YYYY-MM-DD"
        ) from exc
    if end < start:
        raise ValueError("Timeframe end date must be >= start date.")
    return start, end


# ---------------------------------------------------------------------------
# Pure-Python export
# ---------------------------------------------------------------------------

def export_csv(
    records: list[TimelineRecord],
    output_path: str | Path,
    timeframe: Optional[str] = None,
) -> Path:
    """Write *records* to a CSV file at *output_path*.

    Parameters
    ----------
    records:
        Sorted list of TimelineRecord instances (from timeliner.create_timeline).
    output_path:
        Destination CSV path (will be overwritten if it exists).
    timeframe:
        Optional ``YYYY-MM-DD..YYYY-MM-DD`` string. When supplied, only records
        whose timestamp falls within the range are written.

    Returns
    -------
    The resolved output Path.
    """
    output_path = Path(output_path).resolve()

    start: Optional[datetime] = None
    end: Optional[datetime] = None
    if timeframe:
        start, end = parse_timeframe(timeframe)
        log.info("Filtering to timeframe %s → %s", start.date(), end.date())

    filtered = []
    for rec in records:
        if start is not None and rec.timestamp < start:
            continue
        if end is not None and rec.timestamp > end:
            continue
        filtered.append(rec)

    log.info("Writing %d records to %s", len(filtered), output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_COLUMNS)
        for rec in filtered:
            writer.writerow([
                rec.timestamp.isoformat(),
                rec.source,
                rec.description,
                rec.detail,
                rec.inode,
                rec.uid,
                rec.gid,
                rec.size,
                rec.mode,
            ])

    return output_path


# ---------------------------------------------------------------------------
# Legacy mactime export (opt-in)
# ---------------------------------------------------------------------------

def _record_to_body_line(rec: TimelineRecord) -> str:
    """Convert a TimelineRecord to a Sleuth Kit body-file line.

    Body format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
    We use the event timestamp for every time column (conservative approach).
    """
    ts_epoch = int(rec.timestamp.timestamp())
    return "|".join([
        "0",             # MD5 (unknown)
        rec.description.replace("|", "_"),
        rec.inode,
        rec.mode,
        rec.uid,
        rec.gid,
        str(rec.size),
        str(ts_epoch),   # atime
        str(ts_epoch),   # mtime
        str(ts_epoch),   # ctime
        str(ts_epoch),   # crtime
    ])


def export_mactime(
    records: list[TimelineRecord],
    output_path: str | Path,
    timeframe: Optional[str] = None,
) -> Path:
    """Write timeline using the external ``mactime`` binary (legacy mode).

    Creates a temporary body file from *records*, then calls::

        mactime -d -b <bodyfile> [timeframe] > <output_path>

    Requires ``mactime`` from SleuthKit to be on PATH.
    """
    output_path = Path(output_path).resolve()

    mactime_bin = _find_mactime()
    if mactime_bin is None:
        raise RuntimeError(
            "mactime binary not found. Install SleuthKit or use pure-Python mode."
        )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".body", delete=False, encoding="utf-8"
    ) as tmp:
        body_path = Path(tmp.name)
        for rec in records:
            tmp.write(_record_to_body_line(rec) + "\n")

    log.info("Body file written to %s (%d lines)", body_path, len(records))

    cmd = [mactime_bin, "-d", "-b", str(body_path)]
    if timeframe:
        # mactime accepts dates as YYYY-MM-DD..YYYY-MM-DD directly
        cmd.append(timeframe)

    log.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"mactime failed (exit {exc.returncode}):\n{exc.stderr}"
        ) from exc
    finally:
        body_path.unlink(missing_ok=True)

    with output_path.open("w", encoding="utf-8") as fh:
        fh.write(result.stdout)

    log.info("mactime output written to %s", output_path)
    return output_path


def _find_mactime() -> Optional[str]:
    """Return the path of the ``mactime`` binary, or None if not found."""
    import shutil
    return shutil.which("mactime")
