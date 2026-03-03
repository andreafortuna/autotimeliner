"""
timeliner.py
~~~~~~~~~~~~
Runs Volatility3 plugins that contribute to the forensic timeline and returns
normalised records ready for the exporter.

Volatility2 → Volatility3 plugin mapping
-----------------------------------------
timeliner      → volatility3.plugins.timeliner.Timeliner
mftparser      → volatility3.plugins.windows.mftscan.MFTScan
shellbags      → volatility3.plugins.windows.shellbags.ShellBags

Each `collect_*` function returns a list of TimelineRecord namedtuples with
the fields expected by exporter.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .vol3_runner import run_plugin, get_plugin_class

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TimelineRecord:
    """A single forensic event with its associated UTC timestamp."""

    timestamp: datetime          # always UTC
    source: str                  # e.g. "timeliner", "mftscan", "shellbags"
    description: str             # human-readable description of the event
    detail: str = ""             # optional extra detail (file path, size, …)
    inode: str = "0"
    uid: str = "0"
    gid: str = "0"
    size: int = 0
    mode: str = "----------"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_utc(value: Any) -> Optional[datetime]:
    """Convert a Vol3 timestamp value (renderers.Datetime or similar) to a
    timezone-aware UTC datetime, or *None* if the value is invalid / None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    # Vol3 sometimes returns integer/float epoch seconds
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def _progress(label: str) -> Callable[[float, str], None]:
    """Return a simple progress callback that logs at DEBUG level."""
    def _cb(pct: float, msg: str) -> None:
        log.debug("[%s] %.0f%% — %s", label, pct, msg)
    return _cb


# ---------------------------------------------------------------------------
# Plugin collectors
# ---------------------------------------------------------------------------

def collect_timeliner(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 Timeliner plugin and return normalised records.

    The Timeliner plugin already aggregates timestamps from many sub-plugins
    (pslist, cmdline, registry, …) — it is the closest equivalent to the
    old `volatility2 timeliner --output=body`.
    """
    try:
        _Plugin = get_plugin_class("timeliner.Timeliner")
        if _Plugin is None:
            raise ImportError("timeliner.Timeliner not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("timeliner plugin not available — skipping (%s)", exc)
        return []

    log.info("Running timeliner plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("timeliner"))

    records: list[TimelineRecord] = []
    for row in rows:
        # Timeliner columns: Plugin, Description, Created Date, Modified Date,
        #                     Accessed Date, Changed Date  (not all always present)
        plugin_name = str(row.get("Plugin", "timeliner"))
        description = str(row.get("Description", ""))

        for ts_col in ("Created Date", "Modified Date", "Accessed Date", "Changed Date"):
            ts = _to_utc(row.get(ts_col))
            if ts is None:
                continue
            records.append(TimelineRecord(
                timestamp=ts,
                source=f"timeliner/{plugin_name}",
                description=description,
                detail=f"{ts_col}: {ts.isoformat()}",
            ))

    log.info("timeliner: %d records collected", len(records))
    return records


def collect_mftscan(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 MFTScan plugin and return normalised records.

    MFTScan (windows.mftscan.MFTScan) scans memory for MFT FILE objects and
    exposes creation/modification/access/entry timestamps — equivalent to the
    old `mftparser --output=body`.
    """
    try:
        _Plugin = get_plugin_class("windows.mftscan.MFTScan")
        if _Plugin is None:
            raise ImportError("windows.mftscan.MFTScan not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.mftscan plugin not available — skipping (%s)", exc)
        return []

    log.info("Running mftscan plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("mftscan"))

    records: list[TimelineRecord] = []
    for row in rows:
        # MFTScan columns include: Inode, Type, in-use, Filename,
        #   Created Date, Modified Date, Accessed Date, Changed Date, Size
        filename = str(row.get("Filename", ""))
        inode = str(row.get("Inode", "0"))
        size = int(row.get("Size", 0) or 0)
        ftype = str(row.get("Type", ""))

        for ts_col in ("Created Date", "Modified Date", "Accessed Date", "Changed Date"):
            ts = _to_utc(row.get(ts_col))
            if ts is None:
                continue
            records.append(TimelineRecord(
                timestamp=ts,
                source="mftscan",
                description=filename,
                detail=f"{ts_col} | type={ftype}",
                inode=inode,
                size=size,
            ))

    log.info("mftscan: %d records collected", len(records))
    return records


def collect_shellbags(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 ShellBags plugin and return normalised records.

    ShellBags (windows.shellbags.ShellBags) parses user registry hives for
    folder-access timestamps — equivalent to the old `shellbags --output=body`.
    """
    try:
        _Plugin = get_plugin_class("windows.shellbags.ShellBags")
        if _Plugin is None:
            raise ImportError("windows.shellbags.ShellBags not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.shellbags plugin not available — skipping (%s)", exc)
        return []

    log.info("Running shellbags plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("shellbags"))

    records: list[TimelineRecord] = []
    for row in rows:
        # ShellBags columns: Last Write Time, Hive Offset, User, Item Type,
        #                     Last Accessed, Modified Date, Shell Type, Path
        path = str(row.get("Path", ""))
        user = str(row.get("User", ""))

        for ts_col in ("Last Write Time", "Last Accessed", "Modified Date"):
            ts = _to_utc(row.get(ts_col))
            if ts is None:
                continue
            records.append(TimelineRecord(
                timestamp=ts,
                source="shellbags",
                description=path,
                detail=f"user={user} | {ts_col}",
            ))

    log.info("shellbags: %d records collected", len(records))
    return records


# ---------------------------------------------------------------------------
# Main facade
# ---------------------------------------------------------------------------

def create_timeline(
    image_path: str | Path,
    run_timeliner: bool = True,
    run_mftscan: bool = True,
    run_shellbags: bool = True,
) -> list[TimelineRecord]:
    """Collect and merge timeline records from all selected plugins.

    Returns records sorted by timestamp (ascending).
    """
    records: list[TimelineRecord] = []

    if run_timeliner:
        records.extend(collect_timeliner(image_path))
    if run_mftscan:
        records.extend(collect_mftscan(image_path))
    if run_shellbags:
        records.extend(collect_shellbags(image_path))

    records.sort(key=lambda r: r.timestamp)
    log.info("Total timeline records: %d", len(records))
    return records
