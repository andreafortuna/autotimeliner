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
SUCCESS_LEVEL = 25


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


def _pick_plugin_class(candidates: list[str]) -> Optional[type]:
    """Return the first available plugin class from a list of dotted names."""
    for name in candidates:
        plugin_class = get_plugin_class(name)
        if plugin_class is not None:
            return plugin_class
    return None


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

    log.log(SUCCESS_LEVEL, "Timeliner scan complete: %d records collected", len(records))
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

    log.log(SUCCESS_LEVEL, "MFT scan complete: %d records collected", len(records))
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

    log.log(SUCCESS_LEVEL, "ShellBags scan complete: %d records collected", len(records))
    return records


def collect_psscan(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 PsScan plugin and return normalised records.

    PsScan (windows.psscan.PsScan) scans memory for EPROCESS structures,
    finding both active and terminated/hidden processes with their timestamps.
    """
    try:
        _Plugin = get_plugin_class("windows.psscan.PsScan")
        if _Plugin is None:
            raise ImportError("windows.psscan.PsScan not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.psscan plugin not available — skipping (%s)", exc)
        return []

    log.info("Running psscan plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("psscan"))

    records: list[TimelineRecord] = []
    for row in rows:
        # PsScan columns: PID, PPID, ImageFileName, Offset, Threads, Handles,
        #   SessionId, Wow64, CreateTime, ExitTime
        pid = str(row.get("PID", ""))
        ppid = str(row.get("PPID", ""))
        name = str(row.get("ImageFileName", ""))
        offset = str(row.get("Offset", ""))

        for ts_col, event_type in [("CreateTime", "Process Created"), ("ExitTime", "Process Exited")]:
            ts = _to_utc(row.get(ts_col))
            if ts is None:
                continue
            records.append(TimelineRecord(
                timestamp=ts,
                source="psscan",
                description=f"{event_type}: {name}",
                detail=f"PID={pid} PPID={ppid} Offset={offset}",
            ))

    log.log(SUCCESS_LEVEL, "PsScan complete: %d records collected", len(records))
    return records


def collect_cmdline(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 CmdLine plugin and return normalised records.

    CmdLine (windows.cmdline.CmdLine) extracts command-line arguments for
    each running process — useful for detecting malicious parameters.

    Note: CmdLine does not provide timestamps directly. We pair it with
    process creation times from psscan when available.
    """
    try:
        _Plugin = get_plugin_class("windows.cmdline.CmdLine")
        if _Plugin is None:
            raise ImportError("windows.cmdline.CmdLine not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.cmdline plugin not available — skipping (%s)", exc)
        return []

    log.info("Running cmdline plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("cmdline"))

    # CmdLine doesn't have timestamps, so we return records without timeline value
    # These are useful for enriching other records but are returned with epoch 0
    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        # CmdLine columns: PID, Process, Args
        pid = str(row.get("PID", ""))
        process = str(row.get("Process", ""))
        args = str(row.get("Args", ""))

        if not args or args == "N/A":
            continue

        records.append(TimelineRecord(
            timestamp=epoch_zero,
            source="cmdline",
            description=f"Command Line: {process}",
            detail=f"PID={pid} Args={args}",
        ))

    log.log(SUCCESS_LEVEL, "CmdLine complete: %d records collected", len(records))
    return records


def collect_netscan(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 NetScan plugin and return normalised records.

    NetScan (windows.netscan.NetScan) extracts network connections and
    listening sockets with their creation timestamps — essential for
    detecting C2 communications and lateral movement.
    """
    try:
        _Plugin = get_plugin_class("windows.netscan.NetScan")
        if _Plugin is None:
            raise ImportError("windows.netscan.NetScan not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.netscan plugin not available — skipping (%s)", exc)
        return []

    log.info("Running netscan plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("netscan"))

    records: list[TimelineRecord] = []
    for row in rows:
        # NetScan columns: Offset, Proto, LocalAddr, LocalPort, ForeignAddr,
        #   ForeignPort, State, PID, Owner, Created
        proto = str(row.get("Proto", ""))
        local_addr = str(row.get("LocalAddr", ""))
        local_port = str(row.get("LocalPort", ""))
        foreign_addr = str(row.get("ForeignAddr", ""))
        foreign_port = str(row.get("ForeignPort", ""))
        state = str(row.get("State", ""))
        pid = str(row.get("PID", ""))
        owner = str(row.get("Owner", ""))

        ts = _to_utc(row.get("Created"))
        if ts is None:
            continue

        conn_desc = f"{local_addr}:{local_port} → {foreign_addr}:{foreign_port}"
        records.append(TimelineRecord(
            timestamp=ts,
            source="netscan",
            description=f"Network {proto} {state}: {conn_desc}",
            detail=f"PID={pid} Owner={owner}",
        ))

    log.log(SUCCESS_LEVEL, "NetScan complete: %d records collected", len(records))
    return records


def collect_userassist(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 UserAssist plugin and return normalised records.

    UserAssist (windows.registry.userassist.UserAssist) extracts evidence
    of program execution from the Windows registry, including run counts
    and last execution timestamps.
    """
    try:
        _Plugin = get_plugin_class("windows.registry.userassist.UserAssist")
        if _Plugin is None:
            raise ImportError("windows.registry.userassist.UserAssist not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.registry.userassist plugin not available — skipping (%s)", exc)
        return []

    log.info("Running userassist plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("userassist"))

    records: list[TimelineRecord] = []
    for row in rows:
        # UserAssist columns: Hive Offset, Hive Name, Path, Last Write Time,
        #   Subkey Name, Value Name, ID, Count, Focus, Time, Last Updated
        path = str(row.get("Path", ""))
        value_name = str(row.get("Value Name", ""))
        count = str(row.get("Count", ""))
        focus = str(row.get("Focus", ""))

        ts = _to_utc(row.get("Last Updated") or row.get("Last Write Time"))
        if ts is None:
            continue

        records.append(TimelineRecord(
            timestamp=ts,
            source="userassist",
            description=f"Program Executed: {value_name}",
            detail=f"Path={path} Count={count} Focus={focus}",
        ))

    log.log(SUCCESS_LEVEL, "UserAssist complete: %d records collected", len(records))
    return records


def collect_dlllist(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 DllList plugin and return normalised records.

    DllList (windows.dlllist.DllList) lists DLLs loaded by each process.
    Useful for detecting DLL injection and suspicious library loads.
    
    Note: DllList provides LoadTime for some DLLs.
    """
    try:
        _Plugin = get_plugin_class("windows.dlllist.DllList")
        if _Plugin is None:
            raise ImportError("windows.dlllist.DllList not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.dlllist plugin not available — skipping (%s)", exc)
        return []

    log.info("Running dlllist plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("dlllist"))

    records: list[TimelineRecord] = []
    for row in rows:
        # DllList columns: PID, Process, Base, Size, Name, Path, LoadTime
        pid = str(row.get("PID", ""))
        process = str(row.get("Process", ""))
        dll_name = str(row.get("Name", ""))
        dll_path = str(row.get("Path", ""))
        base = str(row.get("Base", ""))
        size = row.get("Size", 0)

        ts = _to_utc(row.get("LoadTime"))
        if ts is None:
            continue

        records.append(TimelineRecord(
            timestamp=ts,
            source="dlllist",
            description=f"DLL Loaded: {dll_name}",
            detail=f"Process={process} PID={pid} Path={dll_path} Base={base}",
            size=int(size) if size else 0,
        ))

    log.log(SUCCESS_LEVEL, "DllList complete: %d records collected", len(records))
    return records


def collect_svcscan(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 SvcScan plugin and return normalised records.

    SvcScan (windows.svcscan.SvcScan) extracts Windows services information.
    Useful for detecting malicious services used for persistence.
    
    Note: Services typically don't have individual timestamps in memory,
    but the presence of unusual services is forensically relevant.
    """
    try:
        _Plugin = get_plugin_class("windows.svcscan.SvcScan")
        if _Plugin is None:
            raise ImportError("windows.svcscan.SvcScan not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.svcscan plugin not available — skipping (%s)", exc)
        return []

    log.info("Running svcscan plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("svcscan"))

    # Services don't have timestamps, return with epoch 0 for reference
    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        # SvcScan columns: Offset, Order, PID, Start, State, Type, Name, Display, Binary
        name = str(row.get("Name", ""))
        display = str(row.get("Display", ""))
        binary = str(row.get("Binary", ""))
        state = str(row.get("State", ""))
        start = str(row.get("Start", ""))
        pid = str(row.get("PID", ""))
        svc_type = str(row.get("Type", ""))

        records.append(TimelineRecord(
            timestamp=epoch_zero,
            source="svcscan",
            description=f"Service: {name} ({display})",
            detail=f"State={state} Start={start} PID={pid} Type={svc_type} Binary={binary}",
        ))

    log.log(SUCCESS_LEVEL, "SvcScan complete: %d records collected", len(records))
    return records


def collect_filescan(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 FileScan plugin and return normalised records.

    FileScan (windows.filescan.FileScan) scans memory for FILE_OBJECT structures,
    revealing files that were open at the time of memory acquisition.
    
    Note: FileScan doesn't provide timestamps, but file presence is valuable.
    """
    try:
        _Plugin = get_plugin_class("windows.filescan.FileScan")
        if _Plugin is None:
            raise ImportError("windows.filescan.FileScan not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.filescan plugin not available — skipping (%s)", exc)
        return []

    log.info("Running filescan plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("filescan"))

    # FileScan doesn't have timestamps
    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        # FileScan columns: Offset, Name (file path)
        offset = str(row.get("Offset", ""))
        name = str(row.get("Name", ""))

        if not name:
            continue

        records.append(TimelineRecord(
            timestamp=epoch_zero,
            source="filescan",
            description=f"Open File: {name}",
            detail=f"Offset={offset}",
        ))

    log.log(SUCCESS_LEVEL, "FileScan complete: %d records collected", len(records))
    return records


def collect_malfind(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 Malfind plugin and return normalised records.

    Malfind (windows.malfind.Malfind) detects injected code and suspicious
    memory regions — critical for malware detection.
    
    Note: Malfind doesn't provide timestamps, but findings are high-priority.
    """
    try:
        _Plugin = get_plugin_class("windows.malfind.Malfind")
        if _Plugin is None:
            raise ImportError("windows.malfind.Malfind not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.malfind plugin not available — skipping (%s)", exc)
        return []

    log.info("Running malfind plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("malfind"))

    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        # Malfind columns: PID, Process, Start VPN, End VPN, Tag, Protection, CommitCharge, etc.
        pid = str(row.get("PID", ""))
        process = str(row.get("Process", ""))
        start_vpn = str(row.get("Start VPN", ""))
        end_vpn = str(row.get("End VPN", ""))
        protection = str(row.get("Protection", ""))
        tag = str(row.get("Tag", ""))

        records.append(TimelineRecord(
            timestamp=epoch_zero,
            source="malfind",
            description=f"⚠️ Suspicious Memory: {process}",
            detail=f"PID={pid} VPN={start_vpn}-{end_vpn} Protection={protection} Tag={tag}",
        ))

    log.log(SUCCESS_LEVEL, "Malfind complete: %d records collected", len(records))
    return records


def collect_handles(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 Handles plugin and return normalised records.

    Handles (windows.handles.Handles) lists open handles for processes,
    including files, registry keys, mutexes, etc.
    
    Note: Handles don't have timestamps, but are useful for context.
    """
    try:
        _Plugin = get_plugin_class("windows.handles.Handles")
        if _Plugin is None:
            raise ImportError("windows.handles.Handles not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.handles plugin not available — skipping (%s)", exc)
        return []

    log.info("Running handles plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("handles"))

    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        # Handles columns: PID, Process, Offset, HandleValue, Type, GrantedAccess, Name
        pid = str(row.get("PID", ""))
        process = str(row.get("Process", ""))
        handle_type = str(row.get("Type", ""))
        name = str(row.get("Name", ""))
        granted_access = str(row.get("GrantedAccess", ""))

        if not name or name == "N/A":
            continue

        records.append(TimelineRecord(
            timestamp=epoch_zero,
            source="handles",
            description=f"Handle ({handle_type}): {name}",
            detail=f"Process={process} PID={pid} Access={granted_access}",
        ))

    log.log(SUCCESS_LEVEL, "Handles complete: %d records collected", len(records))
    return records


def collect_envars(image_path: str | Path) -> list[TimelineRecord]:
    """Run the Vol3 Envars plugin and return normalised records.

    Envars (windows.envars.Envars) extracts environment variables for processes.
    Useful for detecting suspicious PATH modifications or malware configuration.
    
    Note: No timestamps available.
    """
    try:
        _Plugin = get_plugin_class("windows.envars.Envars")
        if _Plugin is None:
            raise ImportError("windows.envars.Envars not in plugin registry")
    except (ImportError, Exception) as exc:
        log.warning("windows.envars plugin not available — skipping (%s)", exc)
        return []

    log.info("Running envars plugin…")
    rows = run_plugin(image_path, _Plugin, progress_callback=_progress("envars"))

    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        # Envars columns: PID, Process, Block, Variable, Value
        pid = str(row.get("PID", ""))
        process = str(row.get("Process", ""))
        variable = str(row.get("Variable", ""))
        value = str(row.get("Value", ""))

        # Only capture interesting environment variables
        interesting_vars = {"PATH", "TEMP", "TMP", "APPDATA", "LOCALAPPDATA", 
                           "USERPROFILE", "COMSPEC", "SYSTEMROOT"}
        if variable.upper() not in interesting_vars:
            continue

        records.append(TimelineRecord(
            timestamp=epoch_zero,
            source="envars",
            description=f"Environment: {variable}",
            detail=f"Process={process} PID={pid} Value={value[:200]}",  # Truncate long values
        ))

    log.log(SUCCESS_LEVEL, "Envars complete: %d records collected", len(records))
    return records


def collect_linux_pslist(image_path: str | Path) -> list[TimelineRecord]:
    """Run a Linux PsList-equivalent plugin and normalize process records."""
    candidates = [
        "linux.pslist.PsList",
        "linux.pslist.Pslist",
    ]
    plugin_class = _pick_plugin_class(candidates)
    if plugin_class is None:
        log.warning("Linux pslist plugin not available - skipping")
        return []

    log.info("Running Linux pslist plugin...")
    rows = run_plugin(image_path, plugin_class, progress_callback=_progress("linux.pslist"))

    records: list[TimelineRecord] = []
    for row in rows:
        pid = str(row.get("PID", ""))
        ppid = str(row.get("PPID", ""))
        name = str(row.get("COMM") or row.get("Name") or row.get("Process") or "")

        for ts_col, event_type in [
            ("Start Time", "Process Started"),
            ("Create Time", "Process Started"),
            ("Exit Time", "Process Exited"),
        ]:
            ts = _to_utc(row.get(ts_col))
            if ts is None:
                continue
            records.append(TimelineRecord(
                timestamp=ts,
                source="linux.pslist",
                description=f"{event_type}: {name}",
                detail=f"PID={pid} PPID={ppid}",
            ))

    log.log(SUCCESS_LEVEL, "Linux PsList complete: %d records collected", len(records))
    return records


def collect_linux_bash(image_path: str | Path) -> list[TimelineRecord]:
    """Run Linux bash history plugin and normalize command history events."""
    plugin_class = _pick_plugin_class(["linux.bash.Bash"])
    if plugin_class is None:
        log.warning("Linux bash plugin not available - skipping")
        return []

    log.info("Running Linux bash plugin...")
    rows = run_plugin(image_path, plugin_class, progress_callback=_progress("linux.bash"))

    # For rows without timestamp we keep epoch 0 to retain useful context.
    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        command = str(row.get("Command") or row.get("Cmd") or row.get("History") or "")
        task = str(row.get("Task") or row.get("Process") or "")
        pid = str(row.get("PID", ""))

        if not command:
            continue

        ts = _to_utc(
            row.get("Command Time")
            or row.get("Time")
            or row.get("Timestamp")
            or row.get("History Time")
        )
        records.append(TimelineRecord(
            timestamp=ts or epoch_zero,
            source="linux.bash",
            description="Shell Command Executed",
            detail=f"PID={pid} Task={task} Command={command}",
        ))

    log.log(SUCCESS_LEVEL, "Linux bash complete: %d records collected", len(records))
    return records


def collect_linux_lsof(image_path: str | Path) -> list[TimelineRecord]:
    """Run Linux Lsof plugin and normalize open-file evidence."""
    plugin_class = _pick_plugin_class(["linux.lsof.Lsof"])
    if plugin_class is None:
        log.warning("Linux lsof plugin not available - skipping")
        return []

    log.info("Running Linux lsof plugin...")
    rows = run_plugin(image_path, plugin_class, progress_callback=_progress("linux.lsof"))

    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        pid = str(row.get("PID", ""))
        process = str(row.get("Process") or row.get("Task") or "")
        fd = str(row.get("FD", ""))
        path = str(row.get("Path") or row.get("Name") or "")

        if not path:
            continue

        records.append(TimelineRecord(
            timestamp=epoch_zero,
            source="linux.lsof",
            description=f"Open File: {path}",
            detail=f"Process={process} PID={pid} FD={fd}",
        ))

    log.log(SUCCESS_LEVEL, "Linux Lsof complete: %d records collected", len(records))
    return records


def collect_mac_pslist(image_path: str | Path) -> list[TimelineRecord]:
    """Run a macOS PsList-equivalent plugin and normalize process events."""
    candidates = [
        "mac.pslist.PsList",
        "mac.pslist.Pslist",
    ]
    plugin_class = _pick_plugin_class(candidates)
    if plugin_class is None:
        log.warning("macOS pslist plugin not available - skipping")
        return []

    log.info("Running macOS pslist plugin...")
    rows = run_plugin(image_path, plugin_class, progress_callback=_progress("mac.pslist"))

    records: list[TimelineRecord] = []
    for row in rows:
        pid = str(row.get("PID", ""))
        ppid = str(row.get("PPID", ""))
        name = str(row.get("COMM") or row.get("Name") or row.get("Process") or "")

        for ts_col, event_type in [
            ("Start Time", "Process Started"),
            ("Create Time", "Process Started"),
            ("Exit Time", "Process Exited"),
        ]:
            ts = _to_utc(row.get(ts_col))
            if ts is None:
                continue
            records.append(TimelineRecord(
                timestamp=ts,
                source="mac.pslist",
                description=f"{event_type}: {name}",
                detail=f"PID={pid} PPID={ppid}",
            ))

    log.log(SUCCESS_LEVEL, "macOS PsList complete: %d records collected", len(records))
    return records


def collect_mac_bash(image_path: str | Path) -> list[TimelineRecord]:
    """Run macOS bash history plugin and normalize command history events."""
    plugin_class = _pick_plugin_class(["mac.bash.Bash"])
    if plugin_class is None:
        log.warning("macOS bash plugin not available - skipping")
        return []

    log.info("Running macOS bash plugin...")
    rows = run_plugin(image_path, plugin_class, progress_callback=_progress("mac.bash"))

    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        command = str(row.get("Command") or row.get("Cmd") or row.get("History") or "")
        process = str(row.get("Process") or row.get("Task") or "")
        pid = str(row.get("PID", ""))

        if not command:
            continue

        ts = _to_utc(
            row.get("Command Time")
            or row.get("Time")
            or row.get("Timestamp")
            or row.get("History Time")
        )
        records.append(TimelineRecord(
            timestamp=ts or epoch_zero,
            source="mac.bash",
            description="Shell Command Executed",
            detail=f"PID={pid} Process={process} Command={command}",
        ))

    log.log(SUCCESS_LEVEL, "macOS bash complete: %d records collected", len(records))
    return records


def collect_mac_lsof(image_path: str | Path) -> list[TimelineRecord]:
    """Run macOS Lsof plugin and normalize open-file evidence."""
    plugin_class = _pick_plugin_class(["mac.lsof.Lsof"])
    if plugin_class is None:
        log.warning("macOS lsof plugin not available - skipping")
        return []

    log.info("Running macOS lsof plugin...")
    rows = run_plugin(image_path, plugin_class, progress_callback=_progress("mac.lsof"))

    records: list[TimelineRecord] = []
    epoch_zero = datetime(1970, 1, 1, tzinfo=timezone.utc)

    for row in rows:
        pid = str(row.get("PID", ""))
        process = str(row.get("Process") or row.get("Task") or "")
        fd = str(row.get("FD", ""))
        path = str(row.get("Path") or row.get("Name") or "")

        if not path:
            continue

        records.append(TimelineRecord(
            timestamp=epoch_zero,
            source="mac.lsof",
            description=f"Open File: {path}",
            detail=f"Process={process} PID={pid} FD={fd}",
        ))

    log.log(SUCCESS_LEVEL, "macOS Lsof complete: %d records collected", len(records))
    return records


# ---------------------------------------------------------------------------
# Main facade
# ---------------------------------------------------------------------------

def create_timeline(
    image_path: str | Path,
    os_family: str = "windows",
    run_timeliner: bool = True,
    run_mftscan: bool = True,
    run_shellbags: bool = True,
    run_psscan: bool = True,
    run_cmdline: bool = True,
    run_netscan: bool = True,
    run_userassist: bool = True,
    run_dlllist: bool = False,      # Disabled by default (can be slow)
    run_svcscan: bool = True,
    run_filescan: bool = False,     # Disabled by default (generates many records)
    run_malfind: bool = True,
    run_handles: bool = False,      # Disabled by default (generates many records)
    run_envars: bool = False,       # Disabled by default (generates many records)
    run_linux_pslist: bool = True,
    run_linux_bash: bool = True,
    run_linux_lsof: bool = True,
    run_mac_pslist: bool = True,
    run_mac_bash: bool = True,
    run_mac_lsof: bool = True,
) -> list[TimelineRecord]:
    """Collect and merge timeline records from all selected plugins.

    Returns records sorted by timestamp (ascending).
    """
    records: list[TimelineRecord] = []
    family = (os_family or "unknown").lower()

    plan: list[tuple[str, Callable[[str | Path], list[TimelineRecord]]]] = []

    if run_timeliner:
        plan.append(("Timeliner", collect_timeliner))

    if family == "windows":
        windows_plan = [
            ("MFT Scanning", run_mftscan, collect_mftscan),
            ("ShellBags Scanning", run_shellbags, collect_shellbags),
            ("Process Scanning (PsScan)", run_psscan, collect_psscan),
            ("Command Line Extraction", run_cmdline, collect_cmdline),
            ("Network Scanning", run_netscan, collect_netscan),
            ("UserAssist Registry", run_userassist, collect_userassist),
            ("DLL List", run_dlllist, collect_dlllist),
            ("Service Scanning", run_svcscan, collect_svcscan),
            ("File Scanning", run_filescan, collect_filescan),
            ("Malware Detection (Malfind)", run_malfind, collect_malfind),
            ("Handle Scanning", run_handles, collect_handles),
            ("Environment Variables", run_envars, collect_envars),
        ]
        plan.extend((label, collector) for label, enabled, collector in windows_plan if enabled)
    elif family == "linux":
        linux_plan = [
            ("Linux Process Scanning (PsList)", run_linux_pslist, collect_linux_pslist),
            ("Linux Shell History", run_linux_bash, collect_linux_bash),
            ("Linux Open Files", run_linux_lsof, collect_linux_lsof),
        ]
        plan.extend((label, collector) for label, enabled, collector in linux_plan if enabled)
    elif family in {"mac", "macos", "darwin"}:
        mac_plan = [
            ("macOS Process Scanning (PsList)", run_mac_pslist, collect_mac_pslist),
            ("macOS Shell History", run_mac_bash, collect_mac_bash),
            ("macOS Open Files", run_mac_lsof, collect_mac_lsof),
        ]
        plan.extend((label, collector) for label, enabled, collector in mac_plan if enabled)
    else:
        log.warning("Unknown memory image family '%s': running only generic plugins", family)

    total_phases = len(plan)
    if total_phases == 0:
        log.warning("No plugins selected for timeline extraction")
        return records

    log.info("=" * 70)
    log.info("Starting comprehensive timeline scan (%d plugins enabled)", total_phases)
    log.info("=" * 70)

    scan_phases: list[str] = []
    for phase, (label, collector) in enumerate(plan, start=1):
        log.info("Phase %d/%d: %s", phase, total_phases, label)
        phase_records = collector(image_path)
        records.extend(phase_records)
        scan_phases.append(f"{label}: {len(phase_records)} records")

    records.sort(key=lambda r: r.timestamp)

    log.info("=" * 70)
    log.info("Scan Summary:")
    for phase_summary in scan_phases:
        log.info("  - %s", phase_summary)
    log.log(SUCCESS_LEVEL, "Total timeline records: %d", len(records))
    log.info("=" * 70)
    return records
