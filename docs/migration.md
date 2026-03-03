# Migrating from v1 (Volatility2)

This document covers the differences between AutoTimeliner v1 (Volatility2-based)
and v2 (Volatility3-based) and how to update your workflows.

---

## What Changed

### Volatility2 → Volatility3 plugin mapping

| v1 (Volatility2) | v2 (Volatility3) | Notes |
|---|---|---|
| `imageinfo` (profile detection) | Replaced by Vol3 probe | AutoTimeliner performs best-effort OS/profile probing via Volatility3 plugins |
| `timeliner --output=body` | `timeliner.Timeliner` | Same concept, TreeGrid output |
| `mftparser --output=body` | `windows.mftscan.MFTScan` | Scans memory for in-memory MFT FILE objects |
| `shellbags --output=body` | `windows.shellbags.ShellBags` | Same registry data, new API |

### Removed concepts

| v1 concept | v2 behaviour |
|---|---|
| `--profile` / `-p` | **Deprecated and ignored.** Volatility3 uses automagic OS/layer detection. Passing `-p` produces a deprecation warning but does not fail. |
| Manual symbol table setup | **Removed.** AutoTimeliner downloads and installs Volatility3 Windows/macOS/Linux symbol packs automatically. |
| Body files written to disk | **Removed.** Data flows internally through Python — no `.body` intermediate files are created (unless `--use-mactime` is used). |
| `which volatility` binary detection | **Removed.** Volatility3 is imported as a Python library; no shell binary is needed. |
| `mactime` required | **Optional.** Pure-Python merge and filter is the default. Pass `--use-mactime` to restore the old body-file behaviour if needed. |

### New features

| Feature | Flag |
|---|---|
| Explicit output path | `-o` / `--output` |
| Skip individual plugins | `--skip-timeliner`, `--skip-mftscan`, `--skip-shellbags` |
| Verbose debug logging | `-v` / `--verbose` |
| Version string | `--version` |

---

## Workflow Comparison

### v1 (Volatility2)

```bash
./autotimeline.py -f memory.raw -t 2023-10-17..2023-10-21
# Internally:
#   1. os.popen("volatility -f memory.raw imageinfo …")  → profile
#   2. os.popen("volatility -f memory.raw --profile=… timeliner …")
#   3. os.popen("volatility -f memory.raw --profile=… mftparser …")
#   4. os.popen("volatility -f memory.raw --profile=… shellbags …")
#   5. Merge .body files on disk
#   6. os.popen("mactime -d -b combined.body 2023-10-17..2023-10-21")
```

### v2 (Volatility3)

```bash
autotimeliner -f memory.raw -t 2023-10-17..2023-10-21
# Internally:
#   1. volatility3 Python API — automatic symbol table setup + OS/profile probe
#   2. volatility3.plugins.timeliner.Timeliner    → rows in memory
#   3. volatility3.plugins.windows.mftscan.MFTScan → rows in memory
#   4. volatility3.plugins.windows.shellbags.ShellBags → rows in memory
#   5. Python sort + timeframe filter
#   6. csv.writer → timeline.csv  (no mactime, no temp files)
```

---

## Output Format Changes

v1 produced a **mactime CSV** (Date, Size, Type, Mode, UID, GID, Meta, File Name).

v2 produces a richer CSV with explicit columns:

```
Timestamp (UTC), Source, Description, Detail, Inode, UID, GID, Size, Mode
```

The `Source` column tells you which plugin produced each record, making it
easier to filter or pivot in tools like Excel or pandas.

---

## Reverting to Legacy mactime Output

If you rely on the exact `mactime` CSV format (e.g. for ingestion into another
tool that expects that schema), you can use the `--use-mactime` flag:

```bash
autotimeliner -f memory.raw --use-mactime -t 2023-10-17..2023-10-21
```

This writes a temporary body file and calls `mactime`, producing output
identical to v1. Requires SleuthKit's `mactime` to be on your `PATH`.
