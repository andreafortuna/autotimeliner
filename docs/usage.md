# Usage Guide

## Installation

### With Poetry (recommended)

```bash
git clone https://github.com/andreafortuna/autotimeliner.git
cd autotimeliner
poetry install
```

The `autotimeliner` command will be available inside the Poetry virtualenv:

```bash
poetry run autotimeliner --help
```

### With pip

```bash
pip install .
autotimeliner --help
```

---

## CLI Reference

At startup, AutoTimeliner automatically downloads/installs Volatility3 symbol
tables (Windows/macOS/Linux) and performs a best-effort memory OS/profile probe.
Schema validation is enabled via `jsonschema` (included in project dependencies).

```
autotimeliner -f IMAGEFILE [-t TIMEFRAME] [-o OUTPUT] [options]
```

### Required

| Flag | Description |
|---|---|
| `-f`, `--imagefile` | Path to the memory image, or a glob pattern (quote it: `'*.raw'`) |

### Optional

| Flag | Description |
|---|---|
| `-t`, `--timeframe` | Restrict output to `YYYY-MM-DD..YYYY-MM-DD` |
| `-o`, `--output` | CSV output path (default: `<imagefile>-timeline.csv`) |

#### Core Plugins (enabled by default)

| Flag | Description |
|---|---|
| `--skip-timeliner` | Do not run the timeliner plugin |
| `--skip-mftscan` | Do not run the mftscan plugin |
| `--skip-shellbags` | Do not run the shellbags plugin |
| `--skip-psscan` | Do not run process scanning |
| `--skip-cmdline` | Do not extract command-line arguments |
| `--skip-netscan` | Do not scan network connections |
| `--skip-userassist` | Do not extract program execution evidence |
| `--skip-svcscan` | Do not scan Windows services |
| `--skip-malfind` | Do not run malware/injection detection |

#### Extended Plugins (disabled by default - opt-in)

| Flag | Description |
|---|---|
| `--with-dlllist` | Enable DLL analysis (can be slow) |
| `--with-filescan` | Enable open files scanning (generates many records) |
| `--with-handles` | Enable handle scanning (generates many records) |
| `--with-envars` | Enable environment variables extraction |

#### Other Options

| Flag | Description |
|---|---|
| `--use-mactime` | Legacy mode: write body files and call `mactime` (requires SleuthKit) |
| `-v`, `--verbose` | Show debug-level output |
| `--version` | Print version string and exit |

---

## Examples

### Full timeline (all plugins)

```bash
autotimeliner -f /evidence/memory.raw
# → /evidence/memory.raw-timeline.csv
```

### Filtered by time window

```bash
autotimeliner -f /evidence/memory.raw -t 2023-10-17..2023-10-21
```

### Custom output path

```bash
autotimeliner -f /evidence/memory.raw -o /results/memory-timeline.csv
```

### Process multiple images with a glob

```bash
autotimeliner -f '/evidence/*.raw' -t 2023-10-01..2023-10-31
```

### Only MFT and timeliner (skip shellbags)

```bash
autotimeliner -f /evidence/memory.raw --skip-shellbags
```

### Full forensic scan (all plugins)

```bash
autotimeliner -f /evidence/memory.raw --with-dlllist --with-filescan --with-handles --with-envars
```

### Quick malware-focused scan

Run only process, network, and malware detection plugins:

```bash
autotimeliner -f /evidence/memory.raw --skip-timeliner --skip-mftscan --skip-shellbags
```

### Network-focused investigation

```bash
autotimeliner -f /evidence/memory.raw --skip-mftscan --skip-shellbags
```

### Verbose debug output

```bash
autotimeliner -f /evidence/memory.raw -v
```

---

## Output Format

The CSV file contains these columns:

| Column | Description |
|---|---|
| `Timestamp (UTC)` | ISO 8601 timestamp, always UTC |
| `Source` | Plugin that produced the record (e.g. `timeliner/pslist`, `mftscan`, `shellbags`, `psscan`, `netscan`, `malfind`) |
| `Description` | File path, process name, registry key, network connection, or folder path |
| `Detail` | Timestamp type, PID, network addresses, or extra context |
| `Inode` | MFT record number (from mftscan; `0` for other sources) |
| `UID` | User identifier |
| `GID` | Group identifier |
| `Size` | File size in bytes |
| `Mode` | File mode string (e.g. `----------`) |

### Example rows

```csv
Timestamp (UTC),Source,Description,Detail,Inode,UID,GID,Size,Mode
2023-10-18T09:14:22+00:00,mftscan,\Windows\System32\cmd.exe,Created Date | type=FILE,123456,0,0,368640,----------
2023-10-18T09:14:23+00:00,shellbags,C:\Users\victim\Desktop,user=victim | Last Write Time,0,0,0,0,----------
2023-10-18T09:14:25+00:00,timeliner/pslist,cmd.exe (PID 1234),Created Date: 2023-10-18T09:14:25+00:00,0,0,0,0,----------
2023-10-18T09:14:26+00:00,psscan,Process Created: powershell.exe,PID=5678 PPID=1234 Offset=0x1a2b3c4d,0,0,0,0,----------
2023-10-18T09:14:30+00:00,netscan,Network TCP ESTABLISHED: 192.168.1.100:49876 → 185.123.45.67:443,PID=5678 Owner=powershell.exe,0,0,0,0,----------
1970-01-01T00:00:00+00:00,malfind,⚠️ Suspicious Memory: svchost.exe,PID=2468 VPN=0x7ff00000-0x7ff10000 Protection=PAGE_EXECUTE_READWRITE,0,0,0,0,----------
1970-01-01T00:00:00+00:00,svcscan,Service: MaliciousSvc (Malicious Service),State=Running Start=Auto PID=9999 Binary=C:\Temp\malware.exe,0,0,0,0,----------
```

> **Note**: Records from plugins without native timestamps (cmdline, svcscan, filescan, malfind, handles, envars) use `1970-01-01T00:00:00` as a placeholder. These records are still forensically valuable for context.

---

## Running Tests

```bash
poetry run pytest
# or with coverage:
poetry run pytest --cov=autotimeliner
```
