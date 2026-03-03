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
| `--skip-timeliner` | Do not run the timeliner plugin |
| `--skip-mftscan` | Do not run the mftscan plugin |
| `--skip-shellbags` | Do not run the shellbags plugin |
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
| `Source` | Plugin that produced the record (e.g. `timeliner/pslist`, `mftscan`, `shellbags`) |
| `Description` | File path, process name, registry key, or folder path |
| `Detail` | Timestamp type (Created/Modified/Accessed/Changed) and extra fields |
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
```

---

## Running Tests

```bash
poetry run pytest
# or with coverage:
poetry run pytest --cov=autotimeliner
```
