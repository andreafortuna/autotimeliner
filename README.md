# AutoTimeliner

> **Automagically extract forensic timeline from volatile memory dumps.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Volatility3](https://img.shields.io/badge/volatility-3.x-orange)](https://github.com/volatilityfoundation/volatility3)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

AutoTimeliner runs multiple Volatility3 plugins against a Windows memory image
and merges their output into a single, sorted CSV timeline:

### Core Timeline Plugins

| Plugin | What it captures |
|---|---|
| `timeliner` | Timestamps from processes, registry, handles, etc. |
| `mftscan` | MFT file entries found in memory |
| `shellbags` | User folder-access history from registry hives |

### Process & Execution Analysis

| Plugin | What it captures |
|---|---|
| `psscan` | Active, terminated, and hidden processes with timestamps |
| `cmdline` | Command-line arguments for each process |
| `userassist` | Program execution evidence from Windows registry |

### Network Analysis

| Plugin | What it captures |
|---|---|
| `netscan` | Network connections with creation timestamps |

### Malware Detection

| Plugin | What it captures |
|---|---|
| `malfind` | Code injection and suspicious memory regions |
| `svcscan` | Windows services (useful for persistence detection) |

### Additional Plugins (opt-in)

| Plugin | What it captures |
|---|---|
| `dlllist` | DLLs loaded by each process |
| `filescan` | Files open in memory at acquisition time |
| `handles` | Open handles (files, registry keys, mutexes) |
| `envars` | Environment variables for processes |

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | ≥ 3.9 | |
| [Volatility3](https://github.com/volatilityfoundation/volatility3) | ≥ 2.5 | installed automatically via Poetry/pip |
| [jsonschema](https://pypi.org/project/jsonschema/) | ≥ 4.0 | enables Volatility3 schema validation and avoids `Dependency for validation unavailable: jsonschema` warning |
| [mactime](https://www.sleuthkit.org/) | any | **optional** — only needed for `--use-mactime` legacy mode |

> **Target OS of memory images**: Windows only (mftscan and shellbags are Windows-specific plugins).  
> Linux/macOS image analysis is not currently supported.

---

## Installation

### With Poetry (recommended)

```bash
git clone https://github.com/andreafortuna/autotimeliner.git
cd autotimeliner
poetry install
```

### With pip

```bash
pip install .
```

---

## Usage

```
autotimeliner -f IMAGEFILE [-t TIMEFRAME] [-o OUTPUT] [options]
```

### Options

| Flag | Description |
|---|---|
| `-f`, `--imagefile` | Memory dump file or glob (e.g. `'*.raw'`) |
| `-t`, `--timeframe` | Filter to `YYYY-MM-DD..YYYY-MM-DD` range |
| `-o`, `--output` | Output CSV path (default: `<imagefile>-timeline.csv`) |
| `--skip-timeliner` | Skip the timeliner plugin |
| `--skip-mftscan` | Skip the mftscan plugin |
| `--skip-shellbags` | Skip the shellbags plugin |
| `--skip-psscan` | Skip process scanning |
| `--skip-cmdline` | Skip command-line extraction |
| `--skip-netscan` | Skip network connection scanning |
| `--skip-userassist` | Skip program execution evidence |
| `--skip-svcscan` | Skip Windows services scanning |
| `--skip-malfind` | Skip malware/injection detection |
| `--with-dlllist` | Enable DLL analysis (slow) |
| `--with-filescan` | Enable open files scanning (many records) |
| `--with-handles` | Enable handle scanning (many records) |
| `--with-envars` | Enable environment variables extraction |
| `--use-mactime` | Legacy mode: use external `mactime` binary |
| `-v`, `--verbose` | Enable debug logging |
| `--version` | Print version and exit |

### Examples

Extract a full timeline from a single image:

```bash
autotimeliner -f TargetServer.raw
```

Filter to a specific time window:

```bash
autotimeliner -f TargetServer.raw -t 2023-10-17..2023-10-21
```

Process all `.raw` files in a directory, specifying output path:

```bash
autotimeliner -f './*.raw' -o /evidence/timeline.csv
```

Run only timeliner and shellbags (skip MFT scan):

```bash
autotimeliner -f TargetServer.raw --skip-mftscan
```

Full forensic scan with all plugins enabled:

```bash
autotimeliner -f TargetServer.raw --with-dlllist --with-filescan --with-handles --with-envars
```

Quick malware-focused scan:

```bash
autotimeliner -f TargetServer.raw --skip-timeliner --skip-mftscan --skip-shellbags
```

---

## Output

The output CSV has the following columns:

| Column | Description |
|---|---|
| `Timestamp (UTC)` | ISO 8601 UTC timestamp |
| `Source` | Plugin that produced the record |
| `Description` | File name, path, process, or registry key |
| `Detail` | Timestamp type, user, or extra context |
| `Inode` | MFT inode number (where applicable) |
| `UID` / `GID` | User/group identifiers |
| `Size` | File size in bytes |
| `Mode` | File mode string |

---

## Migrating from v1 (Volatility2)

See [docs/migration.md](docs/migration.md) for a full comparison.

Key changes:
- **Volatility3 profile identification** — AutoTimeliner performs a best-effort OS/profile probe via Volatility3 plugins.
- **Automatic symbol tables setup** — Windows/macOS/Linux symbol packs are downloaded and installed automatically.
- **`-p / --customprofile` is deprecated** — it is silently ignored.
- **`mftparser` → `mftscan`** — same data, new plugin name.
- **No body files written to disk** — data flows through Python directly to CSV.
- **`mactime` is now optional** — use `--use-mactime` for the old body-file workflow.

---

## Development

```bash
poetry install
poetry run pytest
```

---

## License

MIT — see [LICENSE](LICENSE).

## Author

Andrea Fortuna — [andrea@andreafortuna.org](mailto:andrea@andreafortuna.org) — [andreafortuna.org](https://andreafortuna.org)
