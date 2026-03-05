# AutoTimeliner

> **Automagically extract forensic timeline from volatile memory dumps.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Volatility3](https://img.shields.io/badge/volatility-3.x-orange)](https://github.com/volatilityfoundation/volatility3)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

AutoTimeliner runs multiple Volatility3 plugins against Windows, Linux, and
macOS memory images, then merges their output into a single, sorted CSV timeline:

### Generic Timeline Plugin

| Plugin | What it captures |
|---|---|
| `timeliner` | Cross-plugin timestamp events (all OS families when supported) |

### Windows Plugin Set

| Plugin | What it captures |
|---|---|
| `timeliner` | Timestamps from processes, registry, handles, etc. |
| `mftscan` | MFT file entries found in memory |
| `shellbags` | User folder-access history from registry hives |

### Linux Plugin Set

| Plugin | What it captures |
|---|---|
| `linux.pslist` | Process start/exit timeline context |
| `linux.bash` | Shell command history evidence |
| `linux.lsof` | Open file evidence from processes |

### macOS Plugin Set

| Plugin | What it captures |
|---|---|
| `mac.pslist` | Process start/exit timeline context |
| `mac.bash` | Shell command history evidence |
| `mac.lsof` | Open file evidence from processes |

### Windows Process & Execution Analysis

| Plugin | What it captures |
|---|---|
| `psscan` | Active, terminated, and hidden processes with timestamps |
| `cmdline` | Command-line arguments for each process |
| `userassist` | Program execution evidence from Windows registry |

### Windows Network Analysis

| Plugin | What it captures |
|---|---|
| `netscan` | Network connections with creation timestamps |

### Windows Malware Detection

| Plugin | What it captures |
|---|---|
| `malfind` | Code injection and suspicious memory regions |
| `svcscan` | Windows services (useful for persistence detection) |

### Additional Windows Plugins (opt-in)

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

> AutoTimeliner identifies the memory image family automatically and enables
> the appropriate plugin set for Windows, Linux, or macOS.
> For faster startup you can pass `--os-hint` to skip automatic detection.

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
| `--os-hint` | Force image OS family (`windows`, `linux`, `mac`; aliases: `win`, `macos`, `darwin`) and skip auto-identification |
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

Speed up startup when you already know the dump OS:

```bash
autotimeliner -f TargetServer.raw --os-hint windows
```

Use macOS alias values for convenience:

```bash
autotimeliner -f MacbookCapture.mem --os-hint darwin
```

Run only timeliner and shellbags (skip MFT scan):

```bash
autotimeliner -f TargetServer.raw --skip-mftscan
```

Full forensic scan (Windows plugin set + optional extended plugins):

```bash
autotimeliner -f TargetServer.raw --with-dlllist --with-filescan --with-handles --with-envars
```

Quick malware-focused scan:

```bash
autotimeliner -f TargetServer.raw --skip-timeliner --skip-mftscan --skip-shellbags
```

Linux-focused timeline collection (auto-enables linux plugins):

```bash
autotimeliner -f UbuntuWorkstation.mem
```

macOS-focused timeline collection (auto-enables macOS plugins):

```bash
autotimeliner -f MacbookCapture.mem
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

## Identification Performance

AutoTimeliner includes several optimizations to reduce identification time:

- `--os-hint` bypasses automatic OS probing entirely.
- Probe order is optimized using filename hints (for example `linux`, `ubuntu`, `macos`).
- Identification results are cached per image key (`path + size + mtime`).

Cache file:

```text
~/.cache/autotimeliner/volatility3/.autotimeliner_profile_cache.json
```

During detection, logs include probe progress and result messages such as:

```text
OS probe attempt: family=windows plugin=windows.info.Info
OS probe returned no rows: windows.info.Info
Memory image identification succeeded: os=linux profile=linux:... probe=linux.banners.Banners
```

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
