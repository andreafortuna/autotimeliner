# AutoTimeliner Documentation

## Overview

AutoTimeliner automates the creation of a forensic timeline from Windows, Linux,
and macOS volatile memory dumps.

It runs multiple **Volatility3** plugins and merges their output into a single sorted CSV:

```
┌─────────────────────────────────────────────────┐
│ Core Timeline Plugin                            │
│   timeliner                                      │
├─────────────────────────────────────────────────┤
│ Windows Process & Execution Analysis            │
│   psscan, cmdline, userassist                   │
├─────────────────────────────────────────────────┤
│ Linux Plugin Set                                │
│   linux.pslist, linux.bash, linux.lsof          │
├─────────────────────────────────────────────────┤
│ macOS Plugin Set                                │
│   mac.pslist, mac.bash, mac.lsof                │
├─────────────────────────────────────────────────┤
│ Windows Network Analysis                        │
│   netscan                                       │
├─────────────────────────────────────────────────┤
│ Windows Malware Detection                       │
│   malfind, svcscan                              │
├─────────────────────────────────────────────────┤
│ Extended Windows Plugins (opt-in)               │
│   dlllist, filescan, handles, envars            │
└─────────────────────────────────────────────────┘
                      │
                      ▼
          merge & sort by timestamp
                      │
                      ▼
           filter by timeframe
                      │
                      ▼
               timeline.csv
```

OS identification notes:

- Auto-detection selects Windows/Linux/macOS plugin sets.
- `--os-hint` can skip detection for faster startup.
- Identification results are cached and reused for unchanged images.

## Contents

- [Installation & Quick Start](usage.md)
- [CLI Reference](usage.md#cli-reference)
- [Output Format](usage.md#output-format)
- [Migrating from v1 (Volatility2)](migration.md)
