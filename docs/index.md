# AutoTimeliner Documentation

## Overview

AutoTimeliner automates the creation of a forensic timeline from a Windows volatile memory dump.

It runs multiple **Volatility3** plugins and merges their output into a single sorted CSV:

```
┌─────────────────────────────────────────────────┐
│ Core Timeline Plugins                           │
│   timeliner, mftscan, shellbags                 │
├─────────────────────────────────────────────────┤
│ Process & Execution Analysis                    │
│   psscan, cmdline, userassist                   │
├─────────────────────────────────────────────────┤
│ Network Analysis                                │
│   netscan                                       │
├─────────────────────────────────────────────────┤
│ Malware Detection                               │
│   malfind, svcscan                              │
├─────────────────────────────────────────────────┤
│ Extended Plugins (opt-in)                       │
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

## Contents

- [Installation & Quick Start](usage.md)
- [CLI Reference](usage.md#cli-reference)
- [Output Format](usage.md#output-format)
- [Migrating from v1 (Volatility2)](migration.md)
