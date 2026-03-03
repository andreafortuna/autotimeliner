# AutoTimeliner Documentation

## Overview

AutoTimeliner automates the creation of a forensic timeline from a Windows volatile memory dump.

It runs three **Volatility3** plugins and merges their output into a single sorted CSV:

```
timeliner  ──┐
mftscan    ──┼──► merge & sort ──► filter by timeframe ──► timeline.csv
shellbags  ──┘
```

## Contents

- [Installation & Quick Start](usage.md)
- [CLI Reference](usage.md#cli-reference)
- [Output Format](usage.md#output-format)
- [Migrating from v1 (Volatility2)](migration.md)
