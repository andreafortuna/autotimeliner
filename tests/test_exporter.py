"""
tests/test_exporter.py
~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for autotimeliner.exporter — pure-Python CSV export and
timeframe filtering (no Volatility3 or mactime required).
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

import pytest

from autotimeliner.exporter import parse_timeframe, export_csv, CSV_COLUMNS
from autotimeliner.timeliner import TimelineRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(ts: str, source: str = "test", desc: str = "event") -> TimelineRecord:
    return TimelineRecord(
        timestamp=datetime.fromisoformat(ts).replace(tzinfo=timezone.utc),
        source=source,
        description=desc,
    )


# ---------------------------------------------------------------------------
# parse_timeframe
# ---------------------------------------------------------------------------

class TestParseTimeframe:
    def test_valid_range(self):
        start, end = parse_timeframe("2023-01-01..2023-12-31")
        assert start.year == 2023 and start.month == 1 and start.day == 1
        assert end.year == 2023 and end.month == 12 and end.day == 31
        assert end.hour == 23 and end.minute == 59

    def test_same_day(self):
        start, end = parse_timeframe("2023-06-15..2023-06-15")
        assert start.date() == end.date()

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Invalid timeframe"):
            parse_timeframe("2023-01-01 2023-12-31")

    def test_reversed_range_raises(self):
        with pytest.raises(ValueError, match="end date must be"):
            parse_timeframe("2023-12-31..2023-01-01")


# ---------------------------------------------------------------------------
# export_csv
# ---------------------------------------------------------------------------

class TestExportCsv:
    def test_writes_header_and_rows(self, tmp_path: Path):
        records = [
            _make_record("2023-06-01T10:00:00", desc="alpha"),
            _make_record("2023-06-02T10:00:00", desc="beta"),
        ]
        out = tmp_path / "out.csv"
        result = export_csv(records, out)
        assert result == out
        rows = list(csv.reader(out.open()))
        assert rows[0] == CSV_COLUMNS
        assert len(rows) == 3  # header + 2 records

    def test_timeframe_filter_includes(self, tmp_path: Path):
        records = [
            _make_record("2023-01-15T00:00:00", desc="inside"),
            _make_record("2023-03-01T00:00:00", desc="outside"),
        ]
        out = tmp_path / "out.csv"
        export_csv(records, out, timeframe="2023-01-01..2023-01-31")
        rows = list(csv.reader(out.open()))
        descs = [r[2] for r in rows[1:]]
        assert "inside" in descs
        assert "outside" not in descs

    def test_empty_records_writes_header_only(self, tmp_path: Path):
        out = tmp_path / "out.csv"
        export_csv([], out)
        rows = list(csv.reader(out.open()))
        assert rows[0] == CSV_COLUMNS
        assert len(rows) == 1

    def test_output_path_returned(self, tmp_path: Path):
        out = tmp_path / "subdir" / "timeline.csv"
        result = export_csv([], out)
        assert result.exists()
