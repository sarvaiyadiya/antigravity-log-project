"""
CSV Writer — outputs normalized events as CSV for ML/analytics pipelines.

This writer preserves the existing CSV output behaviour used by
Practicals 1–8 while adding support for writing UnifiedEvent objects
to flat CSV.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import IO, Iterator

from src.schema.unified_event import UnifiedEvent

# Canonical column order for CSV output
CSV_COLUMNS = [
    "event_uid",
    "record_hash",
    "ingest_timestamp",
    "timestamp_utc",
    "format_name",
    "source_id",
    "vendor",
    "device_type",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "event_category",
    "event_action",
    "severity",
    "threat_name",
    "threat_signature_id",
    "username",
    "user_agent",
    "http_method",
    "http_url",
    "http_status",
    "weak_label",
    "label_confidence",
    "evidence_codes",
    "label_conflict",
    "raw_log",
]


class CsvWriter:
    """Writes UnifiedEvent objects as flat CSV rows."""

    def __init__(
        self,
        output: str | Path | None = None,
        append: bool = False,
        write_header: bool = True,
        columns: list[str] | None = None,
    ) -> None:
        self._output_path = Path(output) if output else None
        self._append = append
        self._write_header = write_header
        self._columns = columns or CSV_COLUMNS
        self._file: IO[str] | None = None
        self._writer: csv.DictWriter | None = None

    def __enter__(self) -> "CsvWriter":
        self.open()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def open(self) -> None:
        if self._output_path:
            self._output_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if self._append else "w"
            self._file = self._output_path.open(
                mode, encoding="utf-8", newline=""
            )
        else:
            self._file = sys.stdout

        self._writer = csv.DictWriter(
            self._file,
            fieldnames=self._columns,
            extrasaction="ignore",
            lineterminator="\n",
        )
        if self._write_header and not self._append:
            self._writer.writeheader()

    def close(self) -> None:
        if self._file and self._file is not sys.stdout:
            self._file.close()
        self._file = None
        self._writer = None

    def write(self, event: UnifiedEvent) -> None:
        if self._writer is None:
            raise RuntimeError("Writer is not open.")
        row = event.to_dict()
        self._writer.writerow(row)

    def write_batch(self, events: Iterator[UnifiedEvent]) -> int:
        count = 0
        for event in events:
            self.write(event)
            count += 1
        return count
