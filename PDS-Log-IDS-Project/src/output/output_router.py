"""
Output Router — dispatches normalized events to the correct output adapter.

PS requirement (g): "Efficient SIEM and Data Lake integration."

Supported output formats
------------------------
  cef         → CEF (Splunk, QRadar, ArcSight, Sentinel)
  json-lines  → NDJSON (Elastic, Kafka, S3, BigQuery)
  csv         → CSV (ML pipelines, Excel, Pandas)
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from src.schema.unified_event import UnifiedEvent
from .cef_writer import CefWriter
from .json_lines_writer import JsonLinesWriter
from .csv_writer import CsvWriter

SUPPORTED_FORMATS = {
    "cef": CefWriter,
    "json-lines": JsonLinesWriter,
    "jsonl": JsonLinesWriter,
    "ndjson": JsonLinesWriter,
    "csv": CsvWriter,
}


def get_writer(
    format_name: str,
    output: str | Path | None = None,
    append: bool = False,
) -> CefWriter | JsonLinesWriter | CsvWriter:
    """
    Instantiate the correct writer for the given format name.

    Parameters
    ----------
    format_name : One of "cef", "json-lines", "jsonl", "ndjson", "csv".
    output      : Output file path; None → stdout.
    append      : If True, append to existing file.

    Raises
    ------
    ValueError if format_name is not recognised.
    """
    fmt = format_name.lower().strip()
    writer_class = SUPPORTED_FORMATS.get(fmt)
    if writer_class is None:
        available = ", ".join(sorted(SUPPORTED_FORMATS.keys()))
        raise ValueError(
            f"Unknown output format '{format_name}'. "
            f"Supported formats: {available}."
        )
    return writer_class(output=output, append=append)


class OutputRouter:
    """
    Convenience class that wraps multiple output writers.

    Useful when the same events must be written to multiple formats
    simultaneously (e.g., CSV for ML + CEF for SIEM).
    """

    def __init__(self) -> None:
        self._writers: list[CefWriter | JsonLinesWriter | CsvWriter] = []

    def add(
        self,
        format_name: str,
        output: str | Path | None = None,
        append: bool = False,
    ) -> "OutputRouter":
        """Add an output format. Returns self for chaining."""
        self._writers.append(get_writer(format_name, output, append))
        return self

    def __enter__(self) -> "OutputRouter":
        for writer in self._writers:
            writer.open()
        return self

    def __exit__(self, *args: object) -> None:
        for writer in self._writers:
            writer.close()

    def write(self, event: UnifiedEvent) -> None:
        for writer in self._writers:
            writer.write(event)

    def write_batch(self, events: list[UnifiedEvent]) -> int:
        """Write a list of events to all registered writers."""
        for event in events:
            self.write(event)
        return len(events)
