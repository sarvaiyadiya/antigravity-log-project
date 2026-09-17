"""
JSON-Lines Writer — outputs normalized events as newline-delimited JSON.

PS requirement (g): "Efficient SIEM and Data Lake integration."

JSON-Lines (NDJSON) output is accepted by:
- Elastic / OpenSearch (Logstash, Beats)
- Splunk (JSON input)
- AWS S3 / Azure Data Lake (as Parquet-convertible input)
- Apache Kafka (as message payload)
- BigQuery / Snowflake streaming inserts
- Any Python, Go, or Java data pipeline

Each line is a complete, self-contained JSON object representing
one normalized UnifiedEvent. This makes the output trivially
streamable and splittable.

Usage
-----
writer = JsonLinesWriter("output/events.jsonl")
with writer:
    writer.write(event)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import IO, Iterator

from src.schema.unified_event import UnifiedEvent


class JsonLinesWriter:
    """
    Writes UnifiedEvent objects as newline-delimited JSON (JSON-Lines).

    Parameters
    ----------
    output : path string, Path, or None (defaults to stdout).
    append : if True, open in append mode; otherwise write mode.
    pretty : if True, output indented JSON (for debugging only — not NDJSON).
    """

    def __init__(
        self,
        output: str | Path | None = None,
        append: bool = False,
        pretty: bool = False,
    ) -> None:
        self._output_path = Path(output) if output else None
        self._append = append
        self._pretty = pretty
        self._file: IO[str] | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "JsonLinesWriter":
        self.open()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def open(self) -> None:
        if self._output_path:
            self._output_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if self._append else "w"
            self._file = self._output_path.open(
                mode, encoding="utf-8", newline="\n"
            )
        else:
            self._file = sys.stdout

    def close(self) -> None:
        if self._file and self._file is not sys.stdout:
            self._file.close()
        self._file = None

    # ------------------------------------------------------------------
    # Write methods
    # ------------------------------------------------------------------

    def write(self, event: UnifiedEvent) -> None:
        """Write a single event as one JSON line."""
        if self._file is None:
            raise RuntimeError(
                "Writer is not open. Use 'with JsonLinesWriter(...) as w:'"
            )
        if self._pretty:
            import json
            self._file.write(
                json.dumps(event.to_dict(), indent=2, ensure_ascii=False)
                + "\n"
            )
        else:
            self._file.write(event.to_json() + "\n")

    def write_batch(self, events: Iterator[UnifiedEvent]) -> int:
        """Write multiple events. Returns count written."""
        count = 0
        for event in events:
            self.write(event)
            count += 1
        return count
