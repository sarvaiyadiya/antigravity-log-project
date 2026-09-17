"""
CSV Log Parser — handles generic delimited (CSV/TSV) log files.

Many network devices and legacy security tools export logs as CSV or TSV.
This parser uses the first line as a header to determine column names,
which are then mapped to UES canonical names via the FieldMapper.

Supported sources
-----------------
- NetFlow / IPFIX CSV exports
- Cisco router access-list CSV logs
- Legacy firewall export formats
- Any tabular security log with a header row

Configuration
-------------
In the source YAML config, specify:
  csv_delimiter: ","      # or "\t" for TSV
  csv_has_header: true
  field_map:
    SourceIP: src_ip
    DestIP: dst_ip
    ...
"""

from __future__ import annotations

import csv
import io
import re

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser


class CsvLogParser(BaseLogParser):
    """
    Parses CSV/TSV log lines using a configurable delimiter.

    The first call to parse_line() that looks like a header will set
    the column names for all subsequent lines. In streaming use, call
    set_headers() explicitly before processing data rows.
    """

    def __init__(
        self,
        delimiter: str = ",",
        has_header: bool = True,
        headers: list[str] | None = None,
    ) -> None:
        self._delimiter = delimiter
        self._has_header = has_header
        self._headers: list[str] | None = headers
        self._first_data_line = True

    @property
    def format_name(self) -> str:
        return "csv"

    @property
    def description(self) -> str:
        delim_name = "TSV" if self._delimiter == "\t" else "CSV"
        return f"Generic {delim_name} log parser"

    def set_headers(self, headers: list[str]) -> None:
        """Explicitly set column headers (call before streaming data rows)."""
        self._headers = headers
        self._first_data_line = False

    def can_parse(self, sample: str) -> bool:
        """
        Heuristic: True if the line contains multiple comma/tab separators
        and does not match other known formats (not syslog PRI, not CEF, not JSON).
        """
        stripped = sample.strip()
        # Exclude other known formats
        if (
            stripped.startswith("<")
            or "CEF:" in stripped
            or stripped.startswith("LEEF:")
            or stripped.startswith("{")
            or stripped.startswith("[")
            or "[**]" in stripped
        ):
            return False

        # Count delimiters
        comma_count = stripped.count(",")
        tab_count = stripped.count("\t")
        return comma_count >= 3 or tab_count >= 3

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()
        if not stripped:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error="Blank line.",
                format_name=self.format_name,
            )

        # Parse the row using Python's csv module
        try:
            reader = csv.reader(
                io.StringIO(stripped),
                delimiter=self._delimiter,
            )
            row = next(reader)
        except (csv.Error, StopIteration) as exc:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"CSV parse error: {exc}",
                format_name=self.format_name,
            )

        # Handle header detection
        if self._has_header and self._headers is None:
            # Treat this row as the header
            self._headers = [col.strip() for col in row]
            self._first_data_line = False
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error="Header row detected — not a data event.",
                format_name=self.format_name,
            )

        if self._headers is None:
            # No headers configured; use positional names
            headers = [f"col_{i}" for i in range(len(row))]
        else:
            headers = self._headers

        if len(row) != len(headers):
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=(
                    f"Column count mismatch: expected {len(headers)}, "
                    f"got {len(row)}."
                ),
                format_name=self.format_name,
            )

        fields = {
            header: value.strip()
            for header, value in zip(headers, row)
            if value.strip()
        }

        return ParseResult(
            success=True,
            raw_log=line,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )


# Auto-register on import
register_parser(CsvLogParser())
