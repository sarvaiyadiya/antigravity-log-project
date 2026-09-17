"""
JSON Log Parser — handles generic JSON log lines and the existing cj.log format.

Supports two modes:
  1. Generic JSON objects  — any valid JSON object per line.
  2. cj_json_array format  — the specific positional JSON-array format
     from the existing cj.log dataset (8-field arrays).

The cj_json_array parser wraps the existing cj_parser.py logic, keeping
all original provenance semantics intact.

Example (generic JSON):
  {"timestamp": "2024-01-08T12:34:56Z", "src_ip": "1.2.3.4", "action": "deny"}

Example (cj_json_array):
  ["web_request","page_view","2024-01-08 12:34:56","1.2.3.4",44231,"Mozilla/5.0","en-US","{}"]
"""

from __future__ import annotations

import json

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser
from src.ingestion.cj_parser import (
    FIELD_NAMES as CJ_FIELD_NAMES,
    EXPECTED_FIELD_COUNT,
)


# ---------------------------------------------------------------------------
# Generic JSON object parser
# ---------------------------------------------------------------------------

class GenericJsonParser(BaseLogParser):
    """Parses single-line JSON object logs (one JSON object per line)."""

    @property
    def format_name(self) -> str:
        return "json"

    @property
    def description(self) -> str:
        return "Generic JSON parser — one JSON object per line"

    def can_parse(self, sample: str) -> bool:
        stripped = sample.strip()
        # JSON objects start with { and end with }
        return stripped.startswith("{") and stripped.endswith("}")

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"JSON decode error: {exc}",
                format_name=self.format_name,
            )

        if not isinstance(obj, dict):
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error="JSON value is not an object.",
                format_name=self.format_name,
            )

        # Flatten one level of nesting for common log schemas
        fields: dict = {}
        extra: dict = {}
        for key, value in obj.items():
            if isinstance(value, dict):
                extra[key] = value
            else:
                fields[key] = value

        if extra:
            fields["extra_fields"] = extra

        return ParseResult(
            success=True,
            raw_log=line,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )


# ---------------------------------------------------------------------------
# cj.log JSON-array parser (wraps existing cj_parser.py)
# ---------------------------------------------------------------------------

class CjJsonArrayParser(BaseLogParser):
    """
    Parser for the cj.log positional JSON-array format.

    Each line contains one or more JSON arrays with exactly 8 fields:
    [category_type, sub_key, timestamp, client_ip, source_port,
     user_agent, language, metadata]

    This parser wraps the existing cj_parser.py logic and produces
    ParseResults compatible with the universal parser registry.
    """

    @property
    def format_name(self) -> str:
        return "cj_json_array"

    @property
    def description(self) -> str:
        return (
            "cj.log JSON-array parser — "
            f"{EXPECTED_FIELD_COUNT}-field positional arrays"
        )

    def can_parse(self, sample: str) -> bool:
        """True if the line looks like a JSON array with ~8 elements."""
        stripped = sample.strip()
        if not (stripped.startswith("[") and "]" in stripped):
            return False
        try:
            obj = json.loads(stripped)
            return isinstance(obj, list) and len(obj) == EXPECTED_FIELD_COUNT
        except json.JSONDecodeError:
            return False

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

        try:
            value = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"JSON decode error: {exc}",
                format_name=self.format_name,
            )

        if not isinstance(value, list):
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error="Decoded value is not an array.",
                format_name=self.format_name,
            )

        if len(value) != EXPECTED_FIELD_COUNT:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=(
                    f"Expected {EXPECTED_FIELD_COUNT} fields, "
                    f"found {len(value)}."
                ),
                format_name=self.format_name,
            )

        # Map positional fields to named fields
        fields = dict(zip(CJ_FIELD_NAMES, value, strict=True))

        # Map to UES canonical names
        fields["src_ip"] = fields.pop("client_ip", None)
        fields["src_port"] = fields.pop("source_port", None)
        fields["event_category"] = fields.pop("category_type", None)

        return ParseResult(
            success=True,
            raw_log=line,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )


# Auto-register both parsers
# cj_json_array is registered first so it wins over generic JSON
# for the cj.log format (higher specificity)
register_parser(CjJsonArrayParser())
register_parser(GenericJsonParser())
