"""
LEEF Parser — Log Event Extended Format (IBM QRadar LEEF).

LEEF is used primarily by IBM QRadar and products that integrate with it.
Supported by many Cisco, Juniper, and IBM security products.

Format (LEEF 1.0)
-----------------
LEEF:1.0|Vendor|Product|Version|EventID|key=value\tkey2=value2

Format (LEEF 2.0)
-----------------
LEEF:2.0|Vendor|Product|Version|EventID|delimiter=\t|key=value\tkey2=value2

Example:
  LEEF:1.0|Cisco|ASA|9.14|106023|src=192.168.1.5\tspt=44231\tdst=10.0.0.1\tdpt=443
"""

from __future__ import annotations

import re

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser


_LEEF_HEADER_RE = re.compile(
    r"^LEEF:(?P<version>\d+\.\d+)"
    r"\|(?P<vendor>[^|]*)"
    r"\|(?P<product>[^|]*)"
    r"\|(?P<product_version>[^|]*)"
    r"\|(?P<event_id>[^|]*)"
    r"(?:\|delimiter=(?P<delimiter>[^\|]+))?"  # LEEF 2.0 optional delimiter
    r"\|(?P<attributes>.*)$",
    re.DOTALL,
)

# LEEF canonical attribute → UES field name
_LEEF_FIELD_MAP: dict[str, str] = {
    "src": "src_ip",
    "dst": "dst_ip",
    "spt": "src_port",
    "dpt": "dst_port",
    "proto": "protocol",
    "usrName": "username",
    "url": "http_url",
    "ua": "user_agent",
    "devTime": "timestamp_raw",
    "cat": "event_category",
    "msg": "message",
    "sev": "severity",
    "severity": "severity",
    "action": "action",
    "vSrcPort": "src_port",
    "vDstPort": "dst_port",
}


class LeefParser(BaseLogParser):
    """Parses IBM QRadar LEEF 1.0 and 2.0 log lines."""

    @property
    def format_name(self) -> str:
        return "leef"

    @property
    def description(self) -> str:
        return "LEEF parser — IBM QRadar Log Event Extended Format (v1.0, v2.0)"

    def can_parse(self, sample: str) -> bool:
        return sample.strip().startswith("LEEF:")

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()
        match = _LEEF_HEADER_RE.match(stripped)

        if not match:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error="Line does not match LEEF header pattern.",
                format_name=self.format_name,
            )

        groups = match.groupdict()
        attributes_raw = groups.get("attributes", "") or ""

        # Determine delimiter (tab by default, custom in LEEF 2.0)
        delimiter_raw = groups.get("delimiter") or "\t"
        delimiter = _decode_delimiter(delimiter_raw)

        # Split attributes on delimiter
        attr_pairs: dict[str, str] = {}
        for pair in attributes_raw.split(delimiter):
            if "=" in pair:
                key, _, value = pair.partition("=")
                attr_pairs[key.strip()] = value.strip()

        # Map LEEF → UES
        mapped: dict[str, str] = {}
        extra: dict[str, str] = {}
        for leef_key, leef_val in attr_pairs.items():
            ues_key = _LEEF_FIELD_MAP.get(leef_key)
            if ues_key:
                mapped[ues_key] = leef_val
            else:
                extra[leef_key] = leef_val

        fields: dict = {
            "leef_version": groups.get("version"),
            "vendor": groups.get("vendor"),
            "device_product": groups.get("product"),
            "device_version": groups.get("product_version"),
            "threat_signature_id": groups.get("event_id"),
            **mapped,
            "extra_fields": extra,
        }

        return ParseResult(
            success=True,
            raw_log=line,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )


def _decode_delimiter(raw: str) -> str:
    """Convert hex or escape sequence delimiter to actual character."""
    raw = raw.strip()
    if raw.startswith("0x") or raw.startswith("0X"):
        try:
            return chr(int(raw, 16))
        except ValueError:
            return "\t"
    escape_map = {"\\t": "\t", "\\n": "\n", "\\r": "\r", "\\|": "|"}
    return escape_map.get(raw, raw or "\t")


# Auto-register on import
register_parser(LeefParser())
