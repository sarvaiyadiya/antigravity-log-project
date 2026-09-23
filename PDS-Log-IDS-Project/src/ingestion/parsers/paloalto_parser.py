"""
Palo Alto PAN-OS Parser — native log format for Palo Alto Networks NGFW.

Palo Alto firewalls export logs in a pipe-delimited CSV format.
The log type is embedded as field index 3 (TYPE): TRAFFIC, THREAT, SYSTEM, CONFIG, etc.

Traffic Log Format (key positional fields)
------------------------------------------
Field positions (0-indexed) for TRAFFIC type:
  0   FUTURE_USE
  1   RECEIVE_TIME      e.g. "2024/01/15 10:23:45"
  2   SERIAL            device serial number
  3   TYPE              "TRAFFIC"
  4   SUBTYPE           "start", "end", "drop", "deny"
  6   GENERATED_TIME
  7   SRC_IP
  8   DST_IP
  9   NAT_SRC_IP
  10  NAT_DST_IP
  11  RULE_NAME
  12  SRC_USER
  13  DST_USER
  14  APP              application name (e.g., "web-browsing", "ssl", "unknown-tcp")
  15  VSYS
  16  SRC_ZONE
  17  DST_ZONE
  18  INBOUND_IF
  19  OUTBOUND_IF
  24  SRC_PORT
  25  DST_PORT
  26  NAT_SRC_PORT
  27  NAT_DST_PORT
  28  FLAGS
  29  PROTOCOL         "tcp", "udp", "icmp"
  30  ACTION           "allow", "deny"
  38  BYTES_SENT
  39  BYTES_RECEIVED
  40  PACKETS
  41  START_TIME
  44  PKTS_SENT
  45  PKTS_RECEIVED
  56  CATEGORY
  61  THREAT_ID        (THREAT logs only)
  62  THREAT_NAME      (THREAT logs only)

Threat Log Format
-----------------
Similar to traffic but TYPE="THREAT" and additional fields for threat_id, threat_name,
severity at positions 57-63.

PS requirements covered
-----------------------
(b) Extract source-specific attributes — full network 5-tuple, action, app, zones
(c) Normalize to common taxonomy — mapped to UnifiedEvent
(e) Plug-and-play — registered via register_parser()
"""

from __future__ import annotations

import csv
import io
from typing import Any

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser


# Minimum expected field count for a valid PAN-OS line
_MIN_FIELDS = 30

# PAN-OS ACTION → UES event_action
_ACTION_MAP: dict[str, str] = {
    "allow": "allow",
    "deny": "deny",
    "drop": "drop",
    "reset-client": "reset",
    "reset-server": "reset",
    "reset-both": "reset",
    "block-url": "block",
    "block-ip": "block",
    "sinkhole": "block",
}

# PAN-OS THREAT severity → UES severity
_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
}

# PAN-OS SUBTYPE → UES event_action (for traffic logs)
_SUBTYPE_ACTION_MAP: dict[str, str] = {
    "start": "allow",
    "end": "allow",
    "drop": "drop",
    "deny": "deny",
}


def _parse_csv_line(line: str) -> list[str]:
    """Parse a comma-separated line respecting quoted fields."""
    reader = csv.reader(io.StringIO(line))
    try:
        return next(reader)
    except StopIteration:
        return []


class PaloAltoTrafficParser(BaseLogParser):
    """
    Parses Palo Alto PAN-OS TRAFFIC log entries.

    Traffic logs record every connection that passed through the firewall
    including allowed and denied flows.
    """

    @property
    def format_name(self) -> str:
        return "paloalto_traffic"

    @property
    def description(self) -> str:
        return "Palo Alto PAN-OS Traffic log parser (pipe-delimited CSV)"

    @property
    def vendor_hint(self) -> str | None:
        return "palo_alto"

    def can_parse(self, sample: str) -> bool:
        """True if the line is comma-separated and field[3] is 'TRAFFIC'."""
        fields = _parse_csv_line(sample)
        return len(fields) >= 5 and fields[3].strip().upper() == "TRAFFIC"

    def parse_line(self, line: str) -> ParseResult:
        fields = _parse_csv_line(line.strip())

        if len(fields) < _MIN_FIELDS:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"Too few fields: expected >={_MIN_FIELDS}, got {len(fields)}.",
                format_name=self.format_name,
            )

        def _get(idx: int) -> str | None:
            v = fields[idx].strip() if idx < len(fields) else ""
            return v if v and v != "0.0.0.0" and v != "0" else None

        log_type = (fields[3].strip() if len(fields) > 3 else "").upper()
        if log_type != "TRAFFIC":
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"Expected TRAFFIC log type, got '{log_type}'.",
                format_name=self.format_name,
            )

        subtype = (fields[4].strip() if len(fields) > 4 else "").lower()
        action_raw = (_get(30) or "").lower()
        action = _ACTION_MAP.get(action_raw) or _SUBTYPE_ACTION_MAP.get(subtype, "unknown")

        src_port_raw = _get(24)
        dst_port_raw = _get(25)

        result_fields: dict[str, Any] = {
            "vendor": "palo_alto",
            "device_type": "firewall",
            "event_category": "network",
            "timestamp_raw": _get(1),
            "src_ip": _get(7),
            "dst_ip": _get(8),
            "src_port": src_port_raw,
            "dst_port": dst_port_raw,
            "protocol": (_get(29) or "").lower() or None,
            "event_action": action,
            "username": _get(12),
            "severity": "informational",
            "extra_fields": {
                "serial": _get(2),
                "log_type": log_type,
                "subtype": subtype,
                "rule_name": _get(11),
                "application": _get(14),
                "src_zone": _get(16),
                "dst_zone": _get(17),
                "bytes_sent": _get(38),
                "bytes_received": _get(39),
                "packets": _get(40),
            },
        }

        return ParseResult(
            success=True,
            raw_log=line,
            fields=result_fields,
            error=None,
            format_name=self.format_name,
        )


class PaloAltoThreatParser(BaseLogParser):
    """
    Parses Palo Alto PAN-OS THREAT log entries.

    Threat logs are generated when the firewall detects a threat
    (vulnerability exploit, spyware, virus, etc.).
    """

    @property
    def format_name(self) -> str:
        return "paloalto_threat"

    @property
    def description(self) -> str:
        return "Palo Alto PAN-OS Threat log parser (IDS/IPS alerts)"

    @property
    def vendor_hint(self) -> str | None:
        return "palo_alto"

    def can_parse(self, sample: str) -> bool:
        """True if field[3] is 'THREAT'."""
        fields = _parse_csv_line(sample)
        return len(fields) >= 5 and fields[3].strip().upper() == "THREAT"

    def parse_line(self, line: str) -> ParseResult:
        fields = _parse_csv_line(line.strip())

        if len(fields) < _MIN_FIELDS:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"Too few fields: expected >={_MIN_FIELDS}, got {len(fields)}.",
                format_name=self.format_name,
            )

        def _get(idx: int) -> str | None:
            v = fields[idx].strip() if idx < len(fields) else ""
            return v if v and v not in ("0.0.0.0", "0", "unknown", "any") else None

        log_type = (fields[3].strip() if len(fields) > 3 else "").upper()
        if log_type != "THREAT":
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"Expected THREAT log type, got '{log_type}'.",
                format_name=self.format_name,
            )

        action_raw = (_get(30) or "").lower()
        action = _ACTION_MAP.get(action_raw, "alert")

        # Threat-specific fields are at higher indices
        threat_id = _get(58) if len(fields) > 58 else None
        threat_name = _get(59) if len(fields) > 59 else None
        severity_raw = (_get(60) or "").lower() if len(fields) > 60 else ""
        severity = _SEVERITY_MAP.get(severity_raw, "medium")

        result_fields: dict[str, Any] = {
            "vendor": "palo_alto",
            "device_type": "ids_ips",
            "event_category": "threat",
            "timestamp_raw": _get(1),
            "src_ip": _get(7),
            "dst_ip": _get(8),
            "src_port": _get(24),
            "dst_port": _get(25),
            "protocol": (_get(29) or "").lower() or None,
            "event_action": action,
            "username": _get(12),
            "threat_signature_id": threat_id,
            "threat_name": threat_name,
            "severity": severity,
            "severity_label": severity_raw,
            "extra_fields": {
                "serial": _get(2),
                "log_type": log_type,
                "rule_name": _get(11),
                "application": _get(14),
                "src_zone": _get(16),
                "dst_zone": _get(17),
            },
        }

        return ParseResult(
            success=True,
            raw_log=line,
            fields=result_fields,
            error=None,
            format_name=self.format_name,
        )


# Auto-register both parsers on import
register_parser(PaloAltoTrafficParser())
register_parser(PaloAltoThreatParser())
