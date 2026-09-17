"""
Snort/Suricata Alert Parser — handles IDS/IPS alert output.

Supported formats
-----------------
1. Snort fast alert format:
   01/08-12:34:56.123456  [**] [1:2100498:7] ICMP PING [**] [Classification: Misc] [Priority: 3] {ICMP} 192.168.1.5 -> 10.0.0.1

2. Suricata fast.log format:
   01/08/2024-12:34:56.123456  [Drop] [**] [1:2100498:7] ICMP PING [**] [Classification: Misc activity] [Priority: 3] {ICMP} 192.168.1.5:44231 -> 10.0.0.1:443

3. Snort/Suricata unified2 text (simplified output mode)

These formats are produced by:
- Snort (2.x and 3.x)
- Suricata IDS/IPS
"""

from __future__ import annotations

import re

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser


# Snort/Suricata fast.log format
_FAST_RE = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}(?:/\d{4})?-\d{2}:\d{2}:\d{2}[.\d]*)"
    r"\s+"
    r"(?:\[(?P<action>[^\]]+)\]\s+)?"       # Suricata action (optional)
    r"\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<name>[^\[]+?)\s+"
    r"\[\*\*\]"
    r"(?:\s+\[Classification:\s*(?P<classification>[^\]]*)\])?"
    r"(?:\s+\[Priority:\s*(?P<priority>\d+)\])?"
    r"\s+\{(?P<protocol>\w+)\}\s+"
    r"(?P<src>[\d.]+)(?::(?P<spt>\d+))?"
    r"\s*->\s*"
    r"(?P<dst>[\d.]+)(?::(?P<dpt>\d+))?",
    re.IGNORECASE,
)

_PRIORITY_TO_SEVERITY = {
    "1": "high",
    "2": "medium",
    "3": "low",
    "4": "informational",
}


class SnortParser(BaseLogParser):
    """Parses Snort and Suricata IDS/IPS fast alert log lines."""

    @property
    def format_name(self) -> str:
        return "snort_alert"

    @property
    def description(self) -> str:
        return "Snort/Suricata parser — fast alert format"

    def can_parse(self, sample: str) -> bool:
        """True if line contains the [**] Snort alert marker."""
        return "[**]" in sample

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()
        match = _FAST_RE.search(stripped)

        if not match:
            # Has [**] but pattern didn't match exactly
            if "[**]" in stripped:
                return self._parse_partial(line, stripped)

            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error="Line does not match Snort/Suricata fast alert pattern.",
                format_name=self.format_name,
            )

        groups = match.groupdict()
        priority_raw = groups.get("priority", "") or ""
        action_raw = groups.get("action", "alert") or "alert"

        fields: dict = {
            "timestamp_raw": groups.get("timestamp"),
            "action": action_raw.lower().strip(),
            "threat_signature_id": (
                f"{groups.get('gid', '1')}:{groups.get('sid')}:"
                f"{groups.get('rev', '0')}"
            ),
            "threat_name": (groups.get("name") or "").strip(),
            "event_category": "threat",
            "classification": groups.get("classification"),
            "priority": priority_raw,
            "severity": _PRIORITY_TO_SEVERITY.get(priority_raw, "unknown"),
            "severity_label": f"Priority {priority_raw}" if priority_raw else None,
            "protocol": (groups.get("protocol") or "").lower(),
            "src_ip": groups.get("src"),
            "src_port": groups.get("spt"),
            "dst_ip": groups.get("dst"),
            "dst_port": groups.get("dpt"),
            "vendor": "snort_suricata",
            "device_type": "ids_ips",
        }

        return ParseResult(
            success=True,
            raw_log=line,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )

    def _parse_partial(self, raw: str, stripped: str) -> ParseResult:
        """
        Fallback: extract what we can from a [**]-containing line
        that didn't match the full pattern.
        """
        fields: dict = {
            "raw_message": stripped,
            "event_category": "threat",
            "vendor": "snort_suricata",
            "device_type": "ids_ips",
        }

        # Try to extract SID
        sid_match = re.search(r"\[(\d+):(\d+):(\d+)\]", stripped)
        if sid_match:
            fields["threat_signature_id"] = (
                f"{sid_match.group(1)}:{sid_match.group(2)}:{sid_match.group(3)}"
            )

        # Try to extract name between [**] markers
        name_match = re.search(r"\[\*\*\]\s+(?:\[\d+:\d+:\d+\]\s+)?([^\[]+?)\s+\[\*\*\]", stripped)
        if name_match:
            fields["threat_name"] = name_match.group(1).strip()

        return ParseResult(
            success=True,
            raw_log=raw,
            fields=fields,
            error="Partial parse — some fields may be missing.",
            format_name=self.format_name,
        )


# Auto-register on import
register_parser(SnortParser())
