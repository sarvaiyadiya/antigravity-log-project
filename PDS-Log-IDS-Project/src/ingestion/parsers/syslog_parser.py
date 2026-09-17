"""
Syslog Parser — RFC 3164 and RFC 5424
Handles logs from firewalls, routers, IDS/IPS, and most network devices
that use standard syslog output.

Supported variants:
  • RFC 3164  — <PRI>TIMESTAMP HOSTNAME TAG: MSG
  • RFC 5424  — <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID MSG
  • RFC 3164 with year  — <PRI>Mon DD YYYY HH:MM:SS HOSTNAME ... (FortiGate, some Cisco)
  • key=value pairs embedded in the message body (Palo Alto, pfSense, Fortinet)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser

# ─── Regex patterns ────────────────────────────────────────────────────────────

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID MSG
_RFC5424_RE = re.compile(
    r"^<(?P<priority>\d{1,3})>"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<proc_id>\S+)\s+"
    r"(?P<msg_id>\S+)\s+"
    r"(?P<message>.*)$",
    re.DOTALL,
)

# RFC 3164 (standard): <PRI>Mon DD HH:MM:SS HOSTNAME TAG: MSG
_RFC3164_RE = re.compile(
    r"^<(?P<priority>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<tag>[^\s:]+)(?::\s*)?"
    r"(?P<message>.*)$",
    re.DOTALL,
)

# RFC 3164 with year (FortiGate, some Cisco variants)
_RFC3164_YEAR_RE = re.compile(
    r"^<(?P<priority>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<tag>[^\s:]+)?(?::\s*)?"
    r"(?P<message>.*)$",
    re.DOTALL,
)

# Key=value pairs often embedded in syslog messages
_KV_RE = re.compile(r'(\w+)=(["\']?)([^"\'=,\s]+)\2')

# Common network fields in syslog messages
_IP_PORT_RE = re.compile(
    r"(?:src|source|from)[=:\s]+(?P<src_ip>[\d.]+)(?:[:/](?P<src_port>\d+))?"
    r"|(?:dst|dest|destination|to)[=:\s]+(?P<dst_ip>[\d.]+)(?:[:/](?P<dst_port>\d+))?"
    r"|(?P<lone_ip>(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?!\d))",
    re.IGNORECASE,
)

# Syslog severity code → name
_SYSLOG_SEVERITY_MAP = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "informational", 7: "debug",
}

# Severity name → ULPF numeric severity (0–10)
_SEVERITY_SCORE = {
    "emergency": 10, "alert": 9, "critical": 8, "error": 7,
    "warning": 6, "notice": 5, "informational": 4, "debug": 2,
}

# Action keywords in message
_ACTION_RE = re.compile(
    r"\b(?P<action>deny|denied|allow|allowed|accept|accepted|drop|dropped|block|blocked|reject|rejected|pass)\b",
    re.IGNORECASE,
)


def _decode_priority(priority: int) -> tuple[int, int]:
    """Return (facility_code, severity_code) from a syslog PRI value."""
    return priority >> 3, priority & 0x07


class SyslogParser(BaseLogParser):
    """Parser for RFC 3164 and RFC 5424 syslog messages."""

    @property
    def format_name(self) -> str:
        return "syslog"

    @property
    def description(self) -> str:
        return "Syslog parser — RFC 3164 and RFC 5424"

    def can_parse(self, sample: str) -> bool:
        """Syslog lines typically start with <PRI> (1–5 chars)."""
        stripped = sample.strip()
        if not stripped.startswith("<"):
            return False
        close = stripped.find(">")
        if close < 1 or close > 5:
            return False
        try:
            pri = int(stripped[1:close])
            return 0 <= pri <= 191
        except ValueError:
            return False

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()

        # Try RFC 5424 first (has explicit version number after PRI)
        match = _RFC5424_RE.match(stripped)
        if match:
            return self._from_rfc5424(stripped, match)

        # Try RFC 3164 (standard timestamp)
        match = _RFC3164_RE.match(stripped)
        if match:
            return self._from_rfc3164(stripped, match)

        # Try RFC 3164 with year in timestamp (FortiGate, some Cisco)
        match = _RFC3164_YEAR_RE.match(stripped)
        if match:
            return self._from_rfc3164(stripped, match)

        # Has PRI but non-standard format — extract what we can
        if stripped.startswith("<"):
            return self._parse_lenient(stripped, line)

        return ParseResult(
            success=False,
            raw_log=line,
            fields={},
            error="Not a recognised syslog format.",
            format_name=self.format_name,
        )

    # ── RFC 5424 builder ──────────────────────────────────────────────────────

    def _from_rfc5424(self, stripped: str, m: re.Match) -> ParseResult:
        priority = int(m.group("priority"))
        facility, sev_code = _decode_priority(priority)
        sev_name = _SYSLOG_SEVERITY_MAP.get(sev_code, "unknown")

        message = m.group("message").strip()
        fields: dict[str, Any] = {
            "priority": priority,
            "facility": facility,
            "syslog_severity": sev_name,
            "severity": _SEVERITY_SCORE.get(sev_name, 0),
            "severity_label": sev_name,
            "timestamp_raw": m.group("timestamp"),
            "device_hostname": m.group("hostname"),
            "app_name": m.group("app_name"),
            "message": message,
        }

        fields.update(self._extract_kv(message))
        fields.update(self._extract_network_fields(message))
        fields.update(self._extract_action(message))

        return ParseResult(
            success=True,
            raw_log=stripped,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )

    # ── RFC 3164 builder ──────────────────────────────────────────────────────

    def _from_rfc3164(self, stripped: str, m: re.Match) -> ParseResult:
        priority = int(m.group("priority"))
        facility, sev_code = _decode_priority(priority)
        sev_name = _SYSLOG_SEVERITY_MAP.get(sev_code, "unknown")

        message = m.group("message").strip() if "message" in m.groupdict() else ""
        tag = (m.group("tag") or "").strip() if "tag" in m.groupdict() else ""

        fields: dict[str, Any] = {
            "priority": priority,
            "facility": facility,
            "syslog_severity": sev_name,
            "severity": _SEVERITY_SCORE.get(sev_name, 0),
            "severity_label": sev_name,
            "timestamp_raw": m.group("timestamp"),
            "device_hostname": m.group("hostname"),
            "tag": tag,
            "message": f"{tag}: {message}".strip(": "),
        }

        combined = f"{tag} {message}"
        fields.update(self._extract_kv(combined))
        fields.update(self._extract_network_fields(combined))
        fields.update(self._extract_action(combined))

        return ParseResult(
            success=True,
            raw_log=stripped,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )

    # ── Lenient (last-resort) builder ─────────────────────────────────────────

    def _parse_lenient(self, stripped: str, raw: str) -> ParseResult:
        """Parse syslog lines with non-standard format — extract what we can."""
        fields: dict[str, Any] = {"message": stripped}

        pri_match = re.match(r"^<(\d{1,3})>", stripped)
        if pri_match:
            priority = int(pri_match.group(1))
            facility, sev_code = _decode_priority(priority)
            sev_name = _SYSLOG_SEVERITY_MAP.get(sev_code, "unknown")
            fields.update({
                "priority": priority,
                "facility": facility,
                "syslog_severity": sev_name,
                "severity": _SEVERITY_SCORE.get(sev_name, 0),
                "severity_label": sev_name,
            })

        fields.update(self._extract_kv(stripped))
        fields.update(self._extract_network_fields(stripped))
        fields.update(self._extract_action(stripped))

        return ParseResult(
            success=True,
            raw_log=raw,
            fields=fields,
            error="Non-standard syslog format — lenient parse applied.",
            format_name=self.format_name,
        )

    # ── Field extractors ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_kv(text: str) -> dict[str, Any]:
        """Extract key=value pairs from syslog message body."""
        kv: dict[str, Any] = {}
        # Direct UES field names from k=v pairs
        ues_kv_map = {
            "src": "src_ip", "source": "src_ip", "sip": "src_ip",
            "dst": "dst_ip", "dest": "dst_ip", "dip": "dst_ip",
            "spt": "src_port", "sport": "src_port", "srcport": "src_port",
            "dpt": "dst_port", "dport": "dst_port", "dstport": "dst_port",
            "proto": "protocol", "protocol": "protocol",
            "action": "event_action", "act": "event_action",
            "user": "username", "usrname": "username", "suser": "username",
            "url": "http_url", "request": "http_url",
            "method": "http_method", "requestMethod": "http_method",
        }
        for m in _KV_RE.finditer(text):
            raw_key = m.group(1).lower()
            val = m.group(3)
            ues_key = ues_kv_map.get(raw_key, raw_key)
            kv[ues_key] = val
        return kv

    @staticmethod
    def _extract_network_fields(text: str) -> dict[str, Any]:
        """Extract IP addresses and port numbers from message text."""
        fields: dict[str, Any] = {}
        ips_found: list[str] = []
        for m in _IP_PORT_RE.finditer(text):
            if m.group("src_ip"):
                fields["src_ip"] = m.group("src_ip")
                if m.group("src_port"):
                    fields["src_port"] = int(m.group("src_port"))
            elif m.group("dst_ip"):
                fields["dst_ip"] = m.group("dst_ip")
                if m.group("dst_port"):
                    fields["dst_port"] = int(m.group("dst_port"))
            elif m.group("lone_ip"):
                ips_found.append(m.group("lone_ip"))
        # Assign lone IPs if src/dst not already found
        if ips_found and "src_ip" not in fields:
            fields["src_ip"] = ips_found[0]
        if len(ips_found) > 1 and "dst_ip" not in fields:
            fields["dst_ip"] = ips_found[1]
        return fields

    @staticmethod
    def _extract_action(text: str) -> dict[str, Any]:
        """Extract allow/deny action keywords from message."""
        m = _ACTION_RE.search(text)
        if m:
            return {"event_action": m.group("action").lower()}
        return {}


# ── Register ──────────────────────────────────────────────────────────────────
register_parser(SyslogParser())
