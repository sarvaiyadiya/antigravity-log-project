"""
CEF Parser — Common Event Format (ArcSight CEF).

CEF is widely supported by enterprise security products including:
- Cisco ASA, Firepower
- Palo Alto Networks NGFW
- Check Point firewalls
- Fortinet FortiGate
- ArcSight, QRadar, Splunk (as input format)

Format
------
CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extensions

Example:
  CEF:0|Cisco|ASA|9.14|106023|Deny TCP|6|src=192.168.1.5 spt=44231 dst=10.0.0.1 dpt=443 proto=TCP act=Deny

CEF Extension field reference:
  src/shost  → src_ip / device_hostname
  dst/dhost  → dst_ip
  spt        → src_port
  dpt        → dst_port
  proto      → protocol
  act        → action
  msg        → message
  cs1–cs6    → custom strings (kept in extra_fields)
  cn1–cn3    → custom numbers
  request    → http_url
  requestMethod → http_method
  outcome    → event_action
"""

from __future__ import annotations

import re

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser


# ArcSight CEF header pattern
_CEF_HEADER_RE = re.compile(
    r"^(?:.*?)?CEF:(?P<version>\d+)"
    r"\|(?P<device_vendor>[^|]*)"
    r"\|(?P<device_product>[^|]*)"
    r"\|(?P<device_version>[^|]*)"
    r"\|(?P<signature_id>[^|]*)"
    r"\|(?P<name>[^|]*)"
    r"\|(?P<severity>[^|]*)"
    r"\|(?P<extensions>.*)$",
    re.DOTALL,
)

# CEF extension key=value (handles quoted values and spaces in values)
_CEF_EXT_RE = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)")

# Canonical CEF extension field → UES field name
_CEF_FIELD_MAP: dict[str, str] = {
    "src": "src_ip",
    "shost": "src_ip",
    "dst": "dst_ip",
    "dhost": "dst_ip",
    "spt": "src_port",
    "dpt": "dst_port",
    "proto": "protocol",
    "act": "action",
    "outcome": "event_action",
    "request": "http_url",
    "requestMethod": "http_method",
    "requestClientApplication": "user_agent",
    "suser": "username",
    "duser": "username",
    "msg": "message",
    "reason": "message",
}


class CefParser(BaseLogParser):
    """Parses ArcSight Common Event Format (CEF) log lines."""

    @property
    def format_name(self) -> str:
        return "cef"

    @property
    def description(self) -> str:
        return "CEF parser — ArcSight Common Event Format (CEF:0 / CEF:1)"

    def can_parse(self, sample: str) -> bool:
        """True if line contains the CEF: prefix."""
        return "CEF:" in sample

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()

        match = _CEF_HEADER_RE.match(stripped)
        if not match:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error="Line does not match CEF header pattern.",
                format_name=self.format_name,
            )

        groups = match.groupdict()
        extensions_raw = groups.get("extensions", "") or ""

        # Parse extension key=value pairs
        ext_fields: dict[str, str] = {}
        for key, value in _CEF_EXT_RE.findall(extensions_raw):
            ext_fields[key.strip()] = value.strip()

        # Map CEF field names → UES names
        mapped: dict[str, str] = {}
        extra: dict[str, str] = {}
        for cef_key, cef_val in ext_fields.items():
            ues_key = _CEF_FIELD_MAP.get(cef_key)
            if ues_key:
                mapped[ues_key] = cef_val
            else:
                extra[cef_key] = cef_val

        severity_raw = groups.get("severity", "").strip()

        fields: dict = {
            "cef_version": groups.get("version"),
            "vendor": groups.get("device_vendor"),
            "device_product": groups.get("device_product"),
            "device_version": groups.get("device_version"),
            "threat_signature_id": groups.get("signature_id"),
            "threat_name": groups.get("name"),
            "severity_label": severity_raw,
            "severity": severity_raw,
            **mapped,
        }

        # Numeric severity → pass as-is; text will be converted by FieldMapper
        fields["extra_fields"] = extra

        return ParseResult(
            success=True,
            raw_log=line,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )


# Auto-register on import
register_parser(CefParser())
