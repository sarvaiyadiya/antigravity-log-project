"""
Cisco ASA Parser — native Cisco ASA / Cisco Firepower syslog message format.

Cisco ASA firewalls emit syslog-wrapped messages with the format:
  %ASA-SEVERITY-MSGID: message_text

They typically arrive wrapped in a RFC 3164 syslog envelope:
  <PRIORITY>Timestamp Hostname %ASA-SEVERITY-MSGID: message_text

This parser handles both the bare %ASA format and the syslog-wrapped form.

Common Message IDs
------------------
  106001  — Inbound TCP connection denied (no access-group)
  106006  — Deny inbound UDP
  106007  — Deny inbound UDP
  106010  — Deny inbound TCP
  106014  — Deny inbound ICMP
  106015  — Deny TCP (no connection)
  106020  — Deny IP teardrop fragment
  106021  — Deny TCP RST flood
  106023  — Deny by access-group
  106100  — Access-list log
  110002  — Failed to locate egress interface
  302013  — TCP connection built
  302014  — TCP connection torn down
  302015  — UDP connection built
  302016  — UDP connection torn down
  305011  — Built dynamic NAT translation
  305012  — Teardown dynamic NAT translation
  710003  — TCP access denied (no matching ACE)
  719022  — Group/User/IP AAA (authentication/authorization) failure
  733100  — Object drop-rate exceeded

PS requirements covered
-----------------------
(b) Extract source-specific attributes — message_id, src/dst IP/port, protocol
(c) Normalize to common taxonomy — mapped to UnifiedEvent
(e) Plug-and-play — registered via register_parser()
"""

from __future__ import annotations

import re
from typing import Any

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser


# Matches the %ASA-SEVERITY-MSGID: prefix (with optional syslog header before it)
_ASA_DETECT_RE = re.compile(r"%ASA-\d+-\d+:", re.IGNORECASE)

# Full ASA message: strips optional syslog header, captures severity + msgid + body
_ASA_MAIN_RE = re.compile(
    r"(?:.*?)?%ASA-(?P<severity>\d+)-(?P<msg_id>\d+):\s*(?P<body>.*)",
    re.DOTALL | re.IGNORECASE,
)

# Extracts IP:port pair from "protocol src IFACE:IP/PORT dst IFACE:IP/PORT"
_ADDR_RE = re.compile(
    r"(?P<iface>\w+):(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<port>\d+)",
    re.IGNORECASE,
)

# Extracts standalone IPs when no port is present
_IP_ONLY_RE = re.compile(
    r"(?P<iface>\w+):(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)

# Protocol pattern: "tcp", "udp", "icmp"
_PROTO_RE = re.compile(r"\b(tcp|udp|icmp|gre|esp|ah)\b", re.IGNORECASE)

# Action keywords in the body text
_ACTION_DENY_RE = re.compile(r"\b(deny|denied|drop|block|reject|teardown)\b", re.IGNORECASE)
_ACTION_ALLOW_RE = re.compile(r"\b(permit|allow|built|established|translated)\b", re.IGNORECASE)

# Syslog numeric severity → text
_SYSLOG_SEVERITY: dict[str, str] = {
    "0": "emergency",
    "1": "alert",
    "2": "critical",
    "3": "error",
    "4": "warning",
    "5": "notice",
    "6": "informational",
    "7": "debug",
}

# ASA MessageID prefix → threat name
_MSGID_PREFIX_NAMES: dict[str, str] = {
    "106": "ACL Deny",
    "302": "NAT/Connection",
    "305": "Dynamic Translation",
    "710": "Access Denied",
    "719": "AAA Failure",
    "733": "Rate Limit Exceeded",
    "407": "No Route to Host",
    "313": "ICMP Unreachable",
    "402": "IKE/IPsec Error",
    "609": "Local Host Removed",
}


def _infer_threat_name(msg_id: str) -> str:
    """Return a human-readable threat name from the message ID prefix."""
    prefix = msg_id[:3] if len(msg_id) >= 3 else msg_id
    return _MSGID_PREFIX_NAMES.get(prefix, f"ASA Message {msg_id}")


class CiscoAsaParser(BaseLogParser):
    """
    Parses Cisco ASA / Firepower native syslog messages.

    Handles bare %ASA-n-NNNNNN: format as well as the common
    syslog-header-prefixed variant.
    """

    @property
    def format_name(self) -> str:
        return "cisco_asa"

    @property
    def description(self) -> str:
        return "Cisco ASA/Firepower parser — %ASA-SEVERITY-MSGID: format"

    @property
    def vendor_hint(self) -> str | None:
        return "cisco"

    def can_parse(self, sample: str) -> bool:
        """True if the line contains a %ASA-n-NNNNNN: marker."""
        return bool(_ASA_DETECT_RE.search(sample))

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()

        match = _ASA_MAIN_RE.search(stripped)
        if not match:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error="Line does not contain a %ASA-SEVERITY-MSGID: pattern.",
                format_name=self.format_name,
            )

        severity_num = match.group("severity")
        msg_id = match.group("msg_id")
        body = match.group("body").strip()

        fields: dict[str, Any] = {
            "vendor": "cisco",
            "device_type": "firewall",
            "threat_signature_id": msg_id,
            "threat_name": _infer_threat_name(msg_id),
            "severity": _SYSLOG_SEVERITY.get(severity_num, "unknown"),
            "severity_label": severity_num,
            "event_category": "network",
        }

        # Determine action from body text
        if _ACTION_DENY_RE.search(body):
            fields["event_action"] = "deny"
        elif _ACTION_ALLOW_RE.search(body):
            fields["event_action"] = "allow"
        else:
            fields["event_action"] = "unknown"

        # Extract protocol
        proto_m = _PROTO_RE.search(body)
        if proto_m:
            fields["protocol"] = proto_m.group(1).lower()

        # Extract IP:port pairs (first = src, second = dst)
        addr_matches = _ADDR_RE.findall(body)
        if len(addr_matches) >= 1:
            _, src_ip, src_port = addr_matches[0]
            fields["src_ip"] = src_ip
            fields["src_port"] = src_port
        if len(addr_matches) >= 2:
            _, dst_ip, dst_port = addr_matches[1]
            fields["dst_ip"] = dst_ip
            fields["dst_port"] = dst_port

        # Fallback: try IP-only (no port)
        if "src_ip" not in fields:
            ip_only = _IP_ONLY_RE.findall(body)
            if len(ip_only) >= 1:
                fields["src_ip"] = ip_only[0][1]
            if len(ip_only) >= 2:
                fields["dst_ip"] = ip_only[1][1]

        # Put raw body in extra_fields for forensics
        fields["extra_fields"] = {"asa_body": body, "asa_msg_id": msg_id}

        return ParseResult(
            success=True,
            raw_log=line,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )


# Auto-register on import
register_parser(CiscoAsaParser())
