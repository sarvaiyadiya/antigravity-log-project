"""
Windows Event XML Parser — parses Windows Security Event Log entries in XML format.

Windows Event Log is the primary log source for:
- User authentication events (logon, logoff, failed logon)
- Account management (creation, deletion, lockout)
- Process creation and execution tracking
- Object access and privilege use

Format
------
Each event is wrapped in an <Event> element with two main sections:
  <System>    — metadata: EventID, TimeCreated, Computer, Level, Channel
  <EventData> — event-specific key-value pairs (<Data Name="key">value</Data>)

Common Security EventIDs
------------------------
  4624  — Successful logon
  4625  — Failed logon attempt
  4648  — Logon with explicit credentials
  4672  — Special privileges assigned to new logon
  4688  — Process creation
  4720  — User account created
  4724  — Password reset attempt
  4740  — User account locked out
  4776  — NTLM authentication attempt
  4768  — Kerberos TGT requested
  4769  — Kerberos service ticket requested

PS requirements covered
-----------------------
(b) Extract source-specific attributes — EventID, TimeCreated, EventData fields
(c) Normalize to common taxonomy — mapped to UnifiedEvent
(e) Plug-and-play — registered via register_parser()
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from src.ingestion.base_parser import BaseLogParser, ParseResult
from src.ingestion.parser_registry import register_parser

# Windows Event XML namespace
_WEV_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS = {"e": _WEV_NS}

# EventID → threat_name label for common security events
_EVENTID_NAMES: dict[str, str] = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4634": "Logoff",
    "4647": "User Initiated Logoff",
    "4648": "Logon With Explicit Credentials",
    "4672": "Special Privileges Assigned",
    "4688": "Process Created",
    "4698": "Scheduled Task Created",
    "4700": "Scheduled Task Enabled",
    "4702": "Scheduled Task Updated",
    "4720": "User Account Created",
    "4722": "User Account Enabled",
    "4724": "Password Reset Attempt",
    "4725": "User Account Disabled",
    "4726": "User Account Deleted",
    "4740": "User Account Locked Out",
    "4756": "Member Added to Security Group",
    "4768": "Kerberos TGT Requested",
    "4769": "Kerberos Service Ticket Requested",
    "4776": "NTLM Authentication",
    "5140": "Network Share Accessed",
    "5156": "Windows Filtering Platform Connection Permitted",
    "5157": "Windows Filtering Platform Connection Blocked",
}

# EventID → event_action mapping
_EVENTID_ACTION: dict[str, str] = {
    "4624": "allow",
    "4625": "deny",
    "4648": "allow",
    "5156": "allow",
    "5157": "deny",
    "4740": "block",
}

# EventID → severity mapping
_EVENTID_SEVERITY: dict[str, str] = {
    "4625": "medium",    # Failed logon
    "4740": "high",      # Account lockout
    "4688": "low",       # Process creation
    "4720": "medium",    # Account created
    "4726": "medium",    # Account deleted
    "5157": "medium",    # Connection blocked
}

# Detect a Windows Event XML line
_WIN_EVENT_DETECT = re.compile(
    r"<Event\b|xmlns=\"http://schemas\.microsoft\.com/win/2004/08/events",
    re.IGNORECASE,
)


class WindowsEventParser(BaseLogParser):
    """
    Parses Windows Security Event Log entries in XML format.

    Handles both:
    - Single <Event>...</Event> per line
    - Multi-line XML (attempts to parse the full line as-is)
    """

    @property
    def format_name(self) -> str:
        return "windows_event_xml"

    @property
    def description(self) -> str:
        return "Windows Event Log XML parser (Security, System, Application channels)"

    def can_parse(self, sample: str) -> bool:
        """True if the sample looks like Windows Event XML."""
        return bool(_WIN_EVENT_DETECT.search(sample))

    def parse_line(self, line: str) -> ParseResult:
        stripped = line.strip()

        try:
            root = ET.fromstring(stripped)
        except ET.ParseError as exc:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error=f"XML parse error: {exc}",
                format_name=self.format_name,
            )

        # Normalize namespace: try with and without namespace prefix
        def _find(element: ET.Element, path: str) -> ET.Element | None:
            result = element.find(f"e:{path}", _NS)
            if result is None:
                result = element.find(path)
            return result

        def _findall(element: ET.Element, path: str) -> list[ET.Element]:
            result = element.findall(f"e:{path}", _NS)
            if not result:
                result = element.findall(path)
            return result

        system = _find(root, "System")
        if system is None:
            return ParseResult(
                success=False,
                raw_log=line,
                fields={},
                error="No <System> element found in Windows Event XML.",
                format_name=self.format_name,
            )

        # --- Extract System fields ---
        fields: dict[str, Any] = {}

        event_id_el = _find(system, "EventID")
        event_id = event_id_el.text.strip() if event_id_el is not None and event_id_el.text else None
        fields["threat_signature_id"] = event_id
        fields["threat_name"] = _EVENTID_NAMES.get(event_id or "", f"EventID {event_id}")
        fields["event_action"] = _EVENTID_ACTION.get(event_id or "", "unknown")
        fields["severity"] = _EVENTID_SEVERITY.get(event_id or "", "informational")

        time_el = _find(system, "TimeCreated")
        if time_el is not None:
            fields["timestamp_raw"] = time_el.get("SystemTime") or time_el.text

        computer_el = _find(system, "Computer")
        fields["device_hostname"] = computer_el.text.strip() if computer_el is not None and computer_el.text else None

        channel_el = _find(system, "Channel")
        fields["log_channel"] = channel_el.text.strip() if channel_el is not None and channel_el.text else None

        level_el = _find(system, "Level")
        fields["event_level"] = level_el.text.strip() if level_el is not None and level_el.text else None

        provider_el = _find(system, "Provider")
        if provider_el is not None:
            fields["vendor"] = provider_el.get("Name") or provider_el.get("name")

        # --- Extract EventData fields ---
        event_data = _find(root, "EventData")
        extra: dict[str, Any] = {}

        if event_data is not None:
            for data_el in _findall(event_data, "Data"):
                name = data_el.get("Name") or data_el.get("name", "")
                value = (data_el.text or "").strip()
                if not value or value == "-":
                    continue

                name_lower = name.lower()

                # Map well-known EventData fields to UES
                if name_lower in ("targetusername", "subjectusername", "accountname"):
                    fields["username"] = value
                elif name_lower in ("ipaddress", "sourceaddress", "workstationname"):
                    if value not in ("-", "::1", "127.0.0.1"):
                        fields["src_ip"] = value
                elif name_lower in ("ipport", "sourceport"):
                    fields["src_port"] = value
                elif name_lower == "newprocessname":
                    fields["process_name"] = value
                    extra[name] = value
                elif name_lower == "commandline":
                    fields["command_line"] = value
                    extra[name] = value
                else:
                    extra[name] = value

        fields["extra_fields"] = extra
        fields["device_type"] = "endpoint"
        fields["event_category"] = "authentication"

        return ParseResult(
            success=True,
            raw_log=line,
            fields=fields,
            error=None,
            format_name=self.format_name,
        )


# Auto-register on import
register_parser(WindowsEventParser())
