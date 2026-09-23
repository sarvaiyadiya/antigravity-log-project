"""Parsers sub-package — auto-registers all format parsers on import."""

# Importing each parser module causes its parser instance to be
# registered in the global registry via register_parser().
#
# Registration order matters for auto-detection priority:
# More specific parsers should be imported BEFORE generic fallbacks.

from . import (
    # Specific perimeter device parsers (high priority)
    cisco_asa_parser,       # Cisco ASA / Firepower native syslog (%ASA-)
    paloalto_parser,        # Palo Alto PAN-OS Traffic + Threat logs (CSV)
    windows_event_parser,   # Windows Security Event Log (XML)
    cloudtrail_parser,      # AWS CloudTrail API call records (JSON)
    # Well-defined structured SIEM formats
    cef_parser,
    leef_parser,
    snort_parser,
    # Generic format parsers (fallback)
    syslog_parser,          # RFC 3164 and RFC 5424 (fallback for generic syslog)
    json_parser,            # Generic JSON object / cj.log
    csv_parser,             # Generic CSV
    xml_parser,             # Generic XML fallback
)

__all__ = [
    # Existing
    "syslog_parser",
    "cef_parser",
    "leef_parser",
    "json_parser",
    "snort_parser",
    "csv_parser",
    # New
    "windows_event_parser",
    "cisco_asa_parser",
    "paloalto_parser",
    "cloudtrail_parser",
    "xml_parser",
]
