"""Parsers sub-package — auto-registers all format parsers on import."""

# Importing each parser module causes its parser instance to be
# registered in the global registry via register_parser().

from . import (
    syslog_parser,
    cef_parser,
    leef_parser,
    json_parser,
    snort_parser,
    csv_parser,
)

__all__ = [
    "syslog_parser",
    "cef_parser",
    "leef_parser",
    "json_parser",
    "snort_parser",
    "csv_parser",
]
