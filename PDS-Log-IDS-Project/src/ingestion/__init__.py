"""
ULPF ingestion package.

Exports the primary ingestion API:
  - BaseLogParser / ParseResult
  - ParserRegistry / get_registry / register_parser
  - format detector
  - cj_parser (existing, unchanged)
"""

from .base_parser import BaseLogParser, ParseResult
from .parser_registry import ParserRegistry, get_registry, register_parser
from .format_detector import detect_format, detect_format_from_text
from .cj_parser import stream_log_events, record_to_mapping  # existing

__all__ = [
    "BaseLogParser",
    "ParseResult",
    "ParserRegistry",
    "get_registry",
    "register_parser",
    "detect_format",
    "detect_format_from_text",
    # existing cj_parser exports
    "stream_log_events",
    "record_to_mapping",
]
