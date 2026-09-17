"""
Base Parser — abstract interface that every format-specific parser
must implement to participate in the ULPF plug-and-play registry.

PS requirement (e): "Plug-and-play onboarding of new log sources."
PS requirement (i): "Reduced parser development effort."

Adding a new log source requires:
  1. Subclass BaseLogParser.
  2. Implement the three abstract methods.
  3. Call register_parser(MyParser()) — or place the parser file in
     src/ingestion/parsers/ and it will be auto-discovered.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterator


# ---------------------------------------------------------------------------
# ParseResult — raw parsed fields before schema mapping
# ---------------------------------------------------------------------------

@dataclass
class ParseResult:
    """
    Container returned by a parser for a single log line.

    Attributes
    ----------
    success     : True if the line was parsed successfully.
    raw_log     : The original, unmodified log line.
    fields      : Dict of extracted raw field names → values.
                  Empty on failure.
    error       : Human-readable error message if success is False.
    format_name : Parser format identifier (e.g., "syslog_rfc5424").
    """
    success: bool
    raw_log: str
    fields: dict[str, Any]
    error: str | None
    format_name: str


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class BaseLogParser(ABC):
    """
    Abstract base class for all ULPF format-specific parsers.

    Every parser must implement:
      format_name   — unique string identifier for this format
      can_parse     — heuristic check: can this parser handle a sample?
      parse_line    — parse one log line into a ParseResult

    The parser_registry uses can_parse() for auto-detection and
    routes each line to the correct parser.

    Parsers must be stateless — they do not store per-event state.
    """

    @property
    @abstractmethod
    def format_name(self) -> str:
        """
        Unique, stable identifier for this log format.
        Used as the format_name field in UnifiedEvent.
        Examples: "syslog_rfc5424", "cef", "leef", "snort_alert".
        """

    @property
    def description(self) -> str:
        """Human-readable description of the format this parser handles."""
        return f"{self.format_name} parser"

    @property
    def vendor_hint(self) -> str | None:
        """Optional vendor this parser is primarily designed for."""
        return None

    @abstractmethod
    def can_parse(self, sample: str) -> bool:
        """
        Return True if this parser is likely able to parse the given
        sample text (typically the first non-empty line of a file).

        This is a heuristic, not a guarantee. It is used by format_detector
        to auto-select the correct parser. Parsers should be conservative:
        it is better to return False and let another parser handle the line
        than to return True and produce a malformed result.
        """

    @abstractmethod
    def parse_line(self, line: str) -> ParseResult:
        """
        Parse a single log line and return a ParseResult.

        Must never raise an exception. If the line cannot be parsed,
        return a ParseResult with success=False and a descriptive error.

        The returned fields dict should use source-native field names
        (e.g., "src", "spt", "priority"). The FieldMapper will translate
        them into UES canonical names.
        """

    def parse_lines(self, lines: Iterator[str]) -> Iterator[ParseResult]:
        """
        Convenience generator: parse multiple lines one by one.

        Subclasses may override this for formats that span multiple lines.
        """
        for line in lines:
            stripped = line.rstrip("\r\n")
            if stripped:
                yield self.parse_line(stripped)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(format={self.format_name!r})"
