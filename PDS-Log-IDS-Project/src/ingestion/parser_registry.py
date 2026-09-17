"""
Parser Registry — plug-and-play router for all ULPF format parsers.

PS requirement (e): "Plug-and-play onboarding of new log sources."
PS requirement (i): "Reduced parser development effort."

Usage
-----
# Register a parser
from src.ingestion.parser_registry import register_parser
register_parser(MyCustomParser())

# Auto-detect and parse a line
from src.ingestion.parser_registry import get_registry
result = get_registry().parse(line)

# List all registered parsers
for name, parser in get_registry().list_parsers().items():
    print(name, parser.description)
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Iterator

from .base_parser import BaseLogParser, ParseResult


class ParserRegistry:
    """
    Central registry of all available log format parsers.

    Thread-safety note: parsers are registered at import time and are
    stateless. The registry itself is read-only after startup.
    """

    def __init__(self) -> None:
        self._parsers: dict[str, BaseLogParser] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, parser: BaseLogParser) -> None:
        """
        Add a parser to the registry.

        If a parser with the same format_name already exists it will be
        replaced. This allows patching/upgrading parsers at runtime.
        """
        if not isinstance(parser, BaseLogParser):
            raise TypeError(
                f"Expected a BaseLogParser subclass, got "
                f"{type(parser).__name__}."
            )
        self._parsers[parser.format_name] = parser

    def unregister(self, format_name: str) -> None:
        """Remove a parser by format name (mainly for testing)."""
        self._parsers.pop(format_name, None)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, format_name: str) -> BaseLogParser | None:
        """Return the parser registered under format_name, or None."""
        return self._parsers.get(format_name)

    def get_required(self, format_name: str) -> BaseLogParser:
        """Return parser or raise KeyError if not found."""
        parser = self._parsers.get(format_name)
        if parser is None:
            available = sorted(self._parsers.keys())
            raise KeyError(
                f"No parser registered for format '{format_name}'. "
                f"Available: {available}"
            )
        return parser

    def list_parsers(self) -> dict[str, BaseLogParser]:
        """Return a snapshot of all registered parsers keyed by format_name."""
        return dict(self._parsers)

    def detect(self, sample: str) -> BaseLogParser | None:
        """
        Heuristic auto-detection: return the first parser whose
        can_parse() returns True for the given sample string.

        Parsers are tried in registration order. If ordering matters,
        register higher-priority parsers first.
        """
        for parser in self._parsers.values():
            if parser.can_parse(sample):
                return parser
        return None

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse(
        self,
        line: str,
        format_name: str | None = None,
    ) -> ParseResult:
        """
        Parse a single log line.

        Parameters
        ----------
        line        : The raw log line to parse.
        format_name : If supplied, use this parser directly.
                      If None, auto-detect via can_parse().

        Returns
        -------
        ParseResult — always returned, never raises.
        """
        parser: BaseLogParser | None

        if format_name:
            parser = self._parsers.get(format_name)
            if parser is None:
                return ParseResult(
                    success=False,
                    raw_log=line,
                    fields={},
                    error=f"Parser '{format_name}' is not registered.",
                    format_name=format_name or "unknown",
                )
        else:
            parser = self.detect(line)
            if parser is None:
                return ParseResult(
                    success=False,
                    raw_log=line,
                    fields={},
                    error="No registered parser could handle this line.",
                    format_name="unknown",
                )

        return parser.parse_line(line)

    def parse_stream(
        self,
        lines: Iterator[str],
        format_name: str | None = None,
    ) -> Iterator[ParseResult]:
        """
        Stream-parse multiple lines without loading the file into memory.

        Blank lines are skipped. Errors are yielded as failed ParseResults.
        """
        for line in lines:
            stripped = line.rstrip("\r\n")
            if not stripped:
                continue
            yield self.parse(stripped, format_name=format_name)

    # ------------------------------------------------------------------
    # Auto-discovery
    # ------------------------------------------------------------------

    def auto_discover(self, package_path: str = "src.ingestion.parsers") -> int:
        """
        Import all modules in the parsers sub-package so their
        @register_parser decorators fire automatically.

        Returns the number of newly registered parsers.
        """
        before = len(self._parsers)
        try:
            pkg = importlib.import_module(package_path)
        except ModuleNotFoundError:
            return 0

        pkg_dir = Path(pkg.__file__).parent  # type: ignore[arg-type]

        for module_info in pkgutil.iter_modules([str(pkg_dir)]):
            full_name = f"{package_path}.{module_info.name}"
            try:
                importlib.import_module(full_name)
            except Exception:  # noqa: BLE001
                pass  # silently skip broken optional parsers

        return len(self._parsers) - before

    def __len__(self) -> int:
        return len(self._parsers)

    def __repr__(self) -> str:
        names = sorted(self._parsers.keys())
        return f"ParserRegistry({names})"


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_REGISTRY = ParserRegistry()


def get_registry() -> ParserRegistry:
    """Return the global parser registry singleton."""
    return _REGISTRY


def register_parser(parser: BaseLogParser) -> BaseLogParser:
    """
    Register a parser in the global registry.

    Can be used as a decorator or called directly:

        @register_parser
        class MyParser(BaseLogParser): ...

        register_parser(MyParser())
    """
    if isinstance(parser, type):
        # Used as @register_parser on a class — instantiate it
        instance = parser()
        _REGISTRY.register(instance)
        return parser  # return the class unchanged
    _REGISTRY.register(parser)
    return parser
