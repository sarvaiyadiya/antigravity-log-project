"""
Format Detector — heuristic auto-detection of log format from sample lines.

Used by the CLI pipeline when no explicit format is specified in the
source config. It reads the first N non-blank lines and asks each
registered parser whether it can handle the sample.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .base_parser import BaseLogParser
from .parser_registry import get_registry


_SAMPLE_LINES = 10   # number of lines to sample for detection


def detect_format(
    file_path: str | Path,
    encoding: str = "utf-8",
    sample_lines: int = _SAMPLE_LINES,
) -> str | None:
    """
    Detect the log format of a file by sampling the first N non-blank lines.

    Returns
    -------
    The format_name string of the detected parser, or None if undetected.
    """
    samples = _sample_file(file_path, encoding, sample_lines)
    if not samples:
        return None

    registry = get_registry()

    # Try each parser against ALL sample lines; pick the one with most hits
    scores: dict[str, int] = {}
    for parser in registry.list_parsers().values():
        hits = sum(1 for line in samples if parser.can_parse(line))
        if hits > 0:
            scores[parser.format_name] = hits

    if not scores:
        return None

    # Specific device/protocol parsers take precedence over generic delimiter fallbacks (csv, json, xml)
    generic_parsers = {"csv", "json", "xml"}
    specific_scores = {k: v for k, v in scores.items() if k not in generic_parsers}
    if specific_scores:
        best_format = max(specific_scores, key=lambda k: specific_scores[k])
    else:
        best_format = max(scores, key=lambda k: scores[k])

    return best_format


def detect_format_from_text(sample: str) -> str | None:
    """
    Detect format from a raw text sample (useful for streaming sources).

    Returns format_name or None.
    """
    registry = get_registry()
    parser = registry.detect(sample)
    return parser.format_name if parser else None


def _sample_file(
    file_path: str | Path,
    encoding: str,
    n: int,
) -> list[str]:
    """Read up to n non-blank lines from the start of a file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    lines: list[str] = []
    try:
        with path.open("r", encoding=encoding, errors="replace") as file:
            for line in file:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
                if len(lines) >= n:
                    break
    except (OSError, UnicodeDecodeError):
        pass

    return lines


def describe_format(format_name: str) -> str:
    """Return a human-readable description of a known format."""
    registry = get_registry()
    parser = registry.get(format_name)
    if parser:
        return parser.description
    return f"Unknown format: {format_name!r}"
