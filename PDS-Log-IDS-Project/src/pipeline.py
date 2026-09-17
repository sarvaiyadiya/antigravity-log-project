"""
ULPF Pipeline — Universal Log Pre-processing Framework
End-to-end CLI pipeline for log ingestion, normalization, and output.

PS requirements covered
-----------------------
(a) Preserve raw log data — raw_log field in every UnifiedEvent
(b) Extract source-specific attributes — per-parser extraction
(c) Normalize to common taxonomy — UnifiedEvent schema
(d) Maintain traceability — event_uid + record_hash
(e) Plug-and-play onboarding — YAML source configs + parser registry
(f) Unified visibility — aggregated summary after processing
(g) SIEM/Data Lake output — CEF, JSON-Lines, CSV adapters
(h) AI/ML-ready analytics — existing Practicals pipeline (unchanged)
(i) Reduced parser effort — BaseLogParser interface, auto-discovery
(j) Air-gap deployable — Docker container (no runtime internet access)
(k) Container packaging — docker/Dockerfile

Usage
-----
# Auto-detect format, output as JSON-Lines to stdout
python -m ulpf ingest --source configs/sources/cj_log.yaml

# Explicit format + CEF output to file
python -m ulpf ingest --source configs/sources/cef_ids.yaml \
    --output-format cef --output-file outputs/events.cef

# Process with labeling (existing pipeline)
python -m ulpf process --source cj_log --steps clean,label,features

# List registered parsers
python -m ulpf parsers

# Show source config info
python -m ulpf sources
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import yaml

from src.ingestion.base_parser import ParseResult
from src.ingestion.format_detector import detect_format
from src.ingestion.parser_registry import get_registry
from src.ingestion import parsers as _parsers_pkg  # auto-registers all parsers
from src.schema.unified_event import UnifiedEvent
from src.schema.field_mapper import FieldMapper
from src.schema.schema_validator import validate_unified_event, SchemaValidationError
from src.output.output_router import get_writer, OutputRouter

_PROJECT_ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Source configuration loader
# ---------------------------------------------------------------------------

def load_source_config(config_path: str | Path) -> dict[str, Any]:
    """Load and validate a source YAML configuration file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Source config not found: {config_path}")

    with path.open(encoding="utf-8") as file:
        cfg = yaml.safe_load(file) or {}

    required_keys = ("source_id", "log_path")
    missing = [k for k in required_keys if k not in cfg]
    if missing:
        raise ValueError(
            f"Source config {path.name} is missing required keys: {missing}"
        )

    return cfg


# ---------------------------------------------------------------------------
# Core ingestion → normalization → output pipeline
# ---------------------------------------------------------------------------

def ingest(
    source_config: str | Path,
    output_format: str = "json-lines",
    output_file: str | Path | None = None,
    max_events: int | None = None,
    validate: bool = True,
    verbose: bool = True,
) -> dict[str, Any]:
    """
    Run the ULPF ingestion pipeline for one source.

    Parameters
    ----------
    source_config  : Path to the source YAML config file.
    output_format  : "cef", "json-lines", "csv".
    output_file    : Output file path; None → stdout.
    max_events     : Stop after this many events (for testing).
    validate       : Run schema validation on each event.
    verbose        : Print progress to stderr.

    Returns
    -------
    Summary dict with counts and timing.
    """
    start_time = time.perf_counter()
    cfg = load_source_config(source_config)

    source_id = cfg["source_id"]
    log_path = Path(cfg["log_path"])
    format_name = cfg.get("parser")
    encoding = cfg.get("encoding", "utf-8")

    if verbose:
        _log(f"ULPF — Universal Log Pre-processing Framework")
        _log(f"Source   : {source_id}")
        _log(f"Log file : {log_path}")

    # Auto-detect format if not specified
    if not format_name:
        if verbose:
            _log("Format   : auto-detecting…", end=" ")
        format_name = detect_format(log_path, encoding=encoding)
        if not format_name:
            raise RuntimeError(
                f"Could not auto-detect log format for {log_path}. "
                f"Specify 'parser' in the source config."
            )
        if verbose:
            _log(format_name)
    else:
        if verbose:
            _log(f"Format   : {format_name}")

    # Get parser
    registry = get_registry()
    parser = registry.get(format_name)
    if parser is None:
        available = sorted(registry.list_parsers().keys())
        raise RuntimeError(
            f"Parser '{format_name}' not found. "
            f"Available: {available}"
        )

    # Build field mapper
    mapper = FieldMapper.from_yaml(source_config)

    # Output writer
    writer = get_writer(output_format, output=output_file)

    # Counters
    total = 0
    parsed_ok = 0
    parse_errors = 0
    schema_errors = 0

    if verbose:
        _log(f"Output   : {output_format} → {output_file or 'stdout'}")
        _log(f"{'─' * 60}")

    with writer, log_path.open("r", encoding=encoding, errors="replace") as log_file:
        for line in log_file:
            if max_events is not None and total >= max_events:
                break

            stripped = line.rstrip("\r\n")
            if not stripped:
                continue

            total += 1

            # Parse
            result: ParseResult = parser.parse_line(stripped)
            if not result.success:
                parse_errors += 1
                continue

            # Map to canonical schema
            canonical = mapper.map(result.fields)

            # Build UnifiedEvent
            event = UnifiedEvent.create(
                raw_log=stripped,
                format_name=format_name,
                source_id=source_id,
                **canonical,
            )

            # Validate schema
            if validate:
                try:
                    validate_unified_event(event)
                except SchemaValidationError:
                    schema_errors += 1
                    continue

            # Write output
            writer.write(event)
            parsed_ok += 1

    elapsed = time.perf_counter() - start_time
    eps = parsed_ok / elapsed if elapsed > 0 else 0

    summary = {
        "source_id": source_id,
        "format_name": format_name,
        "log_path": str(log_path),
        "output_format": output_format,
        "output_file": str(output_file) if output_file else "stdout",
        "total_lines": total,
        "parsed_ok": parsed_ok,
        "parse_errors": parse_errors,
        "schema_errors": schema_errors,
        "elapsed_seconds": round(elapsed, 3),
        "events_per_second": round(eps, 1),
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    if verbose:
        _log(f"\n{'─' * 60}")
        _log(f"Lines processed : {total:,}")
        _log(f"Events written  : {parsed_ok:,}")
        _log(f"Parse errors    : {parse_errors:,}")
        _log(f"Schema errors   : {schema_errors:,}")
        _log(f"Elapsed         : {elapsed:.2f}s  ({eps:,.0f} events/sec)")

    return summary


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def cli_main(argv: list[str] | None = None) -> int:
    """
    Minimal CLI implementation (no external dependencies required).

    Commands
    --------
    ingest    — run the ingestion pipeline
    parsers   — list registered parsers
    sources   — list configured sources
    """
    args = argv or sys.argv[1:]

    if not args:
        _print_help()
        return 0

    command = args[0].lower()

    if command in ("-h", "--help", "help"):
        _print_help()
        return 0

    if command == "parsers":
        _cmd_parsers()
        return 0

    if command == "sources":
        _cmd_sources()
        return 0

    if command == "ingest":
        return _cmd_ingest(args[1:])

    print(f"[ULPF] Unknown command: {command!r}. Run with --help.", file=sys.stderr)
    return 1


def _cmd_ingest(args: list[str]) -> int:
    """Handle: python -m ulpf ingest [options]"""
    # Parse simple key=value CLI arguments
    opts = _parse_opts(args)

    source = opts.get("--source") or opts.get("-s")
    if not source:
        _error("--source <config.yaml> is required.")
        return 1

    output_format = opts.get("--output-format") or opts.get("-f") or "json-lines"
    output_file = opts.get("--output-file") or opts.get("-o")
    max_events_raw = opts.get("--max-events")
    max_events = int(max_events_raw) if max_events_raw else None
    no_validate = "--no-validate" in args

    try:
        summary = ingest(
            source_config=source,
            output_format=output_format,
            output_file=output_file,
            max_events=max_events,
            validate=not no_validate,
            verbose=True,
        )
        return 0
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        _error(str(exc))
        return 1


def _cmd_parsers() -> None:
    """List all registered parsers."""
    registry = get_registry()
    parsers = registry.list_parsers()
    print(f"\nRegistered parsers ({len(parsers)}):\n")
    for name, parser in sorted(parsers.items()):
        print(f"  {name:<20}  {parser.description}")
    print()


def _cmd_sources() -> None:
    """List configured source YAML files."""
    sources_dir = _PROJECT_ROOT / "configs" / "sources"
    if not sources_dir.exists():
        print("No sources directory found at configs/sources/")
        return

    yaml_files = list(sources_dir.glob("*.yaml")) + list(sources_dir.glob("*.yml"))
    print(f"\nConfigured sources ({len(yaml_files)}):\n")
    for f in sorted(yaml_files):
        try:
            cfg = load_source_config(f)
            print(
                f"  {cfg.get('source_id', f.stem):<25} "
                f"{cfg.get('parser', 'auto'):<20} "
                f"{cfg.get('log_path', '(no path)')}"
            )
        except Exception:
            print(f"  {f.stem:<25} (could not load config)")
    print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_opts(args: list[str]) -> dict[str, str]:
    """Parse simple --key value CLI arguments into a dict."""
    opts: dict[str, str] = {}
    i = 0
    while i < len(args):
        if args[i].startswith("--") or args[i].startswith("-"):
            key = args[i]
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                opts[key] = args[i + 1]
                i += 2
            else:
                opts[key] = "true"
                i += 1
        else:
            i += 1
    return opts


def _log(msg: str, end: str = "\n") -> None:
    print(f"[ULPF] {msg}", file=sys.stderr, end=end)


def _error(msg: str) -> None:
    print(f"[ULPF ERROR] {msg}", file=sys.stderr)


def _print_help() -> None:
    print(
        """
ULPF — Universal Log Pre-processing Framework v1.0

USAGE:
  python -m ulpf <command> [options]

COMMANDS:
  ingest      Ingest and normalize a log file
  parsers     List all registered format parsers
  sources     List configured log sources
  help        Show this help message

INGEST OPTIONS:
  --source, -s      <path>   Source config YAML (required)
  --output-format, -f <fmt>  Output format: json-lines (default), cef, csv
  --output-file, -o <path>   Output file path (default: stdout)
  --max-events       <n>     Stop after n events (for testing)
  --no-validate              Skip schema validation (faster)

EXAMPLES:
  python -m ulpf ingest --source configs/sources/cj_log.yaml
  python -m ulpf ingest --source configs/sources/syslog_firewall.yaml --output-format cef --output-file output/events.cef
  python -m ulpf parsers
  python -m ulpf sources

DOCKER:
  docker-compose up    # Run ULPF in a container
""",
        file=sys.stderr,
    )
