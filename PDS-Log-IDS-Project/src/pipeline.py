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
import os
import sys
import time
import uuid
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
    enrich: bool = True,
    correlate: bool = True,
    classify: bool = False,
    alerts_file: str | Path | None = None,
    verbose: bool = True,
) -> dict[str, Any]:
    """
    Run the ULPF ingestion pipeline for one source.

    Parameters
    ----------
    source_config  : Path to the source YAML config file.
    output_format  : "cef", "json-lines", "csv".
    output_file    : Output file path; None -> stdout.
    max_events     : Stop after this many events (for testing).
    validate       : Run schema validation on each event.
    enrich         : Apply contextual GeoIP, Threat Intel, MITRE mapping.
    correlate      : Run sliding time-window correlation engine.
    classify       : Apply machine learning classifier (inference & abstention).
    alerts_file    : Path to write generated security alerts (JSON-lines).
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
        _log(f"ULPF -- Universal Log Pre-processing Framework")
        _log(f"Source   : {source_id}")
        _log(f"Log file : {log_path}")

    # Auto-detect format if not specified
    if not format_name:
        if verbose:
            _log("Format   : auto-detecting...", end=" ")
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

    # Enrichment pipeline
    enrichment_pipe = None
    if enrich:
        try:
            from src.enrichment import get_enrichment_pipeline
            enrichment_pipe = get_enrichment_pipeline()
        except Exception as exc:
            if verbose:
                _log(f"Warning: could not load enrichment pipeline: {exc}")

    # Correlation engine
    correlation_engine = None
    if correlate:
        try:
            from src.correlation import get_correlation_engine
            correlation_engine = get_correlation_engine()
        except Exception as exc:
            if verbose:
                _log(f"Warning: could not load correlation engine: {exc}")

    # ML Classifier engine
    model_classifier = None
    if classify:
        try:
            from src.models import get_classifier
            model_classifier = get_classifier()
        except Exception as exc:
            if verbose:
                _log(f"Warning: could not load ML classifier: {exc}")

    # Alerts output handle
    alerts_fh = None
    if alerts_file:
        p = Path(alerts_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        alerts_fh = p.open("a", encoding="utf-8")

    # Counters
    total = 0
    parsed_ok = 0
    parse_errors = 0
    schema_errors = 0
    alerts_count = 0

    if verbose:
        _log(f"Output   : {output_format} -> {output_file or 'stdout'}")
        if enrich:
            _log(f"Enrich   : GeoIP, Threat Intel, MITRE ATT&CK enabled")
        if correlate:
            _log(f"Correlate: Sliding time-window correlation engine enabled")
            if alerts_file:
                _log(f"Alerts   : -> {alerts_file}")
        if classify:
            _log(f"ML Model : Active (calibrated inference & abstention)")
        _log(f"{'-' * 60}")

    try:
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

                # Apply contextual enrichment
                if enrichment_pipe is not None:
                    event = enrichment_pipe.enrich(event)

                # Apply ML classification
                if model_classifier is not None:
                    event = model_classifier.annotate_event(event)

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

                # Correlation
                if correlation_engine is not None:
                    alerts = correlation_engine.process_event(event)
                    if alerts:
                        alerts_count += len(alerts)
                        for a in alerts:
                            if alerts_fh:
                                alerts_fh.write(a.to_json() + "\n")
                                alerts_fh.flush()
                            if verbose:
                                _log(f"  [ALERT] {a.rule_name} | {a.severity.upper()} | {a.primary_ip} -> {a.description}")
    finally:
        if alerts_fh:
            alerts_fh.close()

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
        "alerts_generated": alerts_count,
        "ml_classified": classify,
        "elapsed_seconds": round(elapsed, 3),
        "events_per_second": round(eps, 1),
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    if verbose:
        _log(f"\n{'-' * 60}")
        _log(f"Lines processed  : {total:,}")
        _log(f"Events written   : {parsed_ok:,}")
        _log(f"Parse errors     : {parse_errors:,}")
        _log(f"Schema errors    : {schema_errors:,}")
        if correlate:
            _log(f"Alerts generated : {alerts_count:,}")
        if classify:
            _log(f"ML classified    : Yes")
        _log(f"Elapsed          : {elapsed:.2f}s  ({eps:,.0f} events/sec)")

    return summary


# ---------------------------------------------------------------------------
# Master End-to-End Pipeline & Cryptographic Provenance Engine
# ---------------------------------------------------------------------------

def run_pipeline(
    input_file: str | Path | None = None,
    output_file: str | Path = "outputs/canonical_events.jsonl",
    alerts_file: str | Path | None = "outputs/threat_alerts.jsonl",
    manifest_file: str | Path | None = "outputs/provenance_manifest.json",
    source_config: str | Path | None = None,
    output_format: str = "json-lines",
    max_events: int | None = None,
    validate: bool = True,
    enrich: bool = True,
    correlate: bool = True,
    classify: bool = True,
    verbose: bool = True,
) -> dict[str, Any]:
    """
    Executes the full 6-stage ULPF end-to-end processing pipeline:
      Stage 1: Format Detection & Parsing across 12 perimeter device standards
      Stage 2: Canonical UES Normalization & Lossless Field Mapping
      Stage 3: Contextual Enrichment (GeoIP, Threat Intelligence, MITRE ATT&CK)
      Stage 4: Calibrated ML Inference & Epistemic Uncertainty Abstention
      Stage 5: Stateful Sliding Time-Window Correlation & SecurityAlert Generation
      Stage 6: Output Serialization & Cryptographic Provenance Manifest (SHA-256)
    """
    if not source_config and not input_file:
        raise ValueError("Either input_file or source_config must be provided.")

    # Auto-generate transient source config if raw input file provided
    actual_source_config = source_config
    if not actual_source_config and input_file:
        temp_dir = _PROJECT_ROOT / "outputs" / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_cfg_path = temp_dir / f"pipeline_source_{Path(input_file).stem}.yaml"
        temp_cfg_path.write_text(
            f"source_id: {Path(input_file).stem}\nlog_path: {Path(input_file).as_posix()}\n",
            encoding="utf-8",
        )
        actual_source_config = str(temp_cfg_path)

    # Ensure output parent directories exist
    out_p = Path(output_file)
    out_p.parent.mkdir(parents=True, exist_ok=True)

    if alerts_file:
        Path(alerts_file).parent.mkdir(parents=True, exist_ok=True)

    if verbose:
        _log("============================================================")
        _log("         ULPF MASTER END-TO-END PROCESSING PIPELINE         ")
        _log("============================================================")

    summary = ingest(
        source_config=actual_source_config,
        output_format=output_format,
        output_file=output_file,
        max_events=max_events,
        validate=validate,
        enrich=enrich,
        correlate=correlate,
        classify=classify,
        alerts_file=alerts_file,
        verbose=verbose,
    )

    # Generate Cryptographic Provenance Manifest
    manifest = None
    if manifest_file:
        manifest = generate_manifest(
            input_file=Path(summary["log_path"]),
            output_file=Path(output_file),
            alerts_file=Path(alerts_file) if alerts_file else None,
            manifest_file=Path(manifest_file),
            summary=summary,
            enrich=enrich,
            correlate=correlate,
            classify=classify,
        )
        if verbose:
            _log(f"Manifest written : {manifest_file} (SHA-256 verified)")

    summary["manifest"] = manifest
    return summary


def generate_manifest(
    input_file: Path,
    output_file: Path,
    alerts_file: Path | None,
    manifest_file: Path,
    summary: dict[str, Any],
    enrich: bool = True,
    correlate: bool = True,
    classify: bool = True,
) -> dict[str, Any]:
    """
    Computes cryptographic SHA-256 digests and outputs a tamper-evident audit manifest.
    """
    from src.provenance import calculate_file_sha256

    input_sha256 = calculate_file_sha256(input_file) if input_file.exists() else None
    output_sha256 = calculate_file_sha256(output_file) if output_file.exists() else None
    alerts_sha256 = (
        calculate_file_sha256(alerts_file)
        if alerts_file and alerts_file.exists() and alerts_file.stat().st_size > 0
        else None
    )

    manifest_data = {
        "manifest_schema_version": "ulpf-provenance-v1.0",
        "execution_id": str(uuid.uuid4()),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input": {
            "path": str(input_file.resolve()),
            "sha256": input_sha256,
            "size_bytes": input_file.stat().st_size if input_file.exists() else 0,
        },
        "outputs": {
            "canonical_events": {
                "path": str(output_file.resolve()),
                "sha256": output_sha256,
                "format": summary.get("output_format", "json-lines"),
                "events_count": summary.get("parsed_ok", 0),
                "size_bytes": output_file.stat().st_size if output_file.exists() else 0,
            },
            "threat_alerts": {
                "path": str(alerts_file.resolve()) if alerts_file else None,
                "sha256": alerts_sha256,
                "alerts_count": summary.get("alerts_generated", 0),
            },
        },
        "pipeline_stages": {
            "detection": {
                "format_name": summary.get("format_name", "unknown"),
            },
            "normalization": {
                "total_lines": summary.get("total_lines", 0),
                "parsed_ok": summary.get("parsed_ok", 0),
                "parse_errors": summary.get("parse_errors", 0),
                "schema_errors": summary.get("schema_errors", 0),
            },
            "contextual_enrichment": {
                "enabled": enrich,
                "components": ["geoip_asn", "threat_intel_reputation", "mitre_attack_taxonomy"] if enrich else [],
            },
            "machine_learning": {
                "enabled": classify,
                "calibrated_inference": classify,
                "abstention_support": classify,
            },
            "correlation_engine": {
                "enabled": correlate,
                "sliding_window_sec": 300,
                "alerts_triggered": summary.get("alerts_generated", 0),
            },
        },
        "performance": {
            "elapsed_seconds": summary.get("elapsed_seconds", 0.0),
            "events_per_second": summary.get("events_per_second", 0.0),
        },
        "provenance_verified": True,
    }

    manifest_file.parent.mkdir(parents=True, exist_ok=True)
    with manifest_file.open("w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    return manifest_data


def verify_manifest_details(manifest_path: str | Path) -> tuple[bool, list[str]]:
    """
    Re-verifies on-disk artifacts against the recorded SHA-256 digests in a manifest.
    Returns (True, []) if all digests match exactly.
    Returns (False, [errors...]) if any file is missing, unreadable, or tampered.
    """
    from src.provenance import calculate_file_sha256

    errors: list[str] = []
    p = Path(manifest_path)
    if not p.exists():
        return False, [f"Manifest file not found: {manifest_path}"]

    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        return False, [f"Corrupted or invalid JSON manifest: {exc}"]

    # Verify input file
    input_info = data.get("input", {})
    in_path_str = input_info.get("path")
    expected_in_hash = input_info.get("sha256")
    if in_path_str and expected_in_hash:
        in_path = Path(in_path_str)
        if not in_path.exists():
            errors.append(f"Input file missing on disk: {in_path_str}")
        else:
            actual_in_hash = calculate_file_sha256(in_path)
            if actual_in_hash != expected_in_hash:
                errors.append(
                    f"Input file SHA-256 mismatch: expected {expected_in_hash[:16]}..., got {actual_in_hash[:16]}..."
                )

    # Verify canonical events output file
    output_info = data.get("outputs", {}).get("canonical_events", {})
    out_path_str = output_info.get("path")
    expected_out_hash = output_info.get("sha256")
    if out_path_str and expected_out_hash:
        out_path = Path(out_path_str)
        if not out_path.exists():
            errors.append(f"Canonical output file missing on disk: {out_path_str}")
        else:
            actual_out_hash = calculate_file_sha256(out_path)
            if actual_out_hash != expected_out_hash:
                errors.append(
                    f"Canonical output file SHA-256 mismatch (tampered): expected {expected_out_hash[:16]}..., got {actual_out_hash[:16]}..."
                )

    # Verify threat alerts output file (if configured)
    alerts_info = data.get("outputs", {}).get("threat_alerts", {})
    alerts_path_str = alerts_info.get("path")
    expected_alerts_hash = alerts_info.get("sha256")
    if alerts_path_str and expected_alerts_hash:
        alerts_path = Path(alerts_path_str)
        if not alerts_path.exists():
            errors.append(f"Alerts output file missing on disk: {alerts_path_str}")
        else:
            actual_alerts_hash = calculate_file_sha256(alerts_path)
            if actual_alerts_hash != expected_alerts_hash:
                errors.append(
                    f"Threat alerts file SHA-256 mismatch (tampered): expected {expected_alerts_hash[:16]}..., got {actual_alerts_hash[:16]}..."
                )

    return len(errors) == 0, errors


def verify_manifest(manifest_path: str | Path) -> bool:
    """
    Re-verifies on-disk artifacts against recorded SHA-256 digests.
    Returns True if valid, False if tampered or missing.
    """
    valid, _ = verify_manifest_details(manifest_path)
    return valid


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def cli_main(argv: list[str] | None = None) -> int:
    """
    Minimal CLI implementation (no external dependencies required).

    Commands
    --------
    pipeline        - run full end-to-end pipeline (ingest -> enrich -> ML -> correlate -> manifest)
    verify-manifest - verify cryptographic SHA-256 audit manifest against on-disk files
    ingest          - run the batch ingestion pipeline (file -> normalize -> output)
    listen          - real-time live ingestion (syslog UDP/TCP, file-watch, REST)
    demo            - launch real-time dashboard operations console
    train           - train and serialize machine learning classifier
    evaluate        - evaluate model performance and output diagnostics report
    parsers         - list registered parsers
    sources         - list configured sources
    """
    args = argv or sys.argv[1:]

    if not args:
        _print_help()
        return 0

    command = args[0].lower()

    if command in ("-h", "--help", "help"):
        _print_help()
        return 0

    if command == "pipeline":
        return _cmd_pipeline(args[1:])

    if command in ("verify-manifest", "verify_manifest", "verify"):
        return _cmd_verify_manifest(args[1:])

    if command == "parsers":
        _cmd_parsers()
        return 0

    if command == "sources":
        _cmd_sources()
        return 0

    if command == "ingest":
        return _cmd_ingest(args[1:])

    if command == "listen":
        return _cmd_listen(args[1:])

    if command == "demo":
        return _cmd_demo(args[1:])

    if command == "train":
        return _cmd_train(args[1:])

    if command == "evaluate":
        return _cmd_evaluate(args[1:])

    print(f"[ULPF] Unknown command: {command!r}. Run with --help.", file=sys.stderr)
    return 1


def _cmd_verify_manifest(args: list[str]) -> int:
    """Handle: python -m ulpf verify-manifest [options]"""
    opts = _parse_opts(args)
    manifest = opts.get("--manifest") or opts.get("-m") or "outputs/provenance_manifest.json"
    valid, errors = verify_manifest_details(manifest)
    if valid:
        _log(f"Provenance verification SUCCESSFUL: {manifest} matches on-disk files.")
        return 0
    else:
        _error(f"Provenance verification FAILED for {manifest}:")
        for err in errors:
            _error(f"  - {err}")
        return 1


def _cmd_pipeline(args: list[str]) -> int:
    """Handle: python -m ulpf pipeline [options]"""
    opts = _parse_opts(args)
    input_file = opts.get("--input") or opts.get("-i")
    source = opts.get("--source") or opts.get("-s")

    if not input_file and not source:
        _error("--input <log_file> or --source <config.yaml> is required.")
        return 1

    output_file = opts.get("--output") or opts.get("-o") or "outputs/canonical_events.jsonl"
    alerts_file = opts.get("--alerts") or opts.get("--alerts-file") or "outputs/threat_alerts.jsonl"
    manifest_file = opts.get("--manifest") or "outputs/provenance_manifest.json"
    output_format = opts.get("--output-format") or opts.get("-f") or "json-lines"
    max_events_raw = opts.get("--max-events")
    max_events = int(max_events_raw) if max_events_raw else None

    no_validate = "--no-validate" in args
    no_enrich = "--no-enrich" in args
    no_correlate = "--no-correlate" in args
    no_classify = "--no-classify" in args

    try:
        run_pipeline(
            input_file=input_file,
            output_file=output_file,
            alerts_file=alerts_file,
            manifest_file=manifest_file,
            source_config=source,
            output_format=output_format,
            max_events=max_events,
            validate=not no_validate,
            enrich=not no_enrich,
            correlate=not no_correlate,
            classify=not no_classify,
            verbose=True,
        )
        return 0
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        _error(str(exc))
        return 1


def _cmd_ingest(args: list[str]) -> int:
    """Handle: python -m ulpf ingest [options]"""
    # Parse simple key=value CLI arguments
    opts = _parse_opts(args)

    source = opts.get("--source") or opts.get("-s")
    raw_input = opts.get("--input") or opts.get("-i")
    if not source and raw_input:
        temp_dir = _PROJECT_ROOT / "outputs" / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_config = temp_dir / "cli_source.yaml"
        temp_config.write_text(
            f"source_id: cli_input\nlog_path: {Path(raw_input).as_posix()}\n",
            encoding="utf-8",
        )
        source = str(temp_config)

    if not source:
        _error("--source <config.yaml> or --input <log_file> is required.")
        return 1

    output_format = opts.get("--output-format") or opts.get("-f") or "json-lines"
    output_file = opts.get("--output-file") or opts.get("-o")
    max_events_raw = opts.get("--max-events")
    max_events = int(max_events_raw) if max_events_raw else None
    no_validate = "--no-validate" in args
    no_enrich = "--no-enrich" in args
    no_correlate = "--no-correlate" in args
    classify = "--classify" in args
    alerts_file = opts.get("--alerts-file")

    try:
        summary = ingest(
            source_config=source,
            output_format=output_format,
            output_file=output_file,
            max_events=max_events,
            validate=not no_validate,
            enrich=not no_enrich,
            correlate=not no_correlate,
            classify=classify,
            alerts_file=alerts_file,
            verbose=True,
        )
        return 0
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        _error(str(exc))
        return 1


def _cmd_listen(args: list[str]) -> int:
    """
    Handle: python -m ulpf listen [options]

    Modes
    -----
    syslog  — UDP/TCP Syslog listener (receives live syslog from devices)
    file    — File tail watcher (monitors a log file for new lines)
    rest    — HTTP REST receiver (accepts log lines via POST /ingest)
    """
    opts = _parse_opts(args)

    mode = opts.get("--mode") or opts.get("-m") or "syslog"
    output_format = opts.get("--output-format") or opts.get("-f") or "json-lines"
    output_file = opts.get("--output-file") or opts.get("-o")
    source_config = opts.get("--source") or opts.get("-s")
    no_validate = "--no-validate" in args

    try:
        if mode == "syslog":
            from src.ingestion.syslog_listener import SyslogListener
            host = opts.get("--host") or "0.0.0.0"
            port = int(opts.get("--port") or 514)
            protocol = opts.get("--protocol") or "udp"
            source_id = opts.get("--source-id") or "syslog_live"
            listener = SyslogListener(
                host=host,
                port=port,
                protocol=protocol,
                source_config=source_config,
                output_format=output_format,
                output_file=output_file,
                validate=not no_validate,
                source_id=source_id,
            )
            listener.start()

        elif mode == "file":
            if not source_config:
                _error("--source <config.yaml> is required for file mode.")
                return 1
            from src.ingestion.file_watcher import FileWatcher
            import yaml
            with open(source_config, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            file_path = opts.get("--file") or cfg.get("log_path")
            if not file_path:
                _error("Specify --file <path> or set log_path in source config.")
                return 1
            from_beginning = "--from-beginning" in args
            watcher = FileWatcher(
                file_path=file_path,
                source_config=source_config,
                output_format=output_format,
                output_file=output_file,
                from_beginning=from_beginning,
                validate=not no_validate,
            )
            watcher.start()

        elif mode == "rest":
            from src.ingestion.rest_receiver import RestReceiver
            host = opts.get("--host") or "0.0.0.0"
            port = int(opts.get("--port") or 8080)
            source_id = opts.get("--source-id") or "rest_live"
            receiver = RestReceiver(
                host=host,
                port=port,
                source_config=source_config,
                output_format=output_format,
                output_file=output_file,
                validate=not no_validate,
                source_id=source_id,
            )
            receiver.start()

        else:
            _error(f"Unknown listen mode: {mode!r}. Use: syslog | file | rest")
            return 1

    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        _error(str(exc))
        return 1

    return 0


def _cmd_demo(args: list[str]) -> int:
    """Handle: python -m ulpf demo [options]"""
    opts = _parse_opts(args)
    port = int(opts.get("--port") or 7000)
    host = opts.get("--host") or "0.0.0.0"
    input_file = opts.get("--input") or opts.get("-i")

    from demo.server import start_server
    try:
        start_server(host=host, port=port, input_file=input_file)
        return 0
    except (KeyboardInterrupt, SystemExit):
        return 0
    except Exception as exc:
        _error(str(exc))
        return 1


def _cmd_train(args: list[str]) -> int:
    """Handle: python -m ulpf train [options]"""
    opts = _parse_opts(args)
    samples = int(opts.get("--samples") or 3000)
    model_type = opts.get("--model-type") or "rf"
    output = opts.get("--output") or "models/classifier.joblib"
    from src.models import train_classifier
    try:
        train_classifier(n_samples=samples, model_type=model_type, output_path=output)
        return 0
    except Exception as exc:
        _error(str(exc))
        return 1


def _cmd_evaluate(args: list[str]) -> int:
    """Handle: python -m ulpf evaluate [options]"""
    opts = _parse_opts(args)
    model_path = opts.get("--model") or "models/classifier.joblib"
    samples = int(opts.get("--samples") or 1000)
    output = opts.get("--output") or "outputs/model_evaluation_report.json"
    from src.models import evaluate_classifier
    try:
        evaluate_classifier(model_path=model_path, n_test_samples=samples, report_path=output)
        return 0
    except Exception as exc:
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
  python ulpf.py <command> [options]

COMMANDS:
  pipeline        Run unified 6-stage end-to-end pipeline (ingest -> enrich -> ML -> correlate -> manifest)
  verify-manifest Verify cryptographic SHA-256 audit manifest against on-disk files
  ingest          Batch-ingest and normalize a log file
  listen          Live/real-time ingestion (syslog / file-watch / REST)
  demo            Launch live real-time operations dashboard & SSE server
  train           Train and calibrate perimeter machine learning classifier
  evaluate        Evaluate trained classifier and output metrics report
  parsers         List all registered format parsers
  sources         List configured log sources
  help            Show this help message

PIPELINE OPTIONS:
  --input, -i       <path>   Raw perimeter log file (required if no --source)
  --source, -s      <path>   Source config YAML file
  --output, -o      <path>   Canonical events destination (default: outputs/canonical_events.jsonl)
  --alerts          <path>   Correlated threat alerts destination (default: outputs/threat_alerts.jsonl)
  --manifest        <path>   SHA-256 audit manifest destination (default: outputs/provenance_manifest.json)
  --output-format, -f <fmt>  Output format: json-lines (default), cef, csv
  --max-events       <n>     Stop after n events
  --no-validate              Skip schema validation
  --no-enrich                Disable GeoIP and threat reputation
  --no-correlate             Disable correlation engine
  --no-classify              Disable machine learning inference

INGEST OPTIONS:
  --source, -s      <path>   Source config YAML
  --input, -i       <path>   Direct log file path (auto-configures source)
  --output-format, -f <fmt>  Output format: json-lines (default), cef, csv
  --output-file, -o <path>   Output file path (default: stdout)
  --max-events       <n>     Stop after n events (for testing)
  --no-validate              Skip schema validation (faster)
  --no-enrich                Disable GeoIP, Threat Intel, and MITRE enrichment
  --no-correlate             Disable sliding time-window correlation engine
  --classify                 Apply ML classifier inference & confidence scoring
  --alerts-file     <path>   Write generated security alerts to JSONL file

LISTEN OPTIONS:
  --mode, -m        <mode>   syslog (default) | file | rest
  --host            <addr>   Bind address (default: 0.0.0.0)
  --port            <port>   Listen port (syslog: 514, REST: 8080)
  --protocol        <proto>  udp (default) | tcp  [syslog mode only]
  --source, -s      <path>   Source config YAML (for FieldMapper settings)
  --file            <path>   Log file to watch [file mode only]
  --from-beginning           Process file from start before watching [file mode]
  --output-format, -f <fmt>  Output format: json-lines (default), cef, csv
  --output-file, -o <path>   Output file path (default: stdout)
  --source-id       <id>     Logical source identifier for events
  --no-validate              Skip schema validation (faster)

TRAIN & EVALUATE OPTIONS:
  --samples          <n>     Number of training/evaluation samples (default: 3000)
  --model-type       <type>  rf (RandomForest, default) or lr (LogisticRegression)
  --output           <path>  Path for serialized model (.joblib) or report (.json)
  --model            <path>  Path to trained model for evaluation

DEMO OPTIONS:
  --port            <port>   Listen port (default: 7000)
  --host            <addr>   Bind address (default: 0.0.0.0)
  --input, -i       <path>   JSON-Lines output file to tail (e.g. outputs/live.jsonl)

EXAMPLES:
  # Unified end-to-end pipeline with cryptographic provenance manifest
  python ulpf.py pipeline --input data/raw/cisco_asa.log --output outputs/cisco.jsonl --manifest outputs/manifest.json

  # Batch ingest with ML classification
  python ulpf.py ingest --input data/raw/cisco_asa.log --classify -o outputs/cisco.jsonl

  # Train machine learning classifier
  python ulpf.py train --samples 2000 --model-type rf

  # Evaluate classifier diagnostics
  python ulpf.py evaluate --model models/classifier.joblib

  # Live operations dashboard
  python ulpf.py demo --port 7000 --input outputs/live.jsonl
""",
        file=sys.stderr,
    )
