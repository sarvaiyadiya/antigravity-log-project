"""
File Watcher — live log file tail watcher for ULPF.

Monitors a log file for new lines appended at the end (like `tail -f`)
and feeds them into the normalization pipeline in real-time.

This is the most common way to ingest logs from:
- Locally running services (nginx, Apache, application logs)
- Syslog daemons writing to /var/log/syslog or /var/log/messages
- Firewall/IDS agents writing to local log files
- Log aggregators (Fluent Bit, Vector) writing to local files

Features
--------
- Cross-platform polling (0.5s interval) — works on Windows and Linux
- Handles log rotation: detects file truncation or replacement
- Handles large files (>1GB) — does not load into memory
- Starts from the END of the file by default (tail mode)
  or from the BEGINNING (replay mode)
- Emits statistics to stderr at configurable intervals

Usage
-----
  # From Python
  from src.ingestion.file_watcher import FileWatcher
  watcher = FileWatcher(
      file_path="data/raw/syslog_firewall.log",
      source_config="configs/sources/syslog_firewall.yaml",
      output_format="json-lines",
      output_file="outputs/live.jsonl",
  )
  watcher.start()   # blocks; Ctrl-C to stop

  # From CLI (via pipeline.py)
  python -m ulpf listen --mode file --source configs/sources/syslog_firewall.yaml \\
      --output-file outputs/live.jsonl

PS requirements covered
-----------------------
(e) Plug-and-play — auto-detects format from file content
(f) Unified visibility — real-time event stream from any log file
(g) SIEM/Data Lake output — writes CEF / JSON-Lines / CSV in real-time
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.ingestion.format_detector import detect_format
from src.ingestion.parser_registry import get_registry
from src.ingestion import parsers as _parsers_pkg  # auto-registers all parsers
from src.schema.unified_event import UnifiedEvent
from src.schema.field_mapper import FieldMapper, DEFAULT_MAPPER
from src.schema.schema_validator import validate_unified_event, SchemaValidationError
from src.output.output_router import get_writer

logger = logging.getLogger(__name__)

# Polling interval in seconds
_POLL_INTERVAL = 0.5
# Stats reporting interval (seconds)
_STATS_INTERVAL = 60


# ---------------------------------------------------------------------------
# Rotation detector
# ---------------------------------------------------------------------------

def _get_file_id(path: Path) -> tuple[int, int]:
    """
    Return a tuple (inode, size) used to detect file rotation.
    On Windows, inode is always 0 so we use (0, size).
    """
    try:
        stat = path.stat()
        return (stat.st_ino, stat.st_size)
    except FileNotFoundError:
        return (-1, -1)


# ---------------------------------------------------------------------------
# Public API: FileWatcher
# ---------------------------------------------------------------------------

class FileWatcher:
    """
    Live log file tail watcher.

    Monitors a log file for new lines and feeds them into the
    ULPF normalization pipeline.

    Parameters
    ----------
    file_path      : Path to the log file to monitor.
    source_config  : Path to a ULPF source YAML for format and FieldMapper settings.
                     If None, uses auto-detection and default mapper.
    output_format  : "json-lines" | "cef" | "csv"
    output_file    : Output file path; None → stdout
    from_beginning : If True, process the entire existing file first, then
                     continue watching. If False (default), start from the end.
    validate       : Run schema validation on each event (default: True)
    source_id      : Logical source identifier; overrides source_config value.
    poll_interval  : Seconds between file polls (default: 0.5)
    stats_interval : Seconds between stats reports (default: 60)
    encoding       : File encoding (default: utf-8)
    """

    def __init__(
        self,
        file_path: str | Path,
        source_config: str | Path | None = None,
        output_format: str = "json-lines",
        output_file: str | Path | None = None,
        from_beginning: bool = False,
        validate: bool = True,
        source_id: str | None = None,
        poll_interval: float = _POLL_INTERVAL,
        stats_interval: int = _STATS_INTERVAL,
        encoding: str = "utf-8",
    ) -> None:
        self._file_path = Path(file_path)
        self._source_config = source_config
        self.output_format = output_format
        self.output_file = output_file
        self.from_beginning = from_beginning
        self.validate = validate
        self._source_id = source_id
        self.poll_interval = poll_interval
        self.stats_interval = stats_interval
        self.encoding = encoding
        self._stop_event = threading.Event()

        # Counters
        self._received = 0
        self._parsed_ok = 0
        self._parse_errors = 0
        self._schema_errors = 0
        self._start_time = 0.0

    # ------------------------------------------------------------------
    # Public start/stop
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start watching. Blocks until Ctrl-C / stop() is called."""
        # Load configuration
        if self._source_config:
            mapper = FieldMapper.from_yaml(self._source_config)
            import yaml
            with open(self._source_config, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            source_id = self._source_id or cfg.get("source_id", self._file_path.stem)
            format_name = cfg.get("parser")
            encoding = cfg.get("encoding", self.encoding)
        else:
            mapper = DEFAULT_MAPPER
            source_id = self._source_id or self._file_path.stem
            format_name = None
            encoding = self.encoding

        writer = get_writer(self.output_format, output=self.output_file)
        registry = get_registry()

        # Signal handlers
        def _shutdown(signum: int, frame: Any) -> None:
            print("\n[ULPF WATCH] Shutdown signal — stopping.", file=sys.stderr)
            self._stop_event.set()

        signal.signal(signal.SIGINT, _shutdown)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _shutdown)

        self._start_time = time.monotonic()

        print(
            f"[ULPF WATCH] Watching: {self._file_path} | "
            f"source={source_id} | "
            f"output={self.output_format} → {self.output_file or 'stdout'}",
            file=sys.stderr,
        )
        print("[ULPF WATCH] Press Ctrl-C to stop.", file=sys.stderr)

        # Start stats reporter
        stats_thread = threading.Thread(
            target=self._stats_reporter,
            args=(self._stop_event, self.stats_interval),
            daemon=True,
        )
        stats_thread.start()

        with writer:
            self._watch_loop(
                registry=registry,
                mapper=mapper,
                writer=writer,
                source_id=source_id,
                format_name=format_name,
                encoding=encoding,
            )

        self._print_final_stats()

    def stop(self) -> None:
        """Signal the watcher to stop."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Core watch loop
    # ------------------------------------------------------------------

    def _watch_loop(
        self,
        registry: Any,
        mapper: FieldMapper,
        writer: Any,
        source_id: str,
        format_name: str | None,
        encoding: str,
    ) -> None:
        """Main polling loop — watches file, reads new lines, processes them."""
        file_path = self._file_path

        # Wait for the file to exist
        while not file_path.exists() and not self._stop_event.is_set():
            print(
                f"[ULPF WATCH] Waiting for file: {file_path}",
                file=sys.stderr,
            )
            time.sleep(2.0)

        if self._stop_event.is_set():
            return

        # Auto-detect format if not specified
        if not format_name:
            format_name = detect_format(file_path, encoding=encoding)
            if format_name:
                print(f"[ULPF WATCH] Detected format: {format_name}", file=sys.stderr)
            else:
                print(
                    "[ULPF WATCH] Could not detect format — will try all parsers per line.",
                    file=sys.stderr,
                )

        # Open file and seek to end (or beginning if replay mode)
        current_id = _get_file_id(file_path)

        with file_path.open("r", encoding=encoding, errors="replace") as fh:
            if not self.from_beginning:
                fh.seek(0, 2)  # seek to end

            while not self._stop_event.is_set():
                line = fh.readline()

                if not line:
                    # No new data — check for rotation
                    new_id = _get_file_id(file_path)
                    if new_id != current_id:
                        print("[ULPF WATCH] File rotation detected — reopening.", file=sys.stderr)
                        break  # Exit inner loop; outer recursion handles reopen
                    time.sleep(self.poll_interval)
                    continue

                stripped = line.rstrip("\r\n")
                if not stripped:
                    continue

                self._process_line(
                    line=stripped,
                    registry=registry,
                    mapper=mapper,
                    writer=writer,
                    source_id=source_id,
                    format_name=format_name,
                )

        # If not stopped, re-enter loop (handles file rotation)
        if not self._stop_event.is_set():
            self._watch_loop(
                registry=registry,
                mapper=mapper,
                writer=writer,
                source_id=source_id,
                format_name=format_name,
                encoding=encoding,
            )

    def _process_line(
        self,
        line: str,
        registry: Any,
        mapper: FieldMapper,
        writer: Any,
        source_id: str,
        format_name: str | None,
    ) -> None:
        """Parse, normalize, validate, and write one line."""
        self._received += 1

        result = registry.parse(line, format_name=format_name)
        if not result.success:
            self._parse_errors += 1
            logger.debug("Parse error: %s | line: %.80s…", result.error, line)
            return

        canonical = mapper.map(result.fields)
        event = UnifiedEvent.create(
            raw_log=line,
            format_name=result.format_name,
            source_id=source_id,
            **canonical,
        )

        if self.validate:
            try:
                validate_unified_event(event)
            except SchemaValidationError as exc:
                self._schema_errors += 1
                logger.debug("Schema error: %s", exc)
                return

        writer.write(event)
        self._parsed_ok += 1

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def _stats_reporter(self, stop_event: threading.Event, interval: int) -> None:
        while not stop_event.wait(interval):
            self._print_stats()

    def _print_stats(self) -> None:
        elapsed = time.monotonic() - self._start_time
        eps = self._parsed_ok / elapsed if elapsed > 0 else 0.0
        print(
            f"[ULPF WATCH] {datetime.now(timezone.utc).strftime('%H:%M:%SZ')} | "
            f"recv={self._received:,} parsed={self._parsed_ok:,} "
            f"err={self._parse_errors:,} rate={eps:.0f} eps",
            file=sys.stderr,
        )

    def _print_final_stats(self) -> None:
        elapsed = time.monotonic() - self._start_time
        eps = self._parsed_ok / elapsed if elapsed > 0 else 0.0
        print(
            f"\n[ULPF WATCH] Stopped. "
            f"recv={self._received:,} parsed={self._parsed_ok:,} "
            f"errors={self._parse_errors:,} "
            f"in {elapsed:.1f}s ({eps:.0f} eps avg)",
            file=sys.stderr,
        )
