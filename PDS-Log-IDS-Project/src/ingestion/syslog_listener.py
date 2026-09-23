"""
Syslog Listener — real-time UDP/TCP Syslog receiver for ULPF.

Listens on a network socket and feeds incoming syslog messages
directly into the normalization pipeline, emitting UnifiedEvents
to the configured output writer.

Most perimeter network devices (firewalls, IDS/IPS, routers, VPN
concentrators, switches) natively support syslog forwarding over UDP
port 514 (RFC 3164) or TCP port 514 (RFC 5424 / TLS).

Architecture
------------
  [Network Device] ──syslog──▶ [SyslogListener] ──parse──▶ [FieldMapper]
                                                                   │
                                                            [UnifiedEvent]
                                                                   │
                                                          [OutputWriter (jsonl/cef/csv)]

Usage
-----
  # From Python
  from src.ingestion.syslog_listener import SyslogListener
  listener = SyslogListener(host="0.0.0.0", port=514, protocol="udp",
                            output_format="json-lines", output_file="outputs/live.jsonl")
  listener.start()   # blocks; Ctrl-C to stop

  # From CLI (via pipeline.py)
  python -m ulpf listen --mode syslog --port 514 --output-file outputs/live.jsonl

PS requirements covered
-----------------------
(e) Plug-and-play — auto-detects format of each incoming line
(f) Unified visibility — real-time event stream
(g) SIEM/Data Lake output — writes CEF / JSON-Lines / CSV in real-time
"""

from __future__ import annotations

import logging
import signal
import socketserver
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

# Maximum UDP datagram size (standard syslog limit)
_UDP_BUFFER = 65535
# Maximum TCP line length
_TCP_MAX_LINE = 65535
# Stats reporting interval (seconds)
_STATS_INTERVAL = 60


# ---------------------------------------------------------------------------
# Shared statistics counter (thread-safe via lock)
# ---------------------------------------------------------------------------

class _Stats:
    """Thread-safe counters for listener metrics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.received: int = 0
        self.parsed_ok: int = 0
        self.parse_errors: int = 0
        self.schema_errors: int = 0
        self.start_time: float = time.monotonic()

    def inc_received(self) -> None:
        with self._lock:
            self.received += 1

    def inc_parsed(self) -> None:
        with self._lock:
            self.parsed_ok += 1

    def inc_parse_error(self) -> None:
        with self._lock:
            self.parse_errors += 1

    def inc_schema_error(self) -> None:
        with self._lock:
            self.schema_errors += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            elapsed = time.monotonic() - self.start_time
            eps = self.parsed_ok / elapsed if elapsed > 0 else 0.0
            return {
                "received": self.received,
                "parsed_ok": self.parsed_ok,
                "parse_errors": self.parse_errors,
                "schema_errors": self.schema_errors,
                "elapsed_seconds": round(elapsed, 1),
                "events_per_second": round(eps, 1),
            }


# ---------------------------------------------------------------------------
# Event processor — shared by UDP and TCP handlers
# ---------------------------------------------------------------------------

class _EventProcessor:
    """
    Converts a raw log line into a UnifiedEvent and writes it to output.
    Thread-safe: relies on writer thread-safety or external lock.
    """

    def __init__(
        self,
        mapper: FieldMapper,
        writer: Any,
        stats: _Stats,
        source_id: str = "syslog_live",
        validate: bool = True,
    ) -> None:
        self._registry = get_registry()
        self._mapper = mapper
        self._writer = writer
        self._stats = stats
        self._source_id = source_id
        self._validate = validate
        self._write_lock = threading.Lock()

    def process(self, line: str) -> None:
        """Parse, normalize, validate and write one log line."""
        stripped = line.strip()
        if not stripped:
            return

        self._stats.inc_received()

        # Auto-detect and parse
        result = self._registry.parse(stripped)
        if not result.success:
            self._stats.inc_parse_error()
            logger.debug("Parse error: %s | line: %.80s…", result.error, stripped)
            return

        # Map to canonical schema
        canonical = self._mapper.map(result.fields)

        # Build UnifiedEvent
        event = UnifiedEvent.create(
            raw_log=stripped,
            format_name=result.format_name,
            source_id=self._source_id,
            **canonical,
        )

        # Schema validation (optional)
        if self._validate:
            try:
                validate_unified_event(event)
            except SchemaValidationError as exc:
                self._stats.inc_schema_error()
                logger.debug("Schema error: %s", exc)
                return

        # Write (thread-safe)
        with self._write_lock:
            self._writer.write(event)

        self._stats.inc_parsed()


# ---------------------------------------------------------------------------
# UDP Handler
# ---------------------------------------------------------------------------

class _UdpHandler(socketserver.BaseRequestHandler):
    """Handles one UDP datagram = one syslog message."""

    def handle(self) -> None:
        data, _ = self.request
        try:
            line = data.decode("utf-8", errors="replace")
        except Exception:
            return
        self.server.processor.process(line)  # type: ignore[attr-defined]


class _ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Threaded UDP server — handles each datagram in a thread pool."""
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# TCP Handler
# ---------------------------------------------------------------------------

class _TcpHandler(socketserver.StreamRequestHandler):
    """Handles one TCP connection — reads newline-terminated syslog lines."""

    def handle(self) -> None:
        try:
            for raw_line in self.rfile:
                try:
                    line = raw_line.decode("utf-8", errors="replace")
                except Exception:
                    continue
                self.server.processor.process(line)  # type: ignore[attr-defined]
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass  # Client disconnected


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Threaded TCP server — handles each connection in a separate thread."""
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Stats reporter thread
# ---------------------------------------------------------------------------

def _stats_reporter(stats: _Stats, stop_event: threading.Event, interval: int) -> None:
    """Periodically logs statistics to stderr."""
    while not stop_event.wait(interval):
        snap = stats.snapshot()
        print(
            f"[ULPF LIVE] {datetime.now(timezone.utc).strftime('%H:%M:%SZ')} | "
            f"recv={snap['received']:,} parsed={snap['parsed_ok']:,} "
            f"err={snap['parse_errors']:,} "
            f"rate={snap['events_per_second']:.0f} eps",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Public API: SyslogListener
# ---------------------------------------------------------------------------

class SyslogListener:
    """
    Real-time Syslog UDP/TCP listener.

    Parameters
    ----------
    host           : Bind address (default: "0.0.0.0" — all interfaces)
    port           : Listen port (default: 514)
    protocol       : "udp" (default) | "tcp"
    source_config  : Path to a ULPF source YAML for FieldMapper settings.
                     If None, uses the default no-op mapper.
    output_format  : "json-lines" | "cef" | "csv"
    output_file    : Output file path; None → stdout
    validate       : Run schema validation on each event (default: True)
    source_id      : Logical source identifier for events
    stats_interval : Seconds between stats reports (default: 60)
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 514,
        protocol: str = "udp",
        source_config: str | Path | None = None,
        output_format: str = "json-lines",
        output_file: str | Path | None = None,
        validate: bool = True,
        source_id: str = "syslog_live",
        stats_interval: int = _STATS_INTERVAL,
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.output_format = output_format
        self.output_file = output_file
        self.validate = validate
        self.source_id = source_id
        self.stats_interval = stats_interval
        self._source_config = source_config
        self._stop_event = threading.Event()

    def start(self) -> None:
        """
        Start listening. Blocks until Ctrl-C / SIGTERM / stop() is called.
        """
        mapper = (
            FieldMapper.from_yaml(self._source_config)
            if self._source_config
            else DEFAULT_MAPPER
        )

        writer = get_writer(self.output_format, output=self.output_file)
        stats = _Stats()
        processor = _EventProcessor(
            mapper=mapper,
            writer=writer,
            stats=stats,
            source_id=self.source_id,
            validate=self.validate,
        )

        # Stats reporter
        reporter = threading.Thread(
            target=_stats_reporter,
            args=(stats, self._stop_event, self.stats_interval),
            daemon=True,
        )

        # Build server
        if self.protocol == "udp":
            server_cls = _ThreadedUDPServer
            handler_cls = _UdpHandler
        elif self.protocol == "tcp":
            server_cls = _ThreadedTCPServer
            handler_cls = _TcpHandler
        else:
            raise ValueError(f"Unknown protocol: {self.protocol!r}. Use 'udp' or 'tcp'.")

        server = server_cls((self.host, self.port), handler_cls)
        server.processor = processor  # type: ignore[attr-defined]

        # Signal handlers for graceful shutdown
        def _shutdown(signum: int, frame: Any) -> None:
            print("\n[ULPF LIVE] Shutdown signal received — stopping.", file=sys.stderr)
            self._stop_event.set()
            server.shutdown()

        signal.signal(signal.SIGINT, _shutdown)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _shutdown)

        print(
            f"[ULPF LIVE] Syslog listener started "
            f"({self.protocol.upper()} {self.host}:{self.port}) | "
            f"output={self.output_format} → {self.output_file or 'stdout'}",
            file=sys.stderr,
        )
        print("[ULPF LIVE] Press Ctrl-C to stop.", file=sys.stderr)

        reporter.start()

        try:
            with writer:
                server.serve_forever()
        finally:
            self._stop_event.set()
            snap = stats.snapshot()
            print(
                f"\n[ULPF LIVE] Stopped. "
                f"Total: recv={snap['received']:,} "
                f"parsed={snap['parsed_ok']:,} "
                f"errors={snap['parse_errors']:,} "
                f"in {snap['elapsed_seconds']:.1f}s "
                f"({snap['events_per_second']:.0f} eps avg)",
                file=sys.stderr,
            )

    def stop(self) -> None:
        """Signal the listener to stop (for programmatic use)."""
        self._stop_event.set()
