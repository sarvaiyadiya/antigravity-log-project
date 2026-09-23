"""
REST Receiver — HTTP webhook endpoint for ULPF live log ingestion.

Receives log events via HTTP POST and feeds them into the normalization
pipeline. Useful for:
- Cloud log forwarding (AWS, GCP, Azure → HTTP POST)
- Application-level log shipping (custom agents, Fluent Bit HTTP output)
- Webhook integrations (security tools, SOAR platforms)
- Testing and development (curl / HTTP client)

Endpoints
---------
  POST /ingest
    Body: single raw log line (text/plain) or JSON object
    Response: {"status": "ok", "parsed": 1, "errors": 0}

  POST /ingest/batch
    Body: newline-separated raw log lines
    Response: {"status": "ok", "parsed": N, "errors": M}

  GET /health
    Response: {"status": "ok", "uptime_seconds": N, "events_parsed": N}

  GET /stats
    Response: full statistics snapshot

Usage
-----
  # From Python
  from src.ingestion.rest_receiver import RestReceiver
  receiver = RestReceiver(host="0.0.0.0", port=8080,
                          output_format="json-lines",
                          output_file="outputs/live.jsonl")
  receiver.start()  # blocks; Ctrl-C to stop

  # From CLI (via pipeline.py)
  python -m ulpf listen --mode rest --port 8080 --output-file outputs/live.jsonl

  # Send a log line
  curl -X POST http://localhost:8080/ingest \\
       -H "Content-Type: text/plain" \\
       -d '%ASA-4-106023: Deny tcp src outside:1.2.3.4/1234 dst inside:10.0.0.1/443'

  # Send a batch
  curl -X POST http://localhost:8080/ingest/batch \\
       -H "Content-Type: text/plain" \\
       --data-binary @data/raw/syslog_firewall.log

PS requirements covered
-----------------------
(e) Plug-and-play — auto-detects format of each incoming line
(f) Unified visibility — real-time event stream via REST
(g) SIEM/Data Lake output — writes CEF / JSON-Lines / CSV in real-time
"""

from __future__ import annotations

import http.server
import json
import logging
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.ingestion.parser_registry import get_registry
from src.ingestion import parsers as _parsers_pkg  # auto-registers all parsers
from src.schema.unified_event import UnifiedEvent
from src.schema.field_mapper import FieldMapper, DEFAULT_MAPPER
from src.schema.schema_validator import validate_unified_event, SchemaValidationError
from src.output.output_router import get_writer

logger = logging.getLogger(__name__)

# Maximum request body size (10 MB)
_MAX_BODY = 10 * 1024 * 1024
# Stats reporting interval (seconds)
_STATS_INTERVAL = 60


# ---------------------------------------------------------------------------
# Shared state (injected into handler via server reference)
# ---------------------------------------------------------------------------

class _ReceiverState:
    """Holds shared state for the HTTP server (registry, mapper, writer, stats)."""

    def __init__(
        self,
        mapper: FieldMapper,
        writer: Any,
        source_id: str,
        validate: bool,
    ) -> None:
        self.registry = get_registry()
        self.mapper = mapper
        self.writer = writer
        self.source_id = source_id
        self.validate = validate
        self._lock = threading.Lock()

        # Stats
        self.received: int = 0
        self.parsed_ok: int = 0
        self.parse_errors: int = 0
        self.schema_errors: int = 0
        self.start_time: float = time.monotonic()

    def process_line(self, line: str) -> tuple[bool, str | None]:
        """
        Process one raw log line.
        Returns (success, error_message).
        """
        stripped = line.strip()
        if not stripped:
            return True, None  # blank lines are silently ignored

        with self._lock:
            self.received += 1

        result = self.registry.parse(stripped)
        if not result.success:
            with self._lock:
                self.parse_errors += 1
            return False, result.error

        canonical = self.mapper.map(result.fields)
        event = UnifiedEvent.create(
            raw_log=stripped,
            format_name=result.format_name,
            source_id=self.source_id,
            **canonical,
        )

        if self.validate:
            try:
                validate_unified_event(event)
            except SchemaValidationError as exc:
                with self._lock:
                    self.schema_errors += 1
                return False, str(exc)

        with self._lock:
            self.writer.write(event)
            self.parsed_ok += 1

        return True, None

    def snapshot(self) -> dict[str, Any]:
        elapsed = time.monotonic() - self.start_time
        with self._lock:
            eps = self.parsed_ok / elapsed if elapsed > 0 else 0.0
            return {
                "status": "ok",
                "uptime_seconds": round(elapsed, 1),
                "events_received": self.received,
                "events_parsed": self.parsed_ok,
                "parse_errors": self.parse_errors,
                "schema_errors": self.schema_errors,
                "events_per_second": round(eps, 1),
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            }


# ---------------------------------------------------------------------------
# HTTP Request Handler
# ---------------------------------------------------------------------------

class _ULPFHandler(http.server.BaseHTTPRequestHandler):
    """Handles HTTP requests for the ULPF REST receiver."""

    # Suppress default request logging to stderr (we use our own)
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _read_body(self) -> bytes | None:
        """Read the request body up to _MAX_BODY bytes."""
        length_str = self.headers.get("Content-Length")
        if not length_str:
            return b""
        try:
            length = int(length_str)
        except ValueError:
            return None
        if length > _MAX_BODY:
            return None
        return self.rfile.read(length)

    def _send_json(self, code: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        state: _ReceiverState = self.server.state  # type: ignore[attr-defined]

        if self.path == "/health":
            snap = state.snapshot()
            self._send_json(200, {"status": "ok",
                                  "uptime_seconds": snap["uptime_seconds"],
                                  "events_parsed": snap["events_parsed"]})
        elif self.path == "/stats":
            self._send_json(200, state.snapshot())
        else:
            self._send_json(404, {"status": "error", "message": f"Unknown path: {self.path}"})

    def do_POST(self) -> None:
        state: _ReceiverState = self.server.state  # type: ignore[attr-defined]

        body = self._read_body()
        if body is None:
            self._send_json(413, {"status": "error",
                                  "message": f"Request body too large (max {_MAX_BODY} bytes)."})
            return

        text = body.decode("utf-8", errors="replace")

        if self.path == "/ingest":
            # Single line or single JSON object
            success, error = state.process_line(text)
            if success:
                self._send_json(200, {"status": "ok", "parsed": 1, "errors": 0})
            else:
                self._send_json(422, {"status": "error", "parsed": 0,
                                      "errors": 1, "detail": error})

        elif self.path == "/ingest/batch":
            # Newline-separated lines
            lines = text.splitlines()
            parsed = 0
            errors = 0
            for line in lines:
                if not line.strip():
                    continue
                success, _ = state.process_line(line)
                if success:
                    parsed += 1
                else:
                    errors += 1
            self._send_json(200, {"status": "ok", "parsed": parsed, "errors": errors})

        else:
            self._send_json(404, {"status": "error",
                                  "message": f"Unknown endpoint: {self.path}. "
                                             f"Use /ingest or /ingest/batch."})


class _ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer with allow_reuse_address enabled."""
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# Public API: RestReceiver
# ---------------------------------------------------------------------------

class RestReceiver:
    """
    HTTP REST webhook receiver for real-time log ingestion.

    Parameters
    ----------
    host           : Bind address (default: "0.0.0.0")
    port           : Listen port (default: 8080)
    source_config  : Path to a ULPF source YAML for FieldMapper settings.
    output_format  : "json-lines" | "cef" | "csv"
    output_file    : Output file path; None → stdout
    validate       : Run schema validation on each event
    source_id      : Logical source identifier
    stats_interval : Seconds between stats reports
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        source_config: str | Path | None = None,
        output_format: str = "json-lines",
        output_file: str | Path | None = None,
        validate: bool = True,
        source_id: str = "rest_live",
        stats_interval: int = _STATS_INTERVAL,
    ) -> None:
        self.host = host
        self.port = port
        self._source_config = source_config
        self.output_format = output_format
        self.output_file = output_file
        self.validate = validate
        self.source_id = source_id
        self.stats_interval = stats_interval
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the HTTP server. Blocks until Ctrl-C / stop() called."""
        mapper = (
            FieldMapper.from_yaml(self._source_config)
            if self._source_config
            else DEFAULT_MAPPER
        )

        writer = get_writer(self.output_format, output=self.output_file)
        state = _ReceiverState(
            mapper=mapper,
            writer=writer,
            source_id=self.source_id,
            validate=self.validate,
        )

        server = _ThreadedHTTPServer((self.host, self.port), _ULPFHandler)
        server.state = state  # type: ignore[attr-defined]

        def _shutdown(signum: int, frame: Any) -> None:
            print("\n[ULPF REST] Shutdown signal — stopping.", file=sys.stderr)
            self._stop_event.set()
            server.shutdown()

        # Only register signal handlers in the main thread (signal module restriction)
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, _shutdown)
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, _shutdown)

        print(
            f"[ULPF REST] HTTP receiver started at http://{self.host}:{self.port} | "
            f"output={self.output_format} → {self.output_file or 'stdout'}",
            file=sys.stderr,
        )
        print(
            f"[ULPF REST] Endpoints: POST /ingest  POST /ingest/batch  GET /health  GET /stats",
            file=sys.stderr,
        )
        print("[ULPF REST] Press Ctrl-C to stop.", file=sys.stderr)

        # Stats reporter thread
        def _stats_loop() -> None:
            while not self._stop_event.wait(self.stats_interval):
                snap = state.snapshot()
                print(
                    f"[ULPF REST] {snap['timestamp_utc']} | "
                    f"recv={snap['events_received']:,} parsed={snap['events_parsed']:,} "
                    f"err={snap['parse_errors']:,} rate={snap['events_per_second']:.0f} eps",
                    file=sys.stderr,
                )

        threading.Thread(target=_stats_loop, daemon=True).start()

        try:
            with writer:
                server.serve_forever()
        finally:
            self._stop_event.set()
            snap = state.snapshot()
            print(
                f"\n[ULPF REST] Stopped. "
                f"recv={snap['events_received']:,} parsed={snap['events_parsed']:,} "
                f"errors={snap['parse_errors']:,} "
                f"uptime={snap['uptime_seconds']:.1f}s "
                f"({snap['events_per_second']:.0f} eps avg)",
                file=sys.stderr,
            )

    def stop(self) -> None:
        """Signal the receiver to stop."""
        self._stop_event.set()
