"""
ULPF Demo Server — Live Real-Time Visualization Dashboard Backend
=================================================================
A pure Python standard library HTTP server (zero external dependencies)
providing:
  1. Static file serving (demo/index.html)
  2. Server-Sent Events (SSE) live streaming: GET /api/events/stream
  3. REST stats & buffer queries: GET /api/stats, GET /api/events
  4. Real-time log ingestion: POST /api/ingest, POST /api/process
  5. Background file tailer for pipeline output files (e.g. outputs/live.jsonl)

Usage:
    python demo/server.py [--port 7000] [--host 0.0.0.0] [--input outputs/live.jsonl]
"""

from __future__ import annotations

import collections
import dataclasses
import json
import logging
import os
import queue
import signal
import sys
import threading
import time
from http import HTTPStatus
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import parse_qs, urlparse

# Ensure project root is on Python path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ULPF imports
from src.ingestion import parsers as _reg_parsers  # registers all 12 parsers
from src.ingestion.parser_registry import get_registry
from src.ingestion.format_detector import detect_format_from_text
from src.schema.unified_event import UnifiedEvent
from src.schema.field_mapper import FieldMapper
from src.enrichment import get_enrichment_pipeline
from src.correlation import get_correlation_engine, SecurityAlert

logger = logging.getLogger("ulpf.demo_server")

# Default passthrough mapper for demo ingestion
_UES_FIELD_NAMES = [f.name for f in dataclasses.fields(UnifiedEvent)]
_PASSTHROUGH_MAP = {name: name for name in _UES_FIELD_NAMES}
_DEMO_MAPPER = FieldMapper(
    source_id="demo_live",
    vendor=None,
    device_type="generic",
    field_map=_PASSTHROUGH_MAP,
)


# ---------------------------------------------------------------------------
# Threading HTTP Server
# ---------------------------------------------------------------------------

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server supporting long-lived SSE connections."""
    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# In-Memory State & Ring Buffer
# ---------------------------------------------------------------------------

class DashboardState:
    """Thread-safe state manager for the live demo dashboard."""

    def __init__(self, max_buffer_size: int = 10000) -> None:
        self.lock = threading.Lock()
        self.ring_buffer: collections.deque[dict[str, Any]] = collections.deque(maxlen=max_buffer_size)
        self.alerts_buffer: collections.deque[dict[str, Any]] = collections.deque(maxlen=500)
        self.sse_clients: list[queue.Queue[dict[str, Any] | None]] = []
        self.start_time: float = time.time()
        self.correlation_engine = get_correlation_engine()

        # Cumulative statistics
        self.total_received: int = 0
        self.total_parsed_ok: int = 0
        self.total_parse_errors: int = 0
        self.total_alerts: int = 0
        self.by_severity: dict[str, int] = collections.defaultdict(int)
        self.by_format: dict[str, int] = collections.defaultdict(int)
        self.by_action: dict[str, int] = collections.defaultdict(int)
        self.by_label: dict[str, int] = collections.defaultdict(int)
        self.src_ip_counts: dict[str, int] = collections.defaultdict(int)

        # Rolling EPS tracking: list of (timestamp_seconds, count)
        self._eps_history: collections.deque[tuple[int, int]] = collections.deque(maxlen=120)
        self._last_bucket_sec: int = int(time.time())
        self._current_bucket_count: int = 0

    def add_event(self, event_dict: dict[str, Any], event_obj: UnifiedEvent | None = None) -> list[SecurityAlert]:
        """Add an event to the ring buffer, evaluate correlation rules, update stats, and broadcast to SSE clients."""
        with self.lock:
            self.total_received += 1
            if event_dict.get("success", True):
                self.total_parsed_ok += 1
            else:
                self.total_parse_errors += 1

            # Update breakdowns
            fmt = event_dict.get("format_name") or "unknown"
            self.by_format[fmt] += 1

            sev = str(event_dict.get("severity_label") or event_dict.get("severity") or "unknown").lower()
            self.by_severity[sev] += 1

            act = str(event_dict.get("event_action") or "unknown").lower()
            self.by_action[act] += 1

            lbl = str(event_dict.get("weak_label") or "unknown").lower()
            self.by_label[lbl] += 1

            src_ip = event_dict.get("src_ip")
            if src_ip:
                self.src_ip_counts[str(src_ip)] += 1

            # Rolling EPS bucket
            now_sec = int(time.time())
            if now_sec == self._last_bucket_sec:
                self._current_bucket_count += 1
            else:
                self._eps_history.append((self._last_bucket_sec, self._current_bucket_count))
                # Fill missing seconds if any
                for missing_sec in range(self._last_bucket_sec + 1, now_sec):
                    self._eps_history.append((missing_sec, 0))
                self._last_bucket_sec = now_sec
                self._current_bucket_count = 1

            # Store in ring buffer (shallow copy to prevent mutation)
            self.ring_buffer.append(event_dict)

            # Copy active client queues
            clients_snapshot = list(self.sse_clients)

        # Run correlation engine
        new_alerts: list[SecurityAlert] = []
        if event_obj is not None:
            new_alerts = self.correlation_engine.process_event(event_obj)
        elif event_dict.get("success", True) and (event_dict.get("src_ip") or event_dict.get("device_ip")):
            try:
                temp_ev = UnifiedEvent.create(
                    raw_log=event_dict.get("raw_log", ""),
                    format_name=event_dict.get("format_name", "generic"),
                    source_id=event_dict.get("source_id", "demo"),
                    event_uid=event_dict.get("event_uid"),
                    src_ip=event_dict.get("src_ip"),
                    dst_ip=event_dict.get("dst_ip"),
                    src_port=event_dict.get("src_port"),
                    dst_port=event_dict.get("dst_port"),
                    protocol=event_dict.get("protocol"),
                    event_action=event_dict.get("event_action", "unknown"),
                    event_category=event_dict.get("event_category", "unknown"),
                    severity=event_dict.get("severity", 0),
                    severity_label=event_dict.get("severity_label"),
                    threat_name=event_dict.get("threat_name"),
                    weak_label=event_dict.get("weak_label"),
                    is_malicious=event_dict.get("is_malicious"),
                    threat_intel_score=event_dict.get("threat_intel_score"),
                    threat_intel_source=event_dict.get("threat_intel_source"),
                    mitre_technique_id=event_dict.get("mitre_technique_id"),
                    device_type=event_dict.get("device_type"),
                )
                new_alerts = self.correlation_engine.process_event(temp_ev)
            except Exception:
                pass

        if new_alerts:
            with self.lock:
                self.total_alerts += len(new_alerts)
                for a in new_alerts:
                    self.alerts_buffer.append(a.to_dict())

        # Broadcast outside the main lock
        dead_clients = []
        for q in clients_snapshot:
            try:
                q.put_nowait(event_dict)
                for a in new_alerts:
                    ad = dict(a.to_dict())
                    ad["_sse_type"] = "alert"
                    q.put_nowait(ad)
            except queue.Full:
                pass  # Client is too slow, skip event
            except Exception:
                dead_clients.append(q)

        if dead_clients:
            with self.lock:
                for q in dead_clients:
                    if q in self.sse_clients:
                        self.sse_clients.remove(q)

        return new_alerts

    def register_sse_client(self) -> queue.Queue[dict[str, Any] | None]:
        """Register a new SSE client subscriber queue."""
        q: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=2000)
        with self.lock:
            self.sse_clients.append(q)
        return q

    def unregister_sse_client(self, q: queue.Queue[dict[str, Any] | None]) -> None:
        """Unregister an SSE client subscriber queue."""
        with self.lock:
            if q in self.sse_clients:
                self.sse_clients.remove(q)

    def get_events(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Return the latest N events in reverse chronological order."""
        with self.lock:
            events = list(self.ring_buffer)
        events.reverse()  # Newest first
        return events[offset: offset + limit]

    def get_alerts(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Return the latest alerts in reverse chronological order."""
        with self.lock:
            alerts = list(self.alerts_buffer)
        alerts.reverse()
        return alerts[offset: offset + limit]

    def clear_alerts(self) -> None:
        """Clear alerts history and reset correlation state."""
        with self.lock:
            self.alerts_buffer.clear()
            self.total_alerts = 0
            self.correlation_engine.clear()

    def get_stats(self) -> dict[str, Any]:
        """Generate a complete statistical summary for the dashboard."""
        with self.lock:
            now_sec = int(time.time())
            # Calculate current EPS from last 5 seconds
            recent_count = self._current_bucket_count
            sec_span = 1
            for sec, count in reversed(self._eps_history):
                if now_sec - sec <= 5:
                    recent_count += count
                    sec_span += 1
                else:
                    break
            current_eps = round(recent_count / max(sec_span, 1), 1)

            # Top 10 source IPs
            top_src_ips = sorted(
                [{"ip": ip, "count": count} for ip, count in self.src_ip_counts.items()],
                key=lambda x: x["count"],
                reverse=True,
            )[:10]

            # Last 60 seconds EPS series for line chart
            history_dict = dict(self._eps_history)
            history_dict[self._last_bucket_sec] = self._current_bucket_count
            eps_series = []
            for s in range(now_sec - 59, now_sec + 1):
                eps_series.append({
                    "time": time.strftime("%H:%M:%S", time.localtime(s)),
                    "eps": history_dict.get(s, 0)
                })

            uptime = round(time.time() - self.start_time, 1)

            return {
                "total_events": self.total_received,
                "parsed_ok": self.total_parsed_ok,
                "parse_errors": self.total_parse_errors,
                "total_alerts": self.total_alerts,
                "active_alerts": len(self.alerts_buffer),
                "events_per_second": current_eps,
                "uptime_seconds": uptime,
                "by_severity": dict(self.by_severity),
                "by_format": dict(self.by_format),
                "by_action": dict(self.by_action),
                "by_label": dict(self.by_label),
                "top_source_ips": top_src_ips,
                "eps_series": eps_series,
                "buffer_size": len(self.ring_buffer),
                "active_sse_clients": len(self.sse_clients),
            }


# Global dashboard state singleton
_GLOBAL_STATE = DashboardState()


# ---------------------------------------------------------------------------
# Background File Tailer
# ---------------------------------------------------------------------------

class FileTailerThread(threading.Thread):
    """Background daemon thread that tails a JSON-Lines file and feeds events."""

    def __init__(self, file_path: Path | str, state: DashboardState) -> None:
        super().__init__(daemon=True, name="ULPF-FileTailer")
        self.file_path = Path(file_path)
        self.state = state
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        logger.info(f"FileTailer monitoring {self.file_path}")
        file_obj = None
        last_inode = None
        last_size = 0

        while not self._stop_event.is_set():
            try:
                if not self.file_path.exists():
                    time.sleep(0.5)
                    continue

                stat = self.file_path.stat()
                current_inode = getattr(stat, "st_ino", None)

                # Check for rotation or file opened for the first time
                if file_obj is None or (current_inode and current_inode != last_inode) or (stat.st_size < last_size):
                    if file_obj is not None:
                        try:
                            file_obj.close()
                        except Exception:
                            pass
                    file_obj = self.file_path.open("r", encoding="utf-8", errors="replace")
                    last_inode = current_inode
                    last_size = stat.st_size

                # Read available lines
                lines_read = 0
                while True:
                    line = file_obj.readline()
                    if not line:
                        break
                    lines_read += 1
                    line = line.strip()
                    if not line:
                        continue

                    # Try to parse as pre-formatted JSON event line
                    try:
                        ev_dict = json.loads(line)
                        if isinstance(ev_dict, dict):
                            self.state.add_event(ev_dict)
                            continue
                    except json.JSONDecodeError:
                        pass

                    # Raw log line fallback: process using ULPF registry
                    self._process_raw_line(line)

                last_size = self.file_path.stat().st_size
                if lines_read == 0:
                    time.sleep(0.2)

            except Exception as exc:
                logger.debug(f"FileTailer read error: {exc}")
                time.sleep(0.5)

        if file_obj:
            try:
                file_obj.close()
            except Exception:
                pass

    def _process_raw_line(self, line: str) -> None:
        registry = get_registry()
        parser = registry.detect(line)

        if not parser:
            self.state.add_event({
                "success": False,
                "raw_log": line,
                "error": "Unrecognized format",
                "format_name": "unknown",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            return

        fmt = parser.format_name
        res = parser.parse_line(line)
        if not res.success:
            self.state.add_event({
                "success": False,
                "raw_log": line,
                "error": res.error,
                "format_name": fmt,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            return

        canonical = _DEMO_MAPPER.map(res.fields)
        canonical.pop("raw_log", None)
        event = UnifiedEvent.create(
            raw_log=line,
            format_name=fmt,
            source_id="file_tailer",
            **canonical,
        )
        try:
            event = get_enrichment_pipeline().enrich(event)
        except Exception:
            pass
        d = event.to_dict()
        clean = {k: v for k, v in d.items() if v is not None and v != "" and v != {}}
        clean["success"] = True
        self.state.add_event(clean, event)


# ---------------------------------------------------------------------------
# HTTP Request Handler
# ---------------------------------------------------------------------------

class DashboardRequestHandler(SimpleHTTPRequestHandler):
    """Handles static assets, REST APIs, and SSE connections."""

    server_version = "ULPF-DemoServer/1.0"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # Serve static assets from demo directory
        self.demo_dir = Path(__file__).resolve().parent
        super().__init__(*args, directory=str(self.demo_dir), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress routine request logging to prevent console spam
        pass

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _send_json(self, data: Any, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # 1. Root / index.html
        if path in ("/", "/index.html"):
            index_path = self.demo_dir / "index.html"
            if index_path.exists():
                content = index_path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self.send_error(HTTPStatus.NOT_FOUND, "index.html not found")
                return

        # 2. SSE Stream: /api/events/stream
        if path == "/api/events/stream":
            self._handle_sse_stream()
            return

        # 3. Stats: /api/stats
        if path == "/api/stats":
            stats = _GLOBAL_STATE.get_stats()
            self._send_json(stats)
            return

        # 4. Events Buffer: /api/events
        if path == "/api/events":
            limit = int(query.get("limit", ["50"])[0])
            offset = int(query.get("offset", ["0"])[0])
            limit = max(1, min(limit, 500))
            offset = max(0, offset)
            events = _GLOBAL_STATE.get_events(limit=limit, offset=offset)
            self._send_json({"events": events, "count": len(events)})
            return

        # 5. Parsers List: /api/parsers
        if path == "/api/parsers":
            registry = get_registry()
            parsers = [
                {"name": name, "description": p.description, "format": p.format_name}
                for name, p in sorted(registry.list_parsers().items())
            ]
            self._send_json({"parsers": parsers, "count": len(parsers)})
            return

        # 6. Correlated Alerts Buffer: /api/alerts
        if path == "/api/alerts":
            limit = int(query.get("limit", ["50"])[0])
            offset = int(query.get("offset", ["0"])[0])
            limit = max(1, min(limit, 200))
            offset = max(0, offset)
            alerts = _GLOBAL_STATE.get_alerts(limit=limit, offset=offset)
            self._send_json({
                "alerts": alerts,
                "count": len(alerts),
                "total_alerts": _GLOBAL_STATE.total_alerts,
            })
            return

        # 6. ML Model Diagnostics: /api/model/info
        if path == "/api/model/info":
            try:
                from src.models import get_classifier
                info = get_classifier().get_model_info()
                self._send_json(info)
            except Exception as ex:
                self._send_json({"error": str(ex)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        # Static assets fallback
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        # Read body with length safety
        content_len_header = self.headers.get("Content-Length")
        if not content_len_header:
            self._send_json({"error": "Content-Length header required"}, HTTPStatus.LENGTH_REQUIRED)
            return

        try:
            content_len = int(content_len_header)
            if content_len > 15 * 1024 * 1024:  # 15 MB limit
                self._send_json({"error": "Payload too large (max 15MB)"}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            body_bytes = self.rfile.read(content_len)
            raw_text = body_bytes.decode("utf-8", errors="replace")
        except Exception as exc:
            self._send_json({"error": f"Failed reading request: {exc}"}, HTTPStatus.BAD_REQUEST)
            return

        # 1. Live Ingest Endpoint: /api/ingest
        if path == "/api/ingest":
            self._handle_api_ingest(raw_text)
            return

        # 2. Interactive Process Endpoint: /api/process
        if path == "/api/process":
            self._handle_api_process(raw_text)
            return

        # 3. File Upload helper: /api/upload
        if path == "/api/upload":
            self._send_json({"content": raw_text, "lines": len(raw_text.splitlines())})
            return

        # 4. Clear Alerts / Reset Correlation: /api/alerts/clear
        if path == "/api/alerts/clear":
            _GLOBAL_STATE.clear_alerts()
            self._send_json({"status": "ok", "message": "Alerts and correlation state reset"})
            return

        # 5. Attack Simulation: /api/simulate
        if path == "/api/simulate":
            self._handle_api_simulate(raw_text)
            return

        self.send_error(HTTPStatus.NOT_FOUND, f"Endpoint {path} not found")

    def _handle_sse_stream(self) -> None:
        """Streams normalized events to browser via Server-Sent Events (SSE)."""
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._send_cors_headers()
        self.end_headers()

        # Send initial connected event
        try:
            initial_payload = json.dumps({
                "status": "connected",
                "server_time": time.time(),
                "total_events": _GLOBAL_STATE.total_received,
                "total_alerts": _GLOBAL_STATE.total_alerts,
            })
            self.wfile.write(f"event: connected\ndata: {initial_payload}\n\n".encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return

        q = _GLOBAL_STATE.register_sse_client()
        try:
            while True:
                try:
                    # Wait up to 15 seconds for an event
                    ev = q.get(timeout=15.0)
                    if ev is None:
                        break  # Server shutting down
                    payload = json.dumps(ev)
                    if ev.get("_sse_type") == "alert":
                        msg = f"event: alert\ndata: {payload}\n\n"
                    else:
                        msg = f"event: event\ndata: {payload}\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    # Send periodic ping heartbeat to keep connection active
                    ping_payload = json.dumps({
                        "timestamp": time.time(),
                        "eps": _GLOBAL_STATE.get_stats()["events_per_second"],
                        "total_alerts": _GLOBAL_STATE.total_alerts,
                    })
                    self.wfile.write(f"event: ping\ndata: {ping_payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            _GLOBAL_STATE.unregister_sse_client(q)

    def _ingest_lines(self, lines: list[str]) -> int:
        """Internal helper to parse and ingest a list of lines without sending an HTTP response."""
        ingested_count = 0
        registry = get_registry()

        for line in lines:
            if not line:
                continue
            # Check if line is already JSON
            if line.startswith("{") and line.endswith("}"):
                try:
                    ev_dict = json.loads(line)
                    if isinstance(ev_dict, dict) and ("event_uid" in ev_dict or "raw_log" in ev_dict):
                        ev_dict.setdefault("success", True)
                        _GLOBAL_STATE.add_event(ev_dict)
                        ingested_count += 1
                        continue
                except json.JSONDecodeError:
                    pass

            # Detect format and parse
            parser = registry.detect(line)
            if not parser:
                with _GLOBAL_STATE.lock:
                    _GLOBAL_STATE.total_received += 1
                    _GLOBAL_STATE.total_parse_errors += 1
                continue

            fmt = parser.format_name
            res = parser.parse_line(line)
            if not res.success:
                with _GLOBAL_STATE.lock:
                    _GLOBAL_STATE.total_received += 1
                    _GLOBAL_STATE.total_parse_errors += 1
                continue

            canonical = _DEMO_MAPPER.map(res.fields)
            canonical.pop("raw_log", None)
            event = UnifiedEvent.create(
                raw_log=line,
                format_name=fmt,
                source_id="api_ingest",
                **canonical,
            )
            try:
                event = get_enrichment_pipeline().enrich(event)
            except Exception:
                pass
            try:
                from src.models import get_classifier
                event = get_classifier().annotate_event(event)
            except Exception:
                pass

            sev_lbl = str(event.severity_label or "").lower()
            act = str(event.event_action or "").lower()
            lbl = str(event.weak_label or "").lower()
            is_threat = (
                sev_lbl in ("critical", "high", "medium", "alert", "emergency", "warning", "warn")
                or (isinstance(event.severity, int) and 0 < event.severity <= 4)
                or act in ("deny", "block", "drop", "alert", "quarantine", "reject", "reset")
                or lbl in ("attack", "malicious", "threat")
                or event.is_malicious is True
                or bool(event.mitre_technique_id)
                or (event.threat_intel_score is not None and event.threat_intel_score >= 0.5)
                or bool(event.threat_name and str(event.threat_name).strip() not in ("-", "None", "unknown", ""))
            )

            d = event.to_dict()
            clean = {k: v for k, v in d.items() if v is not None and v != "" and v != {}}
            clean["success"] = True
            clean["is_threat"] = is_threat
            _GLOBAL_STATE.add_event(clean, event)
            ingested_count += 1

        return ingested_count

    def _handle_api_ingest(self, raw_body: str) -> None:
        """Handles POST /api/ingest: raw line, batch lines, or JSON objects."""
        lines = [ln.strip() for ln in raw_body.splitlines() if ln.strip()]
        if not lines:
            self._send_json({"error": "No log content provided"}, HTTPStatus.BAD_REQUEST)
            return

        ingested_count = self._ingest_lines(lines)

        self._send_json({
            "status": "ok",
            "ingested": ingested_count,
            "total_events": _GLOBAL_STATE.total_received,
        })

    def _handle_api_process(self, raw_body: str) -> None:
        """Handles POST /api/process: interactive test playground parser."""
        try:
            req = json.loads(raw_body)
            raw_text = req.get("lines", "").strip()
            forced_format = req.get("format", "auto").strip().lower()
        except Exception:
            raw_text = raw_body.strip()
            forced_format = "auto"

        if not raw_text:
            self._send_json({"error": "No log lines provided"}, HTTPStatus.BAD_REQUEST)
            return

        lines = [ln.rstrip("\r\n") for ln in raw_text.splitlines() if ln.strip()]
        if not lines:
            self._send_json({"error": "No non-empty lines found"}, HTTPStatus.BAD_REQUEST)
            return

        registry = get_registry()
        t0 = time.perf_counter()
        events_out = []
        parse_ok = 0
        parse_err = 0
        threats_count = 0
        severity_counts: dict[str, int] = collections.defaultdict(int)
        format_counts: dict[str, int] = collections.defaultdict(int)

        forced_parser = registry.get(forced_format) if forced_format != "auto" else None

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue

            target_parser = forced_parser if forced_parser else registry.detect(line_str)
            if not target_parser:
                parse_err += 1
                continue

            res = target_parser.parse_line(line_str)
            if not res.success:
                parse_err += 1
                continue

            fmt_name = target_parser.format_name
            format_counts[fmt_name] += 1

            canonical = _DEMO_MAPPER.map(res.fields)
            canonical.pop("raw_log", None)
            event = UnifiedEvent.create(
                raw_log=line_str,
                format_name=fmt_name,
                source_id="interactive_demo",
                **canonical,
            )
            try:
                event = get_enrichment_pipeline().enrich(event)
            except Exception:
                pass
            try:
                from src.models import get_classifier
                event = get_classifier().annotate_event(event)
            except Exception:
                pass
            parse_ok += 1

            sev = str(event.severity_label or event.severity or "informational").lower()
            severity_counts[sev] += 1

            # Determine threat status
            sev_lbl = str(event.severity_label or "").lower()
            act = str(event.event_action or "").lower()
            lbl = str(event.weak_label or "").lower()
            is_threat = (
                sev_lbl in ("critical", "high", "medium", "alert", "emergency", "warning", "warn")
                or (isinstance(event.severity, int) and 0 < event.severity <= 4)
                or act in ("deny", "block", "drop", "alert", "quarantine", "reject", "reset")
                or lbl in ("attack", "malicious", "threat")
                or event.is_malicious is True
                or bool(event.mitre_technique_id)
                or (event.threat_intel_score is not None and event.threat_intel_score >= 0.5)
                or bool(event.threat_name and str(event.threat_name).strip() not in ("-", "None", "unknown", ""))
            )
            if is_threat:
                threats_count += 1

            d = event.to_dict()
            clean = {k: v for k, v in d.items() if v is not None and v != "" and v != {}}
            clean["success"] = True
            clean["is_threat"] = is_threat
            clean["format_name"] = fmt_name
            events_out.append(clean)

        elapsed = time.perf_counter() - t0
        eps = round(parse_ok / elapsed, 0) if elapsed > 0 else 0

        dominant_format = max(format_counts, key=lambda k: format_counts[k]) if format_counts else (forced_format if forced_format != "auto" else "unknown")
        if len(format_counts) > 1:
            display_format = f"Multi-Vendor ({len(format_counts)} formats)"
        else:
            display_format = dominant_format

        self._send_json({
            "format_detected": display_format,
            "dominant_format": dominant_format,
            "format_counts": dict(format_counts),
            "format_auto": forced_format == "auto",
            "stats": {
                "total_lines": len(lines),
                "parsed_ok": parse_ok,
                "parse_errors": parse_err,
                "threats_count": threats_count,
                "benign_count": parse_ok - threats_count,
                "success_rate": round(100 * parse_ok / len(lines), 1) if lines else 0,
                "elapsed_ms": round(elapsed * 1000, 1),
                "events_per_sec": int(eps),
            },
            "severity_counts": dict(severity_counts),
            "events": events_out,
        })

    def _handle_api_simulate(self, raw_body: str) -> None:
        """Simulate realistic multi-event attack scenarios to demonstrate correlation in real-time."""
        try:
            req = json.loads(raw_body) if raw_body else {}
        except Exception:
            req = {}

        attack_type = req.get("attack_type", "port_scan")
        target_ip = req.get("target_ip", "10.0.1.50")
        attacker_ip = req.get("src_ip")

        logs_to_feed: list[str] = []

        if attack_type == "port_scan":
            attacker_ip = attacker_ip or "198.51.100.99"
            ports = [21, 22, 23, 80, 443, 8080, 8443]
            for p in ports:
                logs_to_feed.append(
                    f"Jan 18 10:22:15 firewall-01 %ASA-4-106023: Deny tcp src outside:{attacker_ip}/49152 "
                    f"dst inside:{target_ip}/{p} by access-group 'outside_in' [0x0, 0x0]"
                )

        elif attack_type == "brute_force":
            attacker_ip = attacker_ip or "198.51.100.88"
            users = ["admin", "root", "oracle", "administrator", "service_user", "test"]
            for u in users:
                logs_to_feed.append(
                    f"Jan 18 10:22:15 firewall-01 %ASA-6-113005: AAA user authentication Rejected : "
                    f"reason = 'Invalid password' : server = 10.0.1.10 : user = {u} : user IP = {attacker_ip}"
                )

        elif attack_type == "cross_device":
            attacker_ip = attacker_ip or "198.51.100.77"
            # 1. Cisco ASA Firewall drop
            logs_to_feed.append(
                f"Jan 18 10:22:15 firewall-01 %ASA-4-106023: Deny tcp src outside:{attacker_ip}/51234 "
                f"dst inside:{target_ip}/443 by access-group 'outside_in' [0x0, 0x0]"
            )
            # 2. Snort / Suricata IDS alert
            logs_to_feed.append(
                f'01/18-10:22:16.123456 [**] [1:1000001:1] ET EXPLOIT Apache Log4j RCE Attempt [**] '
                f'[Classification: Web Application Attack] [Priority: 1] {{TCP}} {attacker_ip}:51235 -> {target_ip}:443'
            )

        elif attack_type == "c2_beacon":
            attacker_ip = attacker_ip or "198.51.100.12"
            for _ in range(3):
                logs_to_feed.append(
                    f"Jan 18 10:22:15 firewall-01 %ASA-6-302013: Built outbound TCP connection 98765 for "
                    f"inside:10.0.1.50/49152 to outside:{attacker_ip}/443"
                )

        elif attack_type == "exploit_followup":
            attacker_ip = attacker_ip or "198.51.100.66"
            logs_to_feed.append(
                f'01/18-10:22:16.123456 [**] [1:1000002:1] ET WEB_SPECIFIC_APPS SQL Injection in URI [**] '
                f'[Classification: Web Application Attack] [Priority: 1] {{TCP}} {attacker_ip}:53111 -> {target_ip}:80'
            )
            logs_to_feed.append(
                f"Jan 18 10:22:18 firewall-01 %ASA-4-106023: Deny tcp src outside:{attacker_ip}/53112 "
                f"dst inside:{target_ip}/445 by access-group 'outside_in' [0x0, 0x0]"
            )
        else:
            self._send_json({"error": f"Unknown attack simulation type: {attack_type}"}, HTTPStatus.BAD_REQUEST)
            return

        total_alerts_before = _GLOBAL_STATE.total_alerts
        ingested = self._ingest_lines(logs_to_feed)
        total_alerts_after = _GLOBAL_STATE.total_alerts

        self._send_json({
            "status": "ok",
            "simulation": attack_type,
            "attacker_ip": attacker_ip,
            "logs_injected": ingested,
            "alerts_triggered": total_alerts_after - total_alerts_before,
            "total_alerts": _GLOBAL_STATE.total_alerts,
        })


# ---------------------------------------------------------------------------
# Server Starter Function
# ---------------------------------------------------------------------------

def start_server(
    host: str = "0.0.0.0",
    port: int = 7000,
    input_file: str | Path | None = None,
) -> None:
    """Start the ULPF Dashboard Server."""
    server_address = (host, port)
    server = ThreadingHTTPServer(server_address, DashboardRequestHandler)

    tailer_thread = None
    if input_file:
        tailer_thread = FileTailerThread(file_path=input_file, state=_GLOBAL_STATE)
        tailer_thread.start()

    # ASCII-safe console greeting for Windows
    print("\n" + "=" * 65)
    print("  ULPF -- Universal Log Pre-processing Framework")
    print("  Real-Time Visualization & Operations Dashboard")
    print("=" * 65)
    print(f"  Listening on: http://{host}:{port}")
    if input_file:
        print(f"  Tailing file: {input_file}")
    registry = get_registry()
    print(f"  Parsers registered ({len(registry)}): {', '.join(sorted(registry.list_parsers().keys()))}")
    print("  Press Ctrl+C to stop server.\n")

    def handle_signal(sig: int, frame: Any) -> None:
        print("\n[ULPF] Shutting down demo server gracefully...")
        if tailer_thread:
            tailer_thread.stop()
        # Wake up all SSE queues with None sentinel
        with _GLOBAL_STATE.lock:
            for q in _GLOBAL_STATE.sse_clients:
                try:
                    q.put_nowait(None)
                except Exception:
                    pass
        threading.Thread(target=server.shutdown).start()

    if threading.current_thread() is threading.main_thread():
        try:
            signal.signal(signal.SIGINT, handle_signal)
            signal.signal(signal.SIGTERM, handle_signal)
        except (ValueError, AttributeError):
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        handle_signal(0, None)
    finally:
        server.server_close()
        if tailer_thread:
            tailer_thread.join(timeout=2.0)
        print("[ULPF] Demo server stopped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ULPF Live Visualization Dashboard Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=7000, help="Listen port (default: 7000)")
    parser.add_argument("--input", "-i", default=None, help="JSON-Lines output file to tail (e.g. outputs/live.jsonl)")
    args = parser.parse_args()

    start_server(host=args.host, port=args.port, input_file=args.input)
