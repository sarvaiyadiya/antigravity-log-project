"""
ULPF Demo Server — Interactive Web Dashboard
=============================================
A Flask-based web UI that lets the panel:
  1. Paste any raw log lines into a text area
  2. Upload a log file from disk
  3. See auto-detected format, parsed events, and statistics in real-time

Run:
    python demo/server.py

Then open: http://localhost:5000
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure project root is on path
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder=str(Path(__file__).parent), static_url_path="")

# ── ULPF imports ──────────────────────────────────────────────────────────────
from src.ingestion import parsers as _reg   # auto-registers all parsers
from src.ingestion.parser_registry import get_registry
from src.ingestion.format_detector import detect_format_from_text
from src.schema.unified_event import UnifiedEvent
from src.schema.field_mapper import FieldMapper
import dataclasses

# Passthrough mapper: maps every UES field name to itself so that
# parsers which already emit canonical names (src_ip, dst_ip, etc.)
# land on the real event fields rather than extra_fields.
_UES_FIELD_NAMES = [f.name for f in dataclasses.fields(UnifiedEvent)]
_PASSTHROUGH_MAP = {name: name for name in _UES_FIELD_NAMES}
_DEMO_MAPPER = FieldMapper(
    source_id="demo",
    vendor=None,
    device_type="generic",
    field_map=_PASSTHROUGH_MAP,
)



# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _detect_from_lines(lines: list[str]) -> str | None:
    """Run format detection against the first 10 non-blank lines."""
    registry = get_registry()
    scores: dict[str, int] = {}
    for parser in registry.list_parsers().values():
        hits = sum(1 for line in lines[:10] if parser.can_parse(line))
        if hits > 0:
            scores[parser.format_name] = hits
    if not scores:
        return None
    return max(scores, key=lambda k: scores[k])


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(str(Path(__file__).parent), "index.html")


@app.route("/api/parsers")
def api_parsers():
    """Return list of registered parsers."""
    registry = get_registry()
    return jsonify({
        "parsers": [
            {"name": name, "description": p.description}
            for name, p in sorted(registry.list_parsers().items())
        ]
    })


@app.route("/api/process", methods=["POST"])
def api_process():
    """
    Process raw log lines.

    Accepts JSON body:
        { "lines": "<raw log text>", "format": "auto" | "syslog" | "cef" | ... }

    Returns:
        { "format_detected": "...", "events": [...], "stats": {...} }
    """
    body = request.get_json(force=True, silent=True) or {}
    raw_text: str = body.get("lines", "").strip()
    forced_format: str = body.get("format", "auto").strip().lower()

    if not raw_text:
        return jsonify({"error": "No log lines provided."}), 400

    lines = [ln.rstrip("\r\n") for ln in raw_text.splitlines() if ln.strip()]
    if not lines:
        return jsonify({"error": "No non-empty lines found."}), 400

    # ── Format detection ──────────────────────────────────────────────────
    registry = get_registry()

    if forced_format == "auto":
        format_name = _detect_from_lines(lines) or "unknown"
    else:
        format_name = forced_format

    parser = registry.get(format_name) if format_name != "unknown" else None

    # ── Parse each line ───────────────────────────────────────────────────
    t0 = time.perf_counter()
    events_out = []
    parse_ok = 0
    parse_err = 0
    severity_counts: dict[str, int] = {}

    for line in lines:
        if not line.strip():
            continue

        if parser is None:
            parse_err += 1
            events_out.append({
                "success": False,
                "raw_log": line,
                "error": f"No parser available for format '{format_name}'",
            })
            continue

        result = parser.parse_line(line.strip())
        if not result.success:
            parse_err += 1
            events_out.append({
                "success": False,
                "raw_log": line,
                "error": result.error or "Parse failed",
            })
            continue

        # Map to UES and create UnifiedEvent
        canonical = _DEMO_MAPPER.map(result.fields)
        event = UnifiedEvent.create(
            raw_log=line.strip(),
            format_name=format_name,
            source_id="demo",
            **canonical,
        )
        parse_ok += 1

        # Track severity distribution
        sev = event.severity_label or (str(event.severity) if event.severity else "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Serialize — only include non-None fields for cleaner display
        d = event.to_dict()
        events_out.append({
            "success": True,
            **{k: v for k, v in d.items() if v is not None and v != {} and v != ""},
        })

    elapsed = time.perf_counter() - t0
    eps = round(parse_ok / elapsed, 0) if elapsed > 0 else 0

    return jsonify({
        "format_detected": format_name,
        "format_auto": forced_format == "auto",
        "stats": {
            "total_lines": len(lines),
            "parsed_ok": parse_ok,
            "parse_errors": parse_err,
            "success_rate": round(100 * parse_ok / len(lines), 1) if lines else 0,
            "elapsed_ms": round(elapsed * 1000, 1),
            "events_per_sec": int(eps),
        },
        "severity_counts": severity_counts,
        "events": events_out,
    })


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """Accept a file upload and return its text content for processing."""
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded."}), 400
    try:
        content = file.read().decode("utf-8", errors="replace")
        return jsonify({"content": content, "filename": file.filename})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 62)
    print("  ULPF — Universal Log Pre-processing Framework v1.0")
    print("  Interactive Demo Dashboard")
    print("=" * 62)
    print("\n  >> Open browser at:  http://localhost:5000\n")

    registry = get_registry()
    print(f"  Loaded {len(registry)} parsers: "
          + ", ".join(sorted(registry.list_parsers().keys())))
    print()

    app.run(host="0.0.0.0", port=5000, debug=False)
