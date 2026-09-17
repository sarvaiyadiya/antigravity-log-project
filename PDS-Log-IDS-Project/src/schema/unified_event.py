"""
Universal Event Schema (UES) — the canonical normalized event structure
for the Universal Log Pre-processing Framework (ULPF).

Design principles:
  - PS requirement (a): raw_log preserves the complete original line.
  - PS requirement (d): event_uid + record_hash maintain traceability.
  - PS requirement (c): all source-specific fields map into this schema.
  - Every field has a documented type, meaning, and allowed values.

The schema is inspired by OCSF (Open Cybersecurity Schema Framework)
and Elastic Common Schema (ECS) but remains vendor-agnostic.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class EventSeverity(int, Enum):
    """Numeric severity aligned with syslog and OCSF conventions."""
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 4
    HIGH = 6
    CRITICAL = 8
    EMERGENCY = 10


class EventCategory(str, Enum):
    """Broad event category for cross-source correlation."""
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    THREAT = "threat"
    POLICY = "policy"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class EventAction(str, Enum):
    """Disposition or action taken by the reporting device."""
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    ALERT = "alert"
    BLOCK = "block"
    RESET = "reset"
    UNKNOWN = "unknown"


class SourceType(str, Enum):
    """Broad classification of the log-generating device type."""
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    PROXY = "proxy"
    ROUTER_SWITCH = "router_switch"
    VPN = "vpn"
    WEB_APPLICATION_FIREWALL = "waf"
    ENDPOINT = "endpoint"
    GENERIC = "generic"


# ---------------------------------------------------------------------------
# Universal Event dataclass
# ---------------------------------------------------------------------------

@dataclass
class UnifiedEvent:
    """
    A single normalized security event in the Universal Event Schema.

    Required fields
    ---------------
    event_uid       : ULPF-generated globally unique identifier.
    record_hash     : SHA-256 (first 32 hex chars) of the raw log content.
                      Enables deduplication and traceability (PS req d).
    raw_log         : Complete, unmodified original log line.
                      Lossless preservation (PS req a).
    format_name     : Name of the parser that produced this event.
    source_id       : Logical source identifier from the source config.
    ingest_timestamp: UTC datetime when ULPF ingested this event.

    Optional / derived fields
    -------------------------
    All remaining fields are populated by parsers on a best-effort basis.
    Missing values remain None so downstream analytics can distinguish
    "not present" from "zero" or "empty string".
    """

    # --- Identity & provenance (PS req a, d) ---
    event_uid: str                      # ULPF unique ID
    record_hash: str                    # content fingerprint
    raw_log: str                        # original, unmodified
    format_name: str                    # parser that produced this
    source_id: str                      # logical source name
    ingest_timestamp: datetime          # UTC ingestion time

    # --- Temporal ---
    timestamp_utc: datetime | None = None   # event time (normalized to UTC)
    timestamp_raw: str | None = None        # original timestamp string

    # --- Device / source metadata ---
    vendor: str | None = None           # "cisco", "palo_alto", "snort", etc.
    device_type: SourceType | None = None  # firewall / ids_ips / proxy …
    device_hostname: str | None = None
    device_ip: str | None = None
    observer_name: str | None = None    # reporting sensor / collector name

    # --- Network 5-tuple ---
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None         # "tcp", "udp", "icmp", "unknown"

    # --- Application / transport ---
    http_method: str | None = None
    http_url: str | None = None
    http_status: int | None = None
    user_agent: str | None = None
    username: str | None = None

    # --- Threat classification ---
    event_category: EventCategory = EventCategory.UNKNOWN
    event_action: EventAction = EventAction.UNKNOWN
    severity: EventSeverity = EventSeverity.UNKNOWN
    severity_label: str | None = None  # original vendor severity label
    threat_name: str | None = None
    threat_signature_id: str | None = None
    threat_signature_name: str | None = None

    # --- Weak labeling (from existing labeling.py) ---
    weak_label: str | None = None           # "attack", "benign", "uncertain"
    label_confidence: float | None = None   # 0.0 – 1.0
    evidence_codes: str | None = None       # pipe-separated codes
    label_conflict: bool | None = None

    # --- Source-specific overflow ---
    extra_fields: dict[str, Any] = field(default_factory=dict)
    # Any field the parser captures that has no canonical mapping goes here.
    # This ensures zero information loss (PS req a).

    # ---------------------------------------------------------------------------
    # Factory helpers
    # ---------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        raw_log: str,
        format_name: str,
        source_id: str,
        **kwargs: Any,
    ) -> "UnifiedEvent":
        """
        Construct a UnifiedEvent, auto-generating event_uid, record_hash,
        and ingest_timestamp if not supplied.
        """
        event_uid = kwargs.pop("event_uid", str(uuid.uuid4()))
        record_hash = kwargs.pop(
            "record_hash",
            _compute_record_hash(raw_log),
        )
        ingest_timestamp = kwargs.pop(
            "ingest_timestamp",
            datetime.now(timezone.utc),
        )

        return cls(
            event_uid=event_uid,
            record_hash=record_hash,
            raw_log=raw_log,
            format_name=format_name,
            source_id=source_id,
            ingest_timestamp=ingest_timestamp,
            **kwargs,
        )

    # ---------------------------------------------------------------------------
    # Serialisation helpers
    # ---------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dictionary of all fields."""
        raw = asdict(self)
        # Convert enums → string values
        for key, value in raw.items():
            if isinstance(value, Enum):
                raw[key] = value.value
        # Convert datetimes → ISO strings
        for key in ("timestamp_utc", "ingest_timestamp"):
            if raw[key] is not None and isinstance(raw[key], datetime):
                raw[key] = raw[key].isoformat()
        return raw

    def to_json(self) -> str:
        """Return a compact JSON string representation."""
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def __repr__(self) -> str:
        return (
            f"UnifiedEvent("
            f"uid={self.event_uid[:8]}…, "
            f"format={self.format_name!r}, "
            f"src={self.src_ip}, "
            f"label={self.weak_label})"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_record_hash(raw_log: str) -> str:
    """
    Compute a stable 128-bit (32 hex char) SHA-256 fingerprint of the
    raw log content. Matches the existing provenance.py convention.
    """
    full = hashlib.sha256(raw_log.encode("utf-8", errors="replace")).hexdigest()
    return full[:32]
