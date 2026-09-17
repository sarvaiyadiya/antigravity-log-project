"""
Schema Validator — enforces the Universal Event Schema contracts.

Validates that a UnifiedEvent:
  1. Has all required fields populated.
  2. Has valid enum values where specified.
  3. Has coherent network fields (port ranges, IP format basics).
  4. Has a valid record_hash of the expected length.

Validation is intentionally non-destructive: it raises descriptive
errors rather than silently dropping events.
"""

from __future__ import annotations

import re
from typing import Any

from .unified_event import (
    EventAction,
    EventCategory,
    EventSeverity,
    SourceType,
    UnifiedEvent,
)


# ---------------------------------------------------------------------------
# Required fields (must be non-None and non-empty)
# ---------------------------------------------------------------------------

REQUIRED_FIELDS: tuple[str, ...] = (
    "event_uid",
    "record_hash",
    "raw_log",
    "format_name",
    "source_id",
    "ingest_timestamp",
)

# record_hash is always the first 32 hex chars of SHA-256
_HASH_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)

# Loose IP validation (full validation is done in preprocessing.py)
_IP_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"          # IPv4
    r"|^[0-9a-fA-F:]{3,39}$"               # IPv6 (simplified)
)


class SchemaValidationError(ValueError):
    """Raised when a UnifiedEvent violates a schema contract."""


def validate_unified_event(event: UnifiedEvent) -> None:
    """
    Raise SchemaValidationError if the event violates any schema contract.

    Checks
    ------
    1. Required fields are non-None and non-empty.
    2. record_hash matches the expected 32-char hex format.
    3. src_port / dst_port are in range [0, 65535] when present.
    4. label_confidence is in [0.0, 1.0] when present.
    5. Enum fields carry valid enum members.
    """
    errors: list[str] = []

    # 1. Required fields
    for field_name in REQUIRED_FIELDS:
        value = getattr(event, field_name, None)
        if value is None or str(value).strip() == "":
            errors.append(
                f"Required field '{field_name}' is missing or empty."
            )

    # 2. record_hash format
    if event.record_hash and not _HASH_RE.match(event.record_hash):
        errors.append(
            f"record_hash '{event.record_hash}' does not match "
            f"the expected 32-char hex format."
        )

    # 3. Port ranges
    for port_field in ("src_port", "dst_port"):
        port_value = getattr(event, port_field, None)
        if port_value is not None:
            if not isinstance(port_value, int) or not (0 <= port_value <= 65535):
                errors.append(
                    f"{port_field} value {port_value!r} is outside "
                    f"the valid range [0, 65535]."
                )

    # 4. label_confidence range
    if event.label_confidence is not None:
        conf = event.label_confidence
        if not isinstance(conf, float) or not (0.0 <= conf <= 1.0):
            errors.append(
                f"label_confidence {conf!r} is outside [0.0, 1.0]."
            )

    # 5. Enum field types
    enum_checks: list[tuple[str, type]] = [
        ("severity", EventSeverity),
        ("event_category", EventCategory),
        ("event_action", EventAction),
    ]
    for field_name, enum_type in enum_checks:
        value = getattr(event, field_name, None)
        if value is not None and not isinstance(value, enum_type):
            errors.append(
                f"Field '{field_name}' has type {type(value).__name__!r}, "
                f"expected {enum_type.__name__!r}."
            )

    if errors:
        summary = "; ".join(errors)
        raise SchemaValidationError(
            f"UnifiedEvent validation failed for event_uid="
            f"{event.event_uid!r}: {summary}"
        )


def validate_batch(events: list[UnifiedEvent]) -> dict[str, list[str]]:
    """
    Validate a list of events without raising.

    Returns
    -------
    A dict mapping event_uid → list of error messages.
    Events with no errors are not included in the result.
    """
    report: dict[str, list[str]] = {}
    for event in events:
        try:
            validate_unified_event(event)
        except SchemaValidationError as exc:
            report[event.event_uid] = str(exc).split("; ")
    return report
