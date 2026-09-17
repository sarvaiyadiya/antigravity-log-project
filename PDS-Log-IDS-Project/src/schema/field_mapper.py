"""
Field Mapper — translates source-specific field names and values
into the Universal Event Schema (UES) canonical field names.

Each log source has its own naming conventions:
  - Cisco ASA uses "src" for source IP; UES uses "src_ip"
  - Snort uses "priority" for severity; UES uses "severity"
  - CEF uses "spt" for source port; UES uses "src_port"

FieldMapper loads per-source YAML configs and resolves these
mappings at parse time.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path
from typing import Any

import yaml

from .unified_event import (
    EventAction,
    EventCategory,
    EventSeverity,
    SourceType,
    UnifiedEvent,
)

# Set of valid field names on UnifiedEvent — built once at import time.
# Used by FieldMapper.map() to distinguish real UES fields from
# source-specific overflow names (which go into extra_fields).
_UES_FIELDS: frozenset[str] = frozenset(
    f.name for f in dataclasses.fields(UnifiedEvent)
)


# ---------------------------------------------------------------------------
# Severity conversion helpers
# ---------------------------------------------------------------------------

# Maps common vendor severity labels to UES EventSeverity
_SEVERITY_TEXT_MAP: dict[str, EventSeverity] = {
    # Syslog
    "emerg": EventSeverity.EMERGENCY,
    "alert": EventSeverity.CRITICAL,
    "crit": EventSeverity.CRITICAL,
    "critical": EventSeverity.CRITICAL,
    "err": EventSeverity.HIGH,
    "error": EventSeverity.HIGH,
    "warning": EventSeverity.MEDIUM,
    "warn": EventSeverity.MEDIUM,
    "notice": EventSeverity.LOW,
    "info": EventSeverity.INFORMATIONAL,
    "informational": EventSeverity.INFORMATIONAL,
    "debug": EventSeverity.INFORMATIONAL,
    # Common vendor labels
    "high": EventSeverity.HIGH,
    "medium": EventSeverity.MEDIUM,
    "low": EventSeverity.LOW,
    "unknown": EventSeverity.UNKNOWN,
    # Snort priorities (1=high … 3=low)
    "1": EventSeverity.HIGH,
    "2": EventSeverity.MEDIUM,
    "3": EventSeverity.LOW,
    # CEF severities (0-10 numeric strings)
    "0": EventSeverity.INFORMATIONAL,
    "4": EventSeverity.MEDIUM,
    "6": EventSeverity.HIGH,
    "8": EventSeverity.CRITICAL,
    "10": EventSeverity.EMERGENCY,
}

_ACTION_TEXT_MAP: dict[str, EventAction] = {
    "allow": EventAction.ALLOW,
    "permitted": EventAction.ALLOW,
    "accept": EventAction.ALLOW,
    "deny": EventAction.DENY,
    "denied": EventAction.DENY,
    "block": EventAction.BLOCK,
    "blocked": EventAction.BLOCK,
    "drop": EventAction.DROP,
    "dropped": EventAction.DROP,
    "alert": EventAction.ALERT,
    "reset": EventAction.RESET,
    "teardown": EventAction.DROP,
}

_CATEGORY_TEXT_MAP: dict[str, EventCategory] = {
    "network": EventCategory.NETWORK,
    "firewall": EventCategory.NETWORK,
    "ids": EventCategory.THREAT,
    "ips": EventCategory.THREAT,
    "intrusion": EventCategory.THREAT,
    "threat": EventCategory.THREAT,
    "auth": EventCategory.AUTHENTICATION,
    "authentication": EventCategory.AUTHENTICATION,
    "login": EventCategory.AUTHENTICATION,
    "policy": EventCategory.POLICY,
    "system": EventCategory.SYSTEM,
}

_DEVICE_TYPE_MAP: dict[str, SourceType] = {
    "firewall": SourceType.FIREWALL,
    "ids": SourceType.IDS_IPS,
    "ips": SourceType.IDS_IPS,
    "ids_ips": SourceType.IDS_IPS,
    "proxy": SourceType.PROXY,
    "router": SourceType.ROUTER_SWITCH,
    "switch": SourceType.ROUTER_SWITCH,
    "vpn": SourceType.VPN,
    "waf": SourceType.WEB_APPLICATION_FIREWALL,
    "endpoint": SourceType.ENDPOINT,
    "generic": SourceType.GENERIC,
}


class FieldMapper:
    """
    Translates a raw parsed dict into UES canonical field names
    and converts values to the appropriate types.

    Usage
    -----
    mapper = FieldMapper.from_yaml("configs/sources/cef_ids.yaml")
    canonical = mapper.map(raw_fields_dict)
    """

    def __init__(
        self,
        source_id: str,
        vendor: str | None,
        device_type: str | None,
        field_map: dict[str, str],
        default_category: str = "unknown",
        default_action: str = "unknown",
        default_severity: str = "unknown",
    ) -> None:
        self.source_id = source_id
        self.vendor = vendor
        self.device_type = _DEVICE_TYPE_MAP.get(
            (device_type or "").lower(),
            SourceType.GENERIC,
        )
        self._field_map = field_map  # raw_name → ues_name
        self._default_category = _CATEGORY_TEXT_MAP.get(
            default_category.lower(), EventCategory.UNKNOWN
        )
        self._default_action = _ACTION_TEXT_MAP.get(
            default_action.lower(), EventAction.UNKNOWN
        )
        self._default_severity = _SEVERITY_TEXT_MAP.get(
            default_severity.lower(), EventSeverity.UNKNOWN
        )

    @classmethod
    def from_yaml(cls, config_path: str | Path) -> "FieldMapper":
        """Load a FieldMapper from a YAML source-config file."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Source config not found: {config_path}"
            )
        with path.open(encoding="utf-8") as file:
            cfg = yaml.safe_load(file) or {}

        return cls(
            source_id=cfg.get("source_id", path.stem),
            vendor=cfg.get("vendor"),
            device_type=cfg.get("device_type"),
            field_map=cfg.get("field_map", {}),
            default_category=cfg.get("default_category", "unknown"),
            default_action=cfg.get("default_action", "unknown"),
            default_severity=cfg.get("default_severity", "unknown"),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def map(self, raw: dict[str, Any]) -> dict[str, Any]:
        """
        Apply field name mapping and type coercion.

        Returns a dict ready to be unpacked into UnifiedEvent.create().

        Routing rules:
          1. Raw field name is in field_map → mapped to the UES name.
             - If the UES name is a real UnifiedEvent field → goes into canonical.
             - If the UES name is NOT a real UnifiedEvent field (e.g. 'extra_lang')
               → goes into extra_fields (overflow) under that name.
          2. Raw field name is NOT in field_map → goes into extra_fields.
        """
        canonical: dict[str, Any] = {
            "vendor": self.vendor,
            "device_type": self.device_type,
        }
        extra: dict[str, Any] = {}

        for raw_name, raw_value in raw.items():
            # Skip fields already handled at the top level
            if raw_name in ("extra_fields",):
                if isinstance(raw_value, dict):
                    extra.update(raw_value)
                continue

            ues_name = self._field_map.get(raw_name)
            if ues_name:
                coerced = self._coerce(ues_name, raw_value)
                if ues_name in _UES_FIELDS:
                    # Valid canonical field → add to canonical dict
                    canonical[ues_name] = coerced
                else:
                    # Mapped name is not a real UES field → goes to extra_fields
                    extra[ues_name] = coerced
            else:
                # Unmapped field → overflow
                extra[raw_name] = raw_value

        canonical["extra_fields"] = extra

        # Apply defaults when no value was mapped
        canonical.setdefault("event_category", self._default_category)
        canonical.setdefault("event_action", self._default_action)
        canonical.setdefault("severity", self._default_severity)

        return canonical

    # ------------------------------------------------------------------
    # Internal coercions
    # ------------------------------------------------------------------

    _PORT_RANGE = range(0, 65536)

    def _coerce(self, ues_name: str, value: Any) -> Any:
        """Best-effort type coercion for known canonical field names."""
        if value is None:
            return None

        text = str(value).strip()

        if ues_name in ("src_port", "dst_port", "http_status"):
            return self._to_int(text)

        if ues_name == "severity":
            return _SEVERITY_TEXT_MAP.get(text.lower(), EventSeverity.UNKNOWN)

        if ues_name == "event_action":
            return _ACTION_TEXT_MAP.get(text.lower(), EventAction.UNKNOWN)

        if ues_name == "event_category":
            return _CATEGORY_TEXT_MAP.get(text.lower(), EventCategory.UNKNOWN)

        if ues_name == "label_confidence":
            try:
                v = float(text)
                return max(0.0, min(1.0, v))
            except (ValueError, TypeError):
                return None

        if ues_name == "label_conflict":
            return text.lower() in ("true", "1", "yes")

        return text if text else None

    @staticmethod
    def _to_int(text: str) -> int | None:
        try:
            return int(float(text))
        except (ValueError, TypeError):
            return None


# ---------------------------------------------------------------------------
# Module-level convenience: default no-op mapper
# ---------------------------------------------------------------------------

DEFAULT_MAPPER = FieldMapper(
    source_id="generic",
    vendor=None,
    device_type="generic",
    field_map={},
)
