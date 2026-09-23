"""
SecurityAlert — Canonical Incident & Alert Data Structure for ULPF.

Represents a correlated security detection produced by the stateful
CorrelationEngine. Maintains strict traceability to contributing
UnifiedEvent instances (PS requirement d).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class SecurityAlert:
    """
    A single correlated security alert.

    Attributes
    ----------
    alert_id               : Globally unique identifier for this alert (UUID4).
    timestamp_utc          : ISO 8601 UTC timestamp when the alert was triggered.
    rule_name              : Identifier of the correlation rule that matched.
    incident_type          : Classification category (e.g. 'port_scan', 'brute_force').
    severity               : Severity level ('critical', 'high', 'medium', 'low').
    primary_ip             : Primary attacker or anomalous entity IP.
    target_ip              : Primary destination or victim IP (if applicable).
    event_count            : Number of correlated events contributing to this alert.
    correlated_event_uids  : List of canonical event_uids that formed the detection.
    mitre_tactic           : Associated MITRE ATT&CK tactic (e.g. 'Discovery').
    mitre_technique_id     : Associated MITRE technique ID (e.g. 'T1046').
    mitre_technique_name   : Associated MITRE technique name.
    description            : Human-readable narrative of the incident.
    context                : Additional contextual parameters (e.g. scanned ports).
    """

    alert_id: str
    timestamp_utc: str
    rule_name: str
    incident_type: str
    severity: str
    primary_ip: str
    target_ip: str | None = None
    event_count: int = 1
    correlated_event_uids: list[str] = field(default_factory=list)
    mitre_tactic: str | None = None
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None
    description: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        rule_name: str,
        incident_type: str,
        severity: str,
        primary_ip: str,
        correlated_event_uids: list[str],
        description: str,
        target_ip: str | None = None,
        mitre_tactic: str | None = None,
        mitre_technique_id: str | None = None,
        mitre_technique_name: str | None = None,
        context: dict[str, Any] | None = None,
        alert_id: str | None = None,
        timestamp_utc: str | None = None,
    ) -> "SecurityAlert":
        """Factory constructor with automatic UUID and UTC timestamp generation."""
        if alert_id is None:
            alert_id = f"alert-{uuid.uuid4().hex[:12]}"
        if timestamp_utc is None:
            timestamp_utc = datetime.now(timezone.utc).isoformat()

        return cls(
            alert_id=alert_id,
            timestamp_utc=timestamp_utc,
            rule_name=rule_name,
            incident_type=incident_type,
            severity=severity.lower(),
            primary_ip=primary_ip,
            target_ip=target_ip,
            event_count=len(correlated_event_uids),
            correlated_event_uids=list(correlated_event_uids),
            mitre_tactic=mitre_tactic,
            mitre_technique_id=mitre_technique_id,
            mitre_technique_name=mitre_technique_name,
            description=description,
            context=context or {},
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert alert to a JSON-serializable dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert alert to a compact JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def __repr__(self) -> str:
        return (
            f"SecurityAlert(id={self.alert_id}, rule={self.rule_name!r}, "
            f"ip={self.primary_ip}, sev={self.severity}, events={self.event_count})"
        )
