"""
CorrelationEngine — Stateful Sliding Time-Window Multi-Event Correlation.

Correlates perimeter security events across time windows to detect complex
multi-vector attacks (port sweeps, brute force attacks, cross-device campaigns,
C2 beaconing, high-severity exploits).
"""

from __future__ import annotations

import collections
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from src.schema.unified_event import UnifiedEvent, EventAction, EventCategory, EventSeverity
from src.correlation.alert import SecurityAlert

logger = logging.getLogger("ulpf.correlation")

_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "configs" / "correlation_rules.yaml"


def _extract_epoch_seconds(event: UnifiedEvent) -> float:
    """Extract standard epoch seconds from event temporal metadata."""
    if event.timestamp_utc is not None and isinstance(event.timestamp_utc, datetime):
        return event.timestamp_utc.timestamp()
    if event.ingest_timestamp is not None and isinstance(event.ingest_timestamp, datetime):
        return event.ingest_timestamp.timestamp()
    return time.time()


class CorrelationEngine:
    """
    In-memory stateful sliding time-window correlation engine.

    Features:
    - Sliding-window deques indexed by primary entity (src_ip).
    - Auto-pruning of expired events beyond maximum window.
    - Configurable cooldown suppression to prevent alert fatigue.
    - 5 built-in multi-event perimeter attack rules.
    - Fully thread-safe.
    """

    def __init__(
        self,
        config_path: str | Path | None = None,
        max_sliding_window_seconds: float = 300.0,
    ) -> None:
        self.lock = threading.Lock()
        self.max_window: float = max_sliding_window_seconds
        self.rules_config: dict[str, Any] = {}

        # Entity queues: entity_key (e.g. src_ip) -> deque of (epoch_time, UnifiedEvent)
        self._entity_events: dict[str, collections.deque[tuple[float, UnifiedEvent]]] = collections.defaultdict(collections.deque)

        # Cooldown tracker: (rule_name, entity_key) -> last_alert_epoch
        self._cooldowns: dict[tuple[str, str], float] = {}

        # Alerts ring buffer (last 500 alerts)
        self._alerts_history: collections.deque[SecurityAlert] = collections.deque(maxlen=500)

        # Load configuration if available
        self._load_config(config_path or _CONFIG_PATH)

    def _load_config(self, path: str | Path) -> None:
        """Load declarative rules from YAML config file."""
        p = Path(path)
        if p.exists():
            try:
                with p.open(encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                self.rules_config = cfg
                if "max_sliding_window_seconds" in cfg:
                    self.max_window = float(cfg["max_sliding_window_seconds"])
            except Exception as exc:
                logger.warning(f"Could not load correlation rules config {path}: {exc}")

    def _get_rule_cfg(self, rule_name: str, default_params: dict[str, Any]) -> dict[str, Any]:
        """Retrieve rule config with fallback defaults."""
        rules_list = self.rules_config.get("rules", [])
        for r in rules_list:
            if r.get("rule_name") == rule_name:
                merged = dict(default_params)
                merged.update(r)
                return merged
        return default_params

    def clear(self) -> None:
        """Clear all entity event queues, cooldowns, and alert history."""
        with self.lock:
            self._entity_events.clear()
            self._cooldowns.clear()
            self._alerts_history.clear()

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the latest alerts in reverse chronological order as dicts."""
        with self.lock:
            alerts = list(self._alerts_history)
        alerts.reverse()
        return [a.to_dict() for a in alerts[:limit]]

    def process_event(self, event: UnifiedEvent) -> list[SecurityAlert]:
        """
        Ingest a single UnifiedEvent, update entity state, evaluate rules,
        and return any triggered SecurityAlerts.
        """
        entity_key = event.src_ip or event.device_ip
        if not entity_key:
            return []

        event_time = _extract_epoch_seconds(event)
        new_alerts: list[SecurityAlert] = []

        with self.lock:
            queue = self._entity_events[entity_key]
            queue.append((event_time, event))

            # Prune events older than global max_window
            min_cutoff = event_time - self.max_window
            while queue and queue[0][0] < min_cutoff:
                queue.popleft()

            # Snapshot relevant events for this entity
            recent = list(queue)

            # Evaluate each correlation rule
            alert = self._eval_port_scan(entity_key, recent, event_time)
            if alert:
                new_alerts.append(alert)

            alert = self._eval_brute_force(entity_key, recent, event_time)
            if alert:
                new_alerts.append(alert)

            alert = self._eval_cross_device(entity_key, recent, event_time)
            if alert:
                new_alerts.append(alert)

            alert = self._eval_c2_beacon(entity_key, recent, event_time)
            if alert:
                new_alerts.append(alert)

            alert = self._eval_multi_vector_exploit(entity_key, recent, event_time)
            if alert:
                new_alerts.append(alert)

            for a in new_alerts:
                self._alerts_history.append(a)

        return new_alerts

    def process_batch(self, events: list[UnifiedEvent]) -> list[SecurityAlert]:
        """Process a collection of events in chronological order."""
        all_alerts: list[SecurityAlert] = []
        for ev in events:
            alerts = self.process_event(ev)
            all_alerts.extend(alerts)
        return all_alerts

    # ---------------------------------------------------------------------------
    # Rule Evaluators
    # ---------------------------------------------------------------------------

    def _is_cooling_down(self, rule_name: str, entity_key: str, now: float, cooldown_sec: float) -> bool:
        """Check if an entity is in cooldown for a given rule."""
        key = (rule_name, entity_key)
        last_time = self._cooldowns.get(key)
        if last_time is not None and (now - last_time) < cooldown_sec:
            return True
        return False

    def _mark_cooldown(self, rule_name: str, entity_key: str, now: float) -> None:
        """Update the cooldown timestamp for an entity and rule."""
        self._cooldowns[(rule_name, entity_key)] = now

    def _eval_port_scan(
        self,
        entity_key: str,
        recent: list[tuple[float, UnifiedEvent]],
        now: float,
    ) -> SecurityAlert | None:
        """
        Rule 1: PORT_SCAN_SWEEP
        Detects >= 5 distinct destination ports probed within window_seconds.
        """
        cfg = self._get_rule_cfg("PORT_SCAN_SWEEP", {
            "window_seconds": 30.0,
            "cooldown_seconds": 60.0,
            "min_distinct_ports": 5,
            "severity": "medium",
            "enabled": True,
        })
        if not cfg.get("enabled", True):
            return None

        window_sec = float(cfg["window_seconds"])
        cooldown_sec = float(cfg["cooldown_seconds"])
        threshold = int(cfg["min_distinct_ports"])

        if self._is_cooling_down("PORT_SCAN_SWEEP", entity_key, now, cooldown_sec):
            return None

        cutoff = now - window_sec
        window_events = [ev for (t, ev) in recent if t >= cutoff]

        distinct_ports: dict[int, str] = {}
        for ev in window_events:
            if ev.dst_port is not None and ev.dst_port > 0:
                distinct_ports[ev.dst_port] = ev.event_uid

        if len(distinct_ports) >= threshold:
            self._mark_cooldown("PORT_SCAN_SWEEP", entity_key, now)
            ports_sorted = sorted(distinct_ports.keys())
            target_ips = list({ev.dst_ip for ev in window_events if ev.dst_ip})
            target_ip = target_ips[0] if target_ips else None
            uids = [ev.event_uid for ev in window_events if ev.dst_port in distinct_ports]

            return SecurityAlert.create(
                rule_name="PORT_SCAN_SWEEP",
                incident_type="port_scan",
                severity=cfg.get("severity", "medium"),
                primary_ip=entity_key,
                target_ip=target_ip,
                correlated_event_uids=uids,
                mitre_tactic="Discovery",
                mitre_technique_id="T1046",
                mitre_technique_name="Network Service Discovery",
                description=(
                    f"Port scanning sweep detected from {entity_key}: "
                    f"{len(distinct_ports)} distinct ports probed "
                    f"({', '.join(map(str, ports_sorted[:8]))}{'...' if len(ports_sorted) > 8 else ''}) "
                    f"within {int(window_sec)}s."
                ),
                context={
                    "scanned_ports": ports_sorted,
                    "port_count": len(distinct_ports),
                    "target_ips": target_ips,
                    "window_seconds": window_sec,
                },
            )
        return None

    def _eval_brute_force(
        self,
        entity_key: str,
        recent: list[tuple[float, UnifiedEvent]],
        now: float,
    ) -> SecurityAlert | None:
        """
        Rule 2: BRUTE_FORCE_CAMPAIGN
        Detects >= 5 failed logins, denied access events, or drop actions within window.
        """
        cfg = self._get_rule_cfg("BRUTE_FORCE_CAMPAIGN", {
            "window_seconds": 60.0,
            "cooldown_seconds": 60.0,
            "min_failed_events": 5,
            "severity": "high",
            "enabled": True,
        })
        if not cfg.get("enabled", True):
            return None

        window_sec = float(cfg["window_seconds"])
        cooldown_sec = float(cfg["cooldown_seconds"])
        threshold = int(cfg["min_failed_events"])

        if self._is_cooling_down("BRUTE_FORCE_CAMPAIGN", entity_key, now, cooldown_sec):
            return None

        cutoff = now - window_sec
        window_events = [ev for (t, ev) in recent if t >= cutoff]

        failed_events: list[UnifiedEvent] = []
        for ev in window_events:
            is_denied = False
            # Action matches deny/drop/block
            act = ev.event_action.value if hasattr(ev.event_action, "value") else str(ev.event_action or "").lower()
            if act in ("deny", "drop", "block", "alert"):
                is_denied = True
            elif ev.http_status in (401, 403):
                is_denied = True
            elif (ev.event_category == EventCategory.AUTHENTICATION or str(ev.event_category).lower() == "authentication") and ev.weak_label == "attack":
                is_denied = True
            else:
                raw_lower = (ev.raw_log or "").lower()
                if "failed" in raw_lower or "failure" in raw_lower or "invalid user" in raw_lower:
                    is_denied = True

            if is_denied:
                failed_events.append(ev)

        if len(failed_events) >= threshold:
            self._mark_cooldown("BRUTE_FORCE_CAMPAIGN", entity_key, now)
            usernames = list({ev.username for ev in failed_events if ev.username})
            target_ips = list({ev.dst_ip for ev in failed_events if ev.dst_ip})
            target_ip = target_ips[0] if target_ips else None

            user_str = f" against account(s) {', '.join(usernames[:3])}" if usernames else ""
            return SecurityAlert.create(
                rule_name="BRUTE_FORCE_CAMPAIGN",
                incident_type="brute_force",
                severity=cfg.get("severity", "high"),
                primary_ip=entity_key,
                target_ip=target_ip,
                correlated_event_uids=[ev.event_uid for ev in failed_events],
                mitre_tactic="Credential Access",
                mitre_technique_id="T1110",
                mitre_technique_name="Brute Force",
                description=(
                    f"Brute-force / authentication attack campaign from {entity_key}: "
                    f"{len(failed_events)} failed or denied connection attempts{user_str} "
                    f"within {int(window_sec)}s."
                ),
                context={
                    "failed_count": len(failed_events),
                    "usernames": usernames,
                    "target_ips": target_ips,
                    "window_seconds": window_sec,
                },
            )
        return None

    def _eval_cross_device(
        self,
        entity_key: str,
        recent: list[tuple[float, UnifiedEvent]],
        now: float,
    ) -> SecurityAlert | None:
        """
        Rule 3: CROSS_DEVICE_CAMPAIGN
        Detects coordinated activity from the same IP across >= 2 distinct device
        types (e.g. firewall + IDS/IPS, or WAF + Endpoint) within window.
        """
        cfg = self._get_rule_cfg("CROSS_DEVICE_CAMPAIGN", {
            "window_seconds": 120.0,
            "cooldown_seconds": 90.0,
            "min_distinct_device_types": 2,
            "severity": "high",
            "enabled": True,
        })
        if not cfg.get("enabled", True):
            return None

        window_sec = float(cfg["window_seconds"])
        cooldown_sec = float(cfg["cooldown_seconds"])
        threshold = int(cfg["min_distinct_device_types"])

        if self._is_cooling_down("CROSS_DEVICE_CAMPAIGN", entity_key, now, cooldown_sec):
            return None

        cutoff = now - window_sec
        window_events = [ev for (t, ev) in recent if t >= cutoff]

        device_types: set[str] = set()
        has_suspicious_or_deny = False

        for ev in window_events:
            dt = None
            if ev.device_type is not None:
                dt = ev.device_type.value if hasattr(ev.device_type, "value") else str(ev.device_type)
            elif ev.format_name:
                # Group by parser family
                if "cisco" in ev.format_name or "paloalto" in ev.format_name:
                    dt = "firewall"
                elif "snort" in ev.format_name or "suricata" in ev.format_name or "ids" in ev.format_name:
                    dt = "ids_ips"
                elif "cloudtrail" in ev.format_name:
                    dt = "cloud"
                elif "windows" in ev.format_name:
                    dt = "endpoint"
                else:
                    dt = ev.format_name

            if dt:
                device_types.add(dt.lower())

            # Check if at least one event is flagged as threat / deny
            act = ev.event_action.value if hasattr(ev.event_action, "value") else str(ev.event_action or "").lower()
            if (
                act in ("deny", "drop", "block", "alert")
                or ev.weak_label == "attack"
                or ev.is_malicious is True
                or ev.threat_name is not None
            ):
                has_suspicious_or_deny = True

        if len(device_types) >= threshold and has_suspicious_or_deny:
            self._mark_cooldown("CROSS_DEVICE_CAMPAIGN", entity_key, now)
            target_ips = list({ev.dst_ip for ev in window_events if ev.dst_ip})
            target_ip = target_ips[0] if target_ips else None

            dt_list = sorted(list(device_types))
            return SecurityAlert.create(
                rule_name="CROSS_DEVICE_CAMPAIGN",
                incident_type="cross_device_campaign",
                severity=cfg.get("severity", "high"),
                primary_ip=entity_key,
                target_ip=target_ip,
                correlated_event_uids=[ev.event_uid for ev in window_events],
                mitre_tactic="Initial Access",
                mitre_technique_id="T1190",
                mitre_technique_name="Exploit Public-Facing Application",
                description=(
                    f"Cross-device attack campaign from {entity_key}: suspicious activity "
                    f"correlated across {len(dt_list)} perimeter device types ({', '.join(dt_list)}) "
                    f"within {int(window_sec)}s."
                ),
                context={
                    "device_types": dt_list,
                    "event_count": len(window_events),
                    "target_ips": target_ips,
                    "window_seconds": window_sec,
                },
            )
        return None

    def _eval_c2_beacon(
        self,
        entity_key: str,
        recent: list[tuple[float, UnifiedEvent]],
        now: float,
    ) -> SecurityAlert | None:
        """
        Rule 4: MALICIOUS_C2_BEACON
        Detects recurring connections (>= 2) involving a threat-intel confirmed malicious IP.
        """
        cfg = self._get_rule_cfg("MALICIOUS_C2_BEACON", {
            "window_seconds": 180.0,
            "cooldown_seconds": 120.0,
            "min_malicious_events": 2,
            "threat_score_threshold": 0.70,
            "severity": "critical",
            "enabled": True,
        })
        if not cfg.get("enabled", True):
            return None

        window_sec = float(cfg["window_seconds"])
        cooldown_sec = float(cfg["cooldown_seconds"])
        threshold = int(cfg["min_malicious_events"])
        score_thresh = float(cfg.get("threat_score_threshold", 0.70))

        if self._is_cooling_down("MALICIOUS_C2_BEACON", entity_key, now, cooldown_sec):
            return None

        cutoff = now - window_sec
        window_events = [ev for (t, ev) in recent if t >= cutoff]

        malicious_events: list[UnifiedEvent] = []
        max_score = 0.0
        sources: set[str] = set()

        for ev in window_events:
            score = ev.threat_intel_score or 0.0
            if score > max_score:
                max_score = score
            if ev.threat_intel_source:
                sources.add(ev.threat_intel_source)

            if ev.is_malicious is True or score >= score_thresh:
                malicious_events.append(ev)

        if len(malicious_events) >= threshold:
            self._mark_cooldown("MALICIOUS_C2_BEACON", entity_key, now)
            target_ips = list({ev.dst_ip for ev in malicious_events if ev.dst_ip})
            target_ip = target_ips[0] if target_ips else None
            src_str = f" ({', '.join(sorted(sources))})" if sources else ""

            return SecurityAlert.create(
                rule_name="MALICIOUS_C2_BEACON",
                incident_type="c2_communication",
                severity=cfg.get("severity", "critical"),
                primary_ip=entity_key,
                target_ip=target_ip,
                correlated_event_uids=[ev.event_uid for ev in malicious_events],
                mitre_tactic="Command and Control",
                mitre_technique_id="T1071",
                mitre_technique_name="Application Layer Protocol",
                description=(
                    f"Active C2 / Botnet communication detected: confirmed malicious IP "
                    f"{entity_key} (threat score: {max_score:.2f}{src_str}) exhibited "
                    f"{len(malicious_events)} connection sessions within {int(window_sec)}s."
                ),
                context={
                    "threat_intel_score": max_score,
                    "threat_intel_sources": list(sources),
                    "connection_count": len(malicious_events),
                    "target_ips": target_ips,
                    "window_seconds": window_sec,
                },
            )
        return None

    def _eval_multi_vector_exploit(
        self,
        entity_key: str,
        recent: list[tuple[float, UnifiedEvent]],
        now: float,
    ) -> SecurityAlert | None:
        """
        Rule 5: HIGH_SEVERITY_MULTI_VECTOR
        Detects a high or critical exploit event followed by successive connection attempts.
        """
        cfg = self._get_rule_cfg("HIGH_SEVERITY_MULTI_VECTOR", {
            "window_seconds": 60.0,
            "cooldown_seconds": 60.0,
            "min_events_following_threat": 2,
            "severity": "critical",
            "enabled": True,
        })
        if not cfg.get("enabled", True):
            return None

        window_sec = float(cfg["window_seconds"])
        cooldown_sec = float(cfg["cooldown_seconds"])
        threshold = int(cfg["min_events_following_threat"])

        if self._is_cooling_down("HIGH_SEVERITY_MULTI_VECTOR", entity_key, now, cooldown_sec):
            return None

        cutoff = now - window_sec
        window_events = [ev for (t, ev) in recent if t >= cutoff]

        has_high_threat = False
        threat_name = "Exploit Attempt"
        threat_technique = "T1190"

        for ev in window_events:
            sev = ev.severity
            sev_num = sev.value if isinstance(sev, EventSeverity) else int(sev or 0)
            sev_lbl = str(ev.severity_label or "").lower()

            if sev_num >= EventSeverity.HIGH.value or sev_lbl in ("high", "critical", "emergency"):
                has_high_threat = True
                if ev.threat_name:
                    threat_name = ev.threat_name
                if ev.mitre_technique_id:
                    threat_technique = ev.mitre_technique_id
                break

        # If high threat is present and total events >= threshold (e.g. 2 or more)
        if has_high_threat and len(window_events) >= threshold:
            self._mark_cooldown("HIGH_SEVERITY_MULTI_VECTOR", entity_key, now)
            target_ips = list({ev.dst_ip for ev in window_events if ev.dst_ip})
            target_ip = target_ips[0] if target_ips else None

            return SecurityAlert.create(
                rule_name="HIGH_SEVERITY_MULTI_VECTOR",
                incident_type="multi_vector_exploit",
                severity=cfg.get("severity", "critical"),
                primary_ip=entity_key,
                target_ip=target_ip,
                correlated_event_uids=[ev.event_uid for ev in window_events],
                mitre_tactic="Execution",
                mitre_technique_id=threat_technique,
                mitre_technique_name=threat_name,
                description=(
                    f"High-severity exploit campaign detected: {entity_key} executed "
                    f"'{threat_name}' ({threat_technique}) followed by {len(window_events)} "
                    f"correlated events within {int(window_sec)}s."
                ),
                context={
                    "threat_name": threat_name,
                    "mitre_technique": threat_technique,
                    "correlated_count": len(window_events),
                    "target_ips": target_ips,
                    "window_seconds": window_sec,
                },
            )
        return None


# Global singleton instance
_GLOBAL_CORRELATION_ENGINE: CorrelationEngine | None = None


def get_correlation_engine() -> CorrelationEngine:
    """Return the global CorrelationEngine singleton."""
    global _GLOBAL_CORRELATION_ENGINE
    if _GLOBAL_CORRELATION_ENGINE is None:
        _GLOBAL_CORRELATION_ENGINE = CorrelationEngine()
    return _GLOBAL_CORRELATION_ENGINE
