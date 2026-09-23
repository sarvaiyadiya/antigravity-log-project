"""
Tests for ULPF Correlation Engine & Alert Generation (Priority 5).

Covers:
- SecurityAlert dataclass & JSON serialization
- Sliding time-window retention and pruning
- Rule 1: Port scan sweep detection (T1046)
- Rule 2: Brute force authentication campaign (T1110)
- Rule 3: Cross-device coordinated attack campaign
- Rule 4: Active C2 / Botnet beaconing (T1071)
- Rule 5: High-severity exploit followup
- Cooldown suppression (alert flood prevention)
- Demo server alerts & simulation endpoints
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone, timedelta

import pytest

from src.schema.unified_event import UnifiedEvent, EventAction, EventCategory, EventSeverity, SourceType
from src.correlation.alert import SecurityAlert
from src.correlation.rule_engine import CorrelationEngine


def _make_test_event(
    src_ip: str = "198.51.100.50",
    dst_ip: str = "10.0.1.20",
    dst_port: int = 80,
    action: str = "allow",
    severity: EventSeverity = EventSeverity.LOW,
    device_type: SourceType = SourceType.FIREWALL,
    format_name: str = "cisco_asa",
    timestamp_utc: datetime | None = None,
    **kwargs,
) -> UnifiedEvent:
    """Helper to construct realistic UnifiedEvent test instances."""
    if timestamp_utc is None:
        timestamp_utc = datetime.now(timezone.utc)

    act_enum = EventAction(action) if action in [a.value for a in EventAction] else EventAction.UNKNOWN

    return UnifiedEvent.create(
        raw_log=f"raw test log from {src_ip} to {dst_ip}:{dst_port}",
        format_name=format_name,
        source_id="test_source",
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        event_action=act_enum,
        severity=severity,
        device_type=device_type,
        timestamp_utc=timestamp_utc,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Test SecurityAlert Schema & Serialization
# ---------------------------------------------------------------------------

def test_security_alert_creation_and_serialization():
    alert = SecurityAlert.create(
        rule_name="PORT_SCAN_SWEEP",
        incident_type="port_scan",
        severity="medium",
        primary_ip="198.51.100.99",
        target_ip="10.0.1.50",
        correlated_event_uids=["uid-1", "uid-2", "uid-3"],
        description="Port scan test alert",
        mitre_tactic="Discovery",
        mitre_technique_id="T1046",
        mitre_technique_name="Network Service Discovery",
        context={"ports": [22, 80, 443]},
    )

    assert alert.alert_id.startswith("alert-")
    assert alert.rule_name == "PORT_SCAN_SWEEP"
    assert alert.event_count == 3
    assert alert.severity == "medium"
    assert alert.mitre_technique_id == "T1046"

    d = alert.to_dict()
    assert isinstance(d, dict)
    assert d["primary_ip"] == "198.51.100.99"
    assert d["correlated_event_uids"] == ["uid-1", "uid-2", "uid-3"]

    json_str = alert.to_json()
    parsed = json.loads(json_str)
    assert parsed["alert_id"] == alert.alert_id
    assert parsed["context"]["ports"] == [22, 80, 443]


# ---------------------------------------------------------------------------
# Test Rule 1: Port Scan Sweep (T1046)
# ---------------------------------------------------------------------------

def test_port_scan_detection_triggers_at_threshold():
    engine = CorrelationEngine(max_sliding_window_seconds=60)
    engine.clear()

    src = "198.51.100.101"
    ports = [21, 22, 23, 80]  # 4 distinct ports -> below threshold (5)

    for p in ports:
        ev = _make_test_event(src_ip=src, dst_port=p)
        alerts = engine.process_event(ev)
        assert len(alerts) == 0, f"Should not trigger alert for port count {p}"

    # 5th distinct port -> should trigger alert!
    ev5 = _make_test_event(src_ip=src, dst_port=443)
    alerts = engine.process_event(ev5)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "PORT_SCAN_SWEEP"
    assert alert.incident_type == "port_scan"
    assert alert.mitre_technique_id == "T1046"
    assert alert.primary_ip == src
    assert alert.context["port_count"] == 5
    assert sorted(alert.context["scanned_ports"]) == [21, 22, 23, 80, 443]


def test_port_scan_cooldown_suppresses_flooding():
    engine = CorrelationEngine(max_sliding_window_seconds=60)
    engine.clear()

    src = "198.51.100.102"
    # Trigger 1st alert with 5 ports
    for p in [21, 22, 23, 80, 443]:
        engine.process_event(_make_test_event(src_ip=src, dst_port=p))

    # Send a 6th and 7th port immediately -> should be in cooldown
    alerts2 = engine.process_event(_make_test_event(src_ip=src, dst_port=8080))
    alerts3 = engine.process_event(_make_test_event(src_ip=src, dst_port=8443))

    assert len(alerts2) == 0, "Expected cooldown to suppress duplicate alert"
    assert len(alerts3) == 0, "Expected cooldown to suppress duplicate alert"


# ---------------------------------------------------------------------------
# Test Rule 2: Brute Force Campaign (T1110)
# ---------------------------------------------------------------------------

def test_brute_force_detection():
    engine = CorrelationEngine(max_sliding_window_seconds=120)
    engine.clear()

    src = "198.51.100.103"

    # Send 4 failed logon/deny events -> below threshold (5)
    for i in range(4):
        ev = _make_test_event(
            src_ip=src,
            action="deny",
            username=f"user_{i}",
            event_category=EventCategory.AUTHENTICATION,
        )
        alerts = engine.process_event(ev)
        assert len(alerts) == 0

    # 5th denied event -> triggers brute force alert!
    ev5 = _make_test_event(
        src_ip=src,
        action="deny",
        username="admin",
        event_category=EventCategory.AUTHENTICATION,
    )
    alerts = engine.process_event(ev5)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "BRUTE_FORCE_CAMPAIGN"
    assert alert.incident_type == "brute_force"
    assert alert.mitre_technique_id == "T1110"
    assert alert.severity == "high"
    assert alert.primary_ip == src
    assert alert.context["failed_count"] == 5


# ---------------------------------------------------------------------------
# Test Rule 3: Cross-Device Campaign (FW + IDS)
# ---------------------------------------------------------------------------

def test_cross_device_campaign_detection():
    engine = CorrelationEngine(max_sliding_window_seconds=120)
    engine.clear()

    src = "198.51.100.104"

    # 1. Firewall deny event
    fw_event = _make_test_event(
        src_ip=src,
        device_type=SourceType.FIREWALL,
        format_name="cisco_asa",
        action="deny",
    )
    alerts1 = engine.process_event(fw_event)
    assert len(alerts1) == 0

    # 2. IDS/IPS alert from same IP within window
    ids_event = _make_test_event(
        src_ip=src,
        device_type=SourceType.IDS_IPS,
        format_name="snort",
        action="alert",
        threat_name="SQL Injection in URI",
    )
    alerts2 = engine.process_event(ids_event)

    assert len(alerts2) >= 1
    cross_alerts = [a for a in alerts2 if a.rule_name == "CROSS_DEVICE_CAMPAIGN"]
    assert len(cross_alerts) == 1
    alert = cross_alerts[0]
    assert alert.incident_type == "cross_device_campaign"
    assert alert.primary_ip == src
    assert "firewall" in alert.context["device_types"]
    assert "ids_ips" in alert.context["device_types"]


# ---------------------------------------------------------------------------
# Test Rule 4: Active C2 / Botnet Beaconing (T1071)
# ---------------------------------------------------------------------------

def test_c2_beacon_detection():
    engine = CorrelationEngine(max_sliding_window_seconds=180)
    engine.clear()

    malicious_ip = "198.51.100.12"

    # 1st event from threat-intel flagged malicious IP
    ev1 = _make_test_event(
        src_ip=malicious_ip,
        is_malicious=True,
        threat_intel_score=0.95,
        threat_intel_source="emerging_threats_botnet",
    )
    alerts1 = engine.process_event(ev1)
    assert len(alerts1) == 0  # Requires >= 2 events to establish beaconing pattern

    # 2nd event within window
    ev2 = _make_test_event(
        src_ip=malicious_ip,
        is_malicious=True,
        threat_intel_score=0.95,
        threat_intel_source="emerging_threats_botnet",
    )
    alerts2 = engine.process_event(ev2)

    c2_alerts = [a for a in alerts2 if a.rule_name == "MALICIOUS_C2_BEACON"]
    assert len(c2_alerts) == 1
    alert = c2_alerts[0]
    assert alert.severity == "critical"
    assert alert.incident_type == "c2_communication"
    assert alert.mitre_technique_id == "T1071"
    assert alert.primary_ip == malicious_ip
    assert alert.context["threat_intel_score"] >= 0.90


# ---------------------------------------------------------------------------
# Test Rule 5: High-Severity Exploit Followup
# ---------------------------------------------------------------------------

def test_high_severity_multi_vector_exploit():
    engine = CorrelationEngine(max_sliding_window_seconds=60)
    engine.clear()

    src = "198.51.100.105"

    # 1. High-severity attack (SQLi / T1190)
    ev_threat = _make_test_event(
        src_ip=src,
        severity=EventSeverity.CRITICAL,
        threat_name="Apache Log4j RCE Attempt",
        mitre_technique_id="T1190",
        action="deny",
    )
    alerts1 = engine.process_event(ev_threat)

    # 2. Followup connection within window
    ev_followup = _make_test_event(
        src_ip=src,
        dst_port=445,
        action="deny",
    )
    alerts2 = engine.process_event(ev_followup)

    exploit_alerts = [a for a in (alerts1 + alerts2) if a.rule_name == "HIGH_SEVERITY_MULTI_VECTOR"]
    assert len(exploit_alerts) == 1
    alert = exploit_alerts[0]
    assert alert.severity == "critical"
    assert alert.incident_type == "multi_vector_exploit"
    assert alert.primary_ip == src


# ---------------------------------------------------------------------------
# Test Sliding Window Pruning
# ---------------------------------------------------------------------------

def test_sliding_window_prunes_expired_events():
    engine = CorrelationEngine(max_sliding_window_seconds=30)
    engine.clear()

    src = "198.51.100.106"
    t0 = datetime(2024, 1, 18, 10, 0, 0, tzinfo=timezone.utc)

    # Send 4 distinct port events at T0
    for p in [21, 22, 23, 80]:
        engine.process_event(_make_test_event(src_ip=src, dst_port=p, timestamp_utc=t0))

    # Send 5th port event 60 seconds later (beyond 30s max_window)
    t1 = t0 + timedelta(seconds=60)
    alerts = engine.process_event(_make_test_event(src_ip=src, dst_port=443, timestamp_utc=t1))

    # Should NOT trigger port scan because previous 4 events expired from the 30s window!
    assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Test Batch Processing and Alert History
# ---------------------------------------------------------------------------

def test_process_batch_and_alert_history():
    engine = CorrelationEngine(max_sliding_window_seconds=60)
    engine.clear()

    src = "198.51.100.107"
    events = [_make_test_event(src_ip=src, dst_port=p) for p in [21, 22, 23, 80, 443, 8080]]

    alerts = engine.process_batch(events)
    assert len(alerts) >= 1

    recent = engine.get_recent_alerts(limit=10)
    assert len(recent) >= 1
    assert recent[0]["primary_ip"] == src

    # Test clear
    engine.clear()
    assert len(engine.get_recent_alerts()) == 0


# ---------------------------------------------------------------------------
# Test Demo Server Alerts & Simulation Endpoints
# ---------------------------------------------------------------------------

def test_demo_server_state_alert_integration():
    from demo.server import DashboardState

    state = DashboardState()
    state.clear_alerts()

    # Ingest 5 distinct port scan events
    src = "198.51.100.200"
    for p in [21, 22, 23, 80, 443]:
        ev = _make_test_event(src_ip=src, dst_port=p)
        clean = ev.to_dict()
        clean["success"] = True
        state.add_event(clean, ev)

    # Check alert was recorded in state
    alerts = state.get_alerts()
    assert len(alerts) >= 1
    assert alerts[0]["rule_name"] == "PORT_SCAN_SWEEP"
    assert state.total_alerts >= 1

    # Check stats include alert totals
    stats = state.get_stats()
    assert stats["total_alerts"] >= 1
    assert stats["active_alerts"] >= 1
