"""
Automated unit and endpoint tests for demo/server.py and demo/demo_data_generator.py.
"""

import json
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from demo.server import ThreadingHTTPServer, DashboardRequestHandler, _GLOBAL_STATE


@pytest.fixture(scope="module")
def running_demo_server():
    """Starts the demo server on an ephemeral port for testing."""
    test_port = 7895
    server = ThreadingHTTPServer(("127.0.0.1", test_port), DashboardRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    base_url = f"http://127.0.0.1:{test_port}"
    yield base_url

    server.shutdown()
    server.server_close()


def test_get_index_html(running_demo_server):
    """Verify that GET / returns 200 OK and serves the ULPF web interface."""
    with urllib.request.urlopen(f"{running_demo_server}/") as resp:
        assert resp.status == 200
        content = resp.read().decode("utf-8")
        assert "ULPF" in content
        assert "Universal Log Pre-processing Framework" in content
        assert resp.headers.get("Content-Type").startswith("text/html")


def test_get_parsers_list(running_demo_server):
    """Verify that GET /api/parsers returns all registered parsers."""
    with urllib.request.urlopen(f"{running_demo_server}/api/parsers") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "parsers" in data
        assert data["count"] >= 12
        parser_names = [p["name"] for p in data["parsers"]]
        assert "cisco_asa" in parser_names
        assert "paloalto_threat" in parser_names
        assert "windows_event_xml" in parser_names


def test_post_ingest_and_get_stats(running_demo_server):
    """Verify that POST /api/ingest parses raw log and updates stats."""
    raw_cisco = '<134>Jan 18 10:22:15 fw01 %ASA-3-106023: Deny tcp src outside:198.51.100.44/52100 dst inside:10.0.1.50/443 by access-group outside_in'
    req = urllib.request.Request(
        f"{running_demo_server}/api/ingest",
        data=raw_cisco.encode("utf-8"),
        headers={"Content-Type": "text/plain"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["status"] == "ok"
        assert data["ingested"] == 1

    # Verify stats
    with urllib.request.urlopen(f"{running_demo_server}/api/stats") as resp:
        assert resp.status == 200
        stats = json.loads(resp.read().decode("utf-8"))
        assert stats["total_events"] >= 1
        assert "cisco_asa" in stats["by_format"]
        assert stats["by_action"].get("deny", 0) >= 1


def test_get_events_buffer(running_demo_server):
    """Verify that GET /api/events retrieves latest canonical events."""
    with urllib.request.urlopen(f"{running_demo_server}/api/events?limit=10") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert len(data["events"]) >= 1
        ev = data["events"][0]
        assert ev.get("format_name") == "cisco_asa"
        assert ev.get("src_ip") == "198.51.100.44"
        assert ev.get("dst_ip") == "10.0.1.50"
        assert ev.get("src_port") == 52100
        assert ev.get("dst_port") == 443


def test_post_process_interactive_analyzer(running_demo_server):
    """Verify that POST /api/process auto-detects and normalizes test logs."""
    cef_log = 'CEF:0|Cisco|ASA|9.14|106023|Deny TCP|6|src=192.168.1.5 spt=44231 dst=10.0.0.1 dpt=443 proto=TCP act=Deny'
    payload = json.dumps({"lines": cef_log, "format": "auto"}).encode("utf-8")
    req = urllib.request.Request(
        f"{running_demo_server}/api/process",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data["format_detected"] == "cef"
        assert data["stats"]["parsed_ok"] == 1
        assert len(data["events"]) == 1
        ev = data["events"][0]
        assert ev["src_ip"] == "192.168.1.5"
        assert ev["dst_ip"] == "10.0.0.1"


def test_demo_generator_runs_cleanly(running_demo_server):
    """Verify demo_data_generator sends batches cleanly to ingest endpoint."""
    from demo.demo_data_generator import load_file_samples, generate_log_line, send_to_url

    samples = load_file_samples()
    assert len(samples) > 0

    # Generate and send 5 events
    ingest_url = f"{running_demo_server}/api/ingest"
    for _ in range(5):
        line = generate_log_line(samples)
        ok = send_to_url(ingest_url, line)
        assert ok is True


def test_api_simulate_port_scan_and_alerts_endpoint(running_demo_server):
    """Verify POST /api/simulate triggers port scan correlation alert and GET /api/alerts retrieves it."""
    # 1. Clear alerts first
    req_clear = urllib.request.Request(
        f"{running_demo_server}/api/alerts/clear",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req_clear) as resp:
        assert resp.status == 200

    # 2. Simulate port scan
    req_sim = urllib.request.Request(
        f"{running_demo_server}/api/simulate",
        data=json.dumps({"attack_type": "port_scan", "src_ip": "198.51.100.222"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req_sim) as resp:
        assert resp.status == 200
        sim_data = json.loads(resp.read().decode("utf-8"))
        assert sim_data["status"] == "ok"
        assert sim_data["simulation"] == "port_scan"
        assert sim_data["alerts_triggered"] >= 1

    # 3. Query GET /api/alerts
    with urllib.request.urlopen(f"{running_demo_server}/api/alerts") as resp:
        assert resp.status == 200
        alerts_data = json.loads(resp.read().decode("utf-8"))
        assert "alerts" in alerts_data
        assert alerts_data["count"] >= 1
        port_scan_alerts = [a for a in alerts_data["alerts"] if a["rule_name"] == "PORT_SCAN_SWEEP"]
        assert len(port_scan_alerts) >= 1
        alert = port_scan_alerts[0]
        assert alert["rule_name"] == "PORT_SCAN_SWEEP"
        assert alert["primary_ip"] == "198.51.100.222"
        assert alert["mitre_technique_id"] == "T1046"


def test_api_simulate_cross_device_campaign(running_demo_server):
    """Verify POST /api/simulate triggers cross-device attack campaign."""
    req_sim = urllib.request.Request(
        f"{running_demo_server}/api/simulate",
        data=json.dumps({"attack_type": "cross_device", "src_ip": "198.51.100.223"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req_sim) as resp:
        assert resp.status == 200
        sim_data = json.loads(resp.read().decode("utf-8"))
        assert sim_data["status"] == "ok"
        assert sim_data["alerts_triggered"] >= 1

    with urllib.request.urlopen(f"{running_demo_server}/api/alerts") as resp:
        assert resp.status == 200
        alerts_data = json.loads(resp.read().decode("utf-8"))
        cross_alerts = [a for a in alerts_data["alerts"] if a["rule_name"] == "CROSS_DEVICE_CAMPAIGN"]
        assert len(cross_alerts) >= 1
        assert cross_alerts[0]["primary_ip"] == "198.51.100.223"


def test_api_model_info_endpoint(running_demo_server):
    """Verify GET /api/model/info returns model diagnostics and metrics."""
    with urllib.request.urlopen(f"{running_demo_server}/api/model/info") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "model_version" in data
        assert "feature_dim" in data
        assert data["feature_dim"] == 24
        assert "abstention_threshold" in data
        assert data["abstention_threshold"] == 0.60


