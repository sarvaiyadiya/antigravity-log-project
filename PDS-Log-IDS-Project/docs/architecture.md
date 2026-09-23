# 🏗️ ULPF System Architecture

The **Universal Log Pre-processing Framework (ULPF)** is a modular, high-throughput, explainable cybersecurity data engineering framework. It transforms heterogeneous, noisy, multi-vendor perimeter security log files into canonical, contextually enriched, and machine-learning-ready evidence while preserving cryptographic provenance and traceability.

> **Operational Scope**: ULPF processes perimeter log files, exported security event archives, and on-demand interactive inputs. It is engineered for deterministic, high-throughput batch normalization, forensic auditability, and threat intelligence analysis (it does **not** perform live network packet sniffing or inline network traffic interception).

---

## 1. High-Level Architectural Diagram

```
                        ┌────────────────────────────────────────────────────────┐
                        │                 Log Ingestion Sources                  │
                        │  • Perimeter Log Files (Syslog, CSV, JSON, XML, EVTX)  │
                        │  • Interactive Paste & Log Upload via Web Console      │
                        │  • Master Batch Pipeline CLI (`python ulpf.py`)        │
                        └──────────────────────────┬─────────────────────────────┘
                                                   │
                                                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Stage 1: Dynamic Format Detection & Parser Registry (`src/ingestion/`)                         │
│   • Multi-Format Regex & Heuristic Classifier (`format_detector.py`)                          │
│   • 12 Perimeter Parsers (Cisco ASA, Palo Alto, CEF, LEEF, Snort IDS, Syslog, WinEvent, etc.) │
└──────────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                                   │ Raw Vendor Field Dicts
                                                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Stage 2: Canonical UES Normalization & Validation (`src/schema/`)                              │
│   • FieldMapper (`field_mapper.py`): Vendor keys ➔ Unified Event Schema (`UnifiedEvent`)       │
│   • SchemaValidator (`schema_validator.py`): RFC compliant IP, port, timestamp checks        │
│   • Cryptographic record hashing: `record_hash = SHA256(raw_log)`                              │
└──────────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                                   │ Canonical UnifiedEvents
                                                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Stage 3: Contextual Security Enrichment Layer (`src/enrichment/`)                              │
│   • GeoIPResolver: Offline CIDR & private network routing, country, city, ASN                 │
│   • ThreatIntelEngine: Malicious IP, scanner, Tor exit node, C2 IP scoring                     │
│   • MitreMapper: Threat taxonomy classification (T1190, T1110, T1046, T1059, T1071, etc.)      │
└──────────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                                   │ Enriched Canonical Events
                                                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Stage 4: Machine Learning Inference Engine (`src/models/`)                                     │
│   • FeatureExtractor: 24 numeric/categorical leakage-free security features                   │
│   • Calibrated Random Forest Classifier: Probability calibration (Platt/Isotonic)             │
│   • Explicit Uncertainty Abstention: Assigns `weak_label` and `label_confidence`               │
└──────────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                                   │ Scored Events
                                                   ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Stage 5: Stateful Sliding-Window Correlation Engine (`src/correlation/`)                       │
│   • Time-window buffer (e.g. 120s sliding window)                                              │
│   • Multi-Event Detection Rules: Port Scan, Brute Force, Multi-Vector Attack, C2 Beacon        │
│   • Structured SecurityAlert generation with full event traceability                           │
└──────────────────────────────────────────────────┬─────────────────────────────────────────────┘
                                                   │
                         ┌─────────────────────────┴─────────────────────────┐
                         ▼                                                   ▼
┌─────────────────────────────────────────────────┐ ┌────────────────────────────────────────────┐
│ Stage 6: Output & Cryptographic Provenance      │ │ Stage 7: Interactive Threat Console (UI)   │
│   • Canonical Outputs (JSONL, CEF, CSV)         │ │   • Zero-noise UI (Threats / All Parsed)   │
│   • Security Alerts Log (JSONL)                 │ │   • One-Click Perimeter Presets & Upload   │
│   • Provenance Manifest (`manifest.json`):      │ │   • Instant Client-Side Search & Filter    │
│     SHA-256 integrity digests of all files      │ │   • In-Browser Landscape A4 PDF Export     │
└─────────────────────────────────────────────────┘ └────────────────────────────────────────────┘
```

---

## 2. Canonical Unified Event Schema (UES)

Every parsed event conforms to the `UnifiedEvent` dataclass ([`src/schema/unified_event.py`](file:///c:/Users/ayush/Desktop/sih/antigravity-log-project/PDS-Log-IDS-Project/src/schema/unified_event.py)). The UES standard eliminates schema fragmentation across vendor tools.

| Category | Canonical Fields | Description |
|---|---|---|
| **Traceability** | `event_uid`, `record_hash`, `source_id`, `raw_log` | Unique event UUID, SHA-256 of raw log, ingested source identity, and immutable raw string. |
| **Temporal** | `timestamp`, `ingest_timestamp` | ISO-8601 normalized event occurrence and ingestion time. |
| **Network Endpoints** | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` | Validated IPv4/IPv6 addresses, transport ports (1-65535), and normalized protocol names (TCP, UDP, ICMP). |
| **Perimeter Context** | `vendor`, `device_type`, `format_name`, `event_action`, `severity_label` | Originating firewall/sensor metadata, perimeter action (ALLOW, DENY, DROP), and severity. |
| **Threat Context** | `threat_name`, `threat_signature_id`, `mitre_tactic`, `mitre_technique_id`, `mitre_technique_name` | Threat signature name, ID, and mapped MITRE ATT&CK taxonomy codes. |
| **Enrichment** | `src_country`, `src_city`, `src_asn`, `dst_country`, `is_src_private`, `threat_intel_score`, `is_malicious` | Offline GeoIP lookup, private network detection, and threat intelligence reputation score [0.0 - 1.0]. |
| **ML Inference** | `weak_label`, `label_confidence` | Calibrated model decision (`attack`, `benign`, `uncertain`) and confidence probability. |
| **Extensibility** | `extra_fields` | Preserves vendor-specific keys without dropping unmapped data. |

---

## 3. Cryptographic Provenance Architecture

To prevent silent log tampering or forensic repudiation, ULPF computes and stores cryptographic SHA-256 audit manifests for every pipeline execution:

```json
{
  "manifest_version": "ulpf-provenance-v1.0",
  "execution_id": "7662c129-a359-450f-a496-e24cbb115f21",
  "timestamp": "2026-09-18T09:30:15.123456+00:00",
  "input_files": {
    "data/raw/firewall.log": {
      "sha256": "4a7d...391a",
      "size_bytes": 1048576,
      "format_detected": "cisco_asa"
    }
  },
  "output_files": {
    "outputs/normalized.jsonl": {
      "sha256": "9b1c...7e22",
      "size_bytes": 2097152,
      "record_count": 10000
    }
  },
  "stage_telemetry": {
    "parsed_ok": 9980,
    "parse_errors": 20,
    "threats_count": 142,
    "elapsed_ms": 185.4
  }
}
```

The `ulpf.py verify-manifest` command re-computes digests from disk and immediately flags single-byte adversary modifications or deleted records.

---

## 4. Interactive Threat Intelligence & Log Analyzer Console

The web console (`demo/index.html` and `demo/server.py`) provides an interactive interface for analysts:
- **Batch & Interactive Analysis**: Raw log lines can be pasted directly or uploaded from local files. The server endpoint `/api/process` normalizes, enriches, and classifies the logs on demand.
- **Zero-Noise Security View**: High-severity threats (firewall denies, exploit signatures, critical severities, ML attacks) are isolated into a dedicated threat intelligence feed, with an instant toggle (`🌐 All Parsed`) to view normal baseline network traffic.
- **Client-Side Export**: Generates landscape A4 incident threat briefing reports in PDF format directly in the browser with zero external server dependencies.
