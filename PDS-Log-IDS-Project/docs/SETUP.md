# 🚀 ULPF Quickstart & Setup Guide

This guide provides step-by-step instructions to set up, test, and run the **Universal Log Pre-processing Framework (ULPF)**.

> **Note on Operating Model**: ULPF operates as a high-throughput, deterministic log pre-processing, normalization, contextual enrichment, and threat intelligence framework. It processes raw perimeter log files, exported security event archives, and on-demand interactive inputs (it does not perform live network packet sniffing or inline network traffic interception).

---

## 1. Prerequisites

- **Python**: Version 3.10 or higher
- **Operating System**: Linux, macOS, or Windows
- **Git**: (Optional) For version control

---

## 2. Environment Setup

### Step A: Clone or Navigate to the Repository
```bash
cd PDS-Log-IDS-Project
```

### Step B: Create and Activate a Virtual Environment
- **Linux / macOS**:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```
- **Windows (PowerShell)**:
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  ```

### Step C: Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 3. Verify Installation with the Test Suite

Run the full automated test suite to ensure all 12 parsers, contextual enrichment, ML inference, and provenance features are functional:

```bash
pytest tests/ -v
```

Expected output:
```text
============================= 152 passed in ~5.0s =============================
```

---

## 4. Running the Master End-to-End Pipeline

Execute a complete end-to-end pipeline run that parses raw logs, applies contextual enrichment (GeoIP, Threat Intel, MITRE ATT&CK), evaluates calibrated ML inference, runs sliding-window correlation, and writes an audited cryptographic manifest:

```bash
python ulpf.py pipeline \
  --input data/raw/cisco_asa.log \
  --output outputs/cisco_normalized.jsonl \
  --alerts outputs/cisco_alerts.jsonl \
  --manifest outputs/cisco_manifest.json
```

### Supported Pipeline Flags:
- `--format <auto|cisco_asa|paloalto_threat|cef|snort|syslog|leef|windows_event_xml|cloudtrail|json|xml>`: Explicitly select format (or use `auto` for heuristic detection).
- `--output-format <jsonl|cef|csv>`: Select serialization format.
- `--no-enrich`: Skip GeoIP, Threat Intel, and MITRE mapping.
- `--no-classify`: Skip ML classifier scoring.
- `--no-correlate`: Skip stateful sliding-window correlation.
- `--max-events <N>`: Process up to N events.

---

## 5. Verifying Cryptographic Provenance & Tamper Detection

Verify that neither the ingested log files nor the generated canonical output files have been modified or tampered with on disk:

```bash
python ulpf.py verify-manifest --manifest outputs/cisco_manifest.json
```

Expected output:
```text
[OK] Manifest verification PASSED:
  Execution ID : 7662c129-a359-450f-a496-e24cbb115f21
  Input Files  : 1 verified (0 mismatches, 0 missing)
  Output Files : 1 verified (0 mismatches, 0 missing)
  Alert Files  : 1 verified (0 mismatches, 0 missing)
```

If an attacker or insider modifies a single byte of an archived event log, `verify-manifest` immediately flags the mismatch and pinpoints the corrupted file.

---

## 6. Running the Interactive Security Log Analyzer Console

Launch the zero-dependency web operations console (built entirely in Python's standard library with zero external web framework dependencies):

```bash
python ulpf.py demo --port 7000
```
or:
```bash
python demo/server.py --port 7000
```

Open your browser and navigate to:
```text
http://localhost:7000
```

### Web Console Features:
- **One-Click Presets**: Immediately test Cisco ASA, Palo Alto Threat, ArcSight CEF, Snort IDS, Syslog, LEEF, Windows Event XML, AWS CloudTrail, and JSON logs.
- **Log Upload & Paste**: Upload local perimeter log files or paste raw log lines into the editor.
- **Zero-Noise Security Filtering**: Automatically isolates actionable threats (firewall denies, exploit signatures, critical severities, ML attacks) while allowing instant toggle to inspect safe baseline traffic (`🌐 All Parsed`).
- **Live Search & Filter**: Sub-millisecond client-side filtering across IPs, event actions, signatures, and MITRE techniques.
- **Executive PDF Threat Report**: Download professional landscape A4 threat briefings generated directly in the browser with zero server dependencies.

---

## 7. Machine Learning Model Training & Evaluation

Train or evaluate the calibrated Random Forest intrusion detection classifier:

### Train the Calibrated Model:
```bash
python ulpf.py train \
  --input data/processed/cleaned_events.jsonl \
  --output models/calibrated_rf.joblib
```

### Evaluate Model Metrics:
```bash
python ulpf.py evaluate \
  --model models/calibrated_rf.joblib \
  --test-data data/processed/test_split.jsonl
```
Outputs classification report (Precision, Recall, F1-score) and confusion matrix with explicit uncertainty preservation.
