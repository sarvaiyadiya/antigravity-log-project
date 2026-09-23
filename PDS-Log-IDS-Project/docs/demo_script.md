# 🎬 5-Minute Live Demo Script for Judges
## Project: ULPF (Universal Log Pre-processing Framework)

This script is engineered for a flawless, high-impact live demonstration during evaluation or presentation sessions.

---

## ⏱️ Timeline Summary

| Time | Phase | Target Screen / Tool |
|---|---|---|
| **0:00 - 1:00** | System Health & CLI Test Suite | Terminal (`pytest tests/ -v`) |
| **1:00 - 2:30** | Live Dashboard & Zero-Noise Ingestion | Web Browser (`http://localhost:7000`) |
| **2:30 - 3:30** | Multi-Format Ingestion & Threat Isolation | Web Browser (Palo Alto, Snort, CloudTrail presets) |
| **3:30 - 4:15** | PDF Incident Threat Report Generation | Web Browser ("Download PDF" button) |
| **4:15 - 5:00** | Cryptographic Provenance & Tamper Showcase | Terminal (`ulpf.py verify-manifest`) |

---

## 📝 Step-by-Step Demonstration Actions

### Step 1: Prove System Reliability & Engineering Quality (0:00 - 1:00)
**Action**: Open your terminal and run the test suite:
```bash
pytest tests/ -v
```
**Speaking Script**:
> *"Before we show you the live interface, we want to demonstrate engineering rigor. ULPF is backed by 152 automated unit and integration tests covering 12 perimeter format parsers, enrichment pipelines, calibrated ML models, sliding-window correlation, and cryptographic provenance — all passing with a 100% pass rate in under 5 seconds."*

---

### Step 2: Launch the Zero-Dependency Live Dashboard (1:00 - 1:30)
**Action**: Start the server (if not already running):
```bash
python ulpf.py demo --port 7000
```
Open your browser to `http://localhost:7000`.

**Speaking Script**:
> *"Here is the ULPF Threat Intelligence & Log Analyzer. Notice that this entire dashboard backend runs in Python's standard library with zero external web framework overhead. It is lightweight enough to run air-gapped on edge firewalls or local SOC workstations."*

---

### Step 3: Zero-Noise Threat Ingestion & Format Auto-Detection (1:30 - 2:30)
**Action**:
1. Click the **`🛡️ Palo Alto Threat`** preset button.
2. Click **`▶ Analyze Logs`**.

**Visual Output**:
- Top KPI cards update instantly: Total Logs = 1, Threats Isolated = 1 (100%), Format = `PALOALTO_THREAT`.
- The right panel renders the canonical UES event card highlighted with a red threat border:
  - Severity: **CRITICAL**
  - MITRE ATT&CK: **T1190 (Exploit Public-Facing Application)**
  - ML Confidence: **ML:ATTACK (99%)**
  - Origin: **198.51.100.12 (United States) ➔ 10.0.0.45**

**Speaking Script**:
> *"With one click, ULPF auto-detected the complex Palo Alto CSV format, extracted the threat vector, mapped it against MITRE ATT&CK technique T1190, resolved GeoIP/ASN, and ran our calibrated Random Forest classifier. Crucially, ULPF operates under a Zero-Noise security model: rather than burying the analyst in baseline records, high-severity threats are isolated immediately."*

---

### Step 4: Multi-Format Agility & Baseline Toggle (2:30 - 3:30)
**Action**:
1. Click the **`🔥 Cisco ASA Firewall`** preset button.
2. Click **`▶ Analyze Logs`**.
3. Point to the detected format (`CISCO_ASA`) and the 2 isolated deny actions.
4. Click the **`🌐 All Parsed`** button in the toolbar, then switch back to **`🛡️ Threats Only`**.

**Speaking Script**:
> *"Now we test a completely different vendor: Cisco ASA syslog. Without changing any configuration or writing custom regex, the engine auto-detects the format and standardizes the records into the identical canonical UES schema. Analysts can toggle between isolated threats and normal baseline network traffic at any time."*

---

### Step 5: Instant Threat Intelligence PDF Export (3:30 - 4:15)
**Action**:
1. Click the **`⬇ Download PDF`** button on the interface.
2. Open the downloaded PDF file (`ulpf_threat_report_*.pdf`).

**Visual Output**:
- Landscape A4 executive security briefing.
- Dark navy header with official ULPF branding and timestamp.
- Executive KPI summary box showing Total Scanned, Threats Isolated, and Noise Reduction Percentage.
- Formatted tabular records showing Event #, Vendor Format, Source IP, Destination IP, Action, Severity, Threat Signature, and MITRE Technique.
- Formal Confidentiality & Cryptographic Provenance footer.

**Speaking Script**:
> *"In an incident response situation, compliance officers and C-suite executives need immediate documentation. ULPF compiles an executive incident report directly in the browser with zero external server dependencies, filtering out benign noise and delivering a clean, auditable threat briefing."*

---

### Step 6: Cryptographic Provenance & Tamper Detection (4:15 - 5:00)
**Action**: Switch back to the terminal and execute the pipeline with manifest generation:
```bash
python ulpf.py pipeline \
  --input data/raw/cisco_asa.log \
  --output outputs/cisco.jsonl \
  --manifest outputs/manifest.json
```
Then run the verification check:
```bash
python ulpf.py verify-manifest --manifest outputs/manifest.json
```

**Visual Output**:
```text
[OK] Manifest verification PASSED:
  Execution ID : 7662c129-a359-450f-a496-e24cbb115f21
  Input Files  : 1 verified (0 mismatches, 0 missing)
  Output Files : 1 verified (0 mismatches, 0 missing)
  Alert Files  : 1 verified (0 mismatches, 0 missing)
```

**Speaking Script**:
> *"Finally, we address chain-of-custody and evidence integrity. ULPF generates SHA-256 cryptographic provenance manifests for every run. If an insider or adversary modifies even a single byte of an event log to conceal an attack, `verify-manifest` flags the exact corrupted file instantly. This guarantees forensic defensibility in a court of law."*

---

## 🎯 Quick Troubleshooting During Live Demos

- If port 7000 is occupied: Launch on port 7001 via `python demo/server.py --port 7001`.
- If browser displays cached view: Press `Ctrl + Shift + R` to hard reload.
- If you need to clear the editor: Click the **`🗑 Clear`** button in the ingestion toolbar.
