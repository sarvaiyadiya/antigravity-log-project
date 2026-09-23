# ✅ WORK DONE — ULPF (Universal Log Pre-processing Framework)

> Last updated: 2026-09-18 (P1 + P2 + P3 + P4 + P5 + P6 + P7 COMPLETE)
> SIH Problem Statement: Universal Log Pre-processing Framework for perimeter network device logs

---

## 🏗️ Core Architecture (Complete)

### Universal Event Schema (`src/schema/`)
- [x] `UnifiedEvent` dataclass — canonical normalized event structure
  - `event_uid` (UUID), `record_hash` (SHA-256), `raw_log` (lossless preservation)
  - Full network 5-tuple: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
  - HTTP fields: `http_method`, `http_url`, `http_status`, `user_agent`
  - Threat fields: `threat_name`, `threat_signature_id`, `severity`
  - Enums: `EventSeverity`, `EventCategory`, `EventAction`, `SourceType`
  - `extra_fields` dict for zero-loss overflow of unmapped fields
  - **Enrichment slots (P4)**: `src_country`, `src_city`, `src_asn`, `dst_country`, `is_src_private`, `threat_intel_score`, `threat_intel_source`, `is_malicious`, `mitre_tactic`, `mitre_technique_id`, `mitre_technique_name`
  - **ML Prediction slots (P6)**: `weak_label` ("attack", "benign", "uncertain"), `label_confidence` (calibrated probability)
- [x] `FieldMapper` — YAML-driven field name translation (source -> UES canonical)
  - Severity, action, category, device_type value normalization
  - Direct passthrough coercion for fields matching canonical UES names
  - Overflow routing to `extra_fields` for unknown vendor fields
- [x] `SchemaValidator` — validates UnifiedEvent fields at ingest time

### Ingestion Layer (`src/ingestion/`)
- [x] `BaseLogParser` — abstract interface (3 methods: `format_name`, `can_parse`, `parse_line`)
- [x] `ParserRegistry` — singleton plug-and-play router with auto-discovery
- [x] `FormatDetector` — auto-detects log format by sampling first 10 lines

### Format Parsers (12 formats — 7 original + 5 new ✅)
- [x] `syslog_parser.py` — RFC 3164 and RFC 5424 Syslog
- [x] `cef_parser.py` — ArcSight Common Event Format (CEF)
- [x] `leef_parser.py` — IBM QRadar LEEF
- [x] `snort_parser.py` — Snort / Suricata fast alert format
- [x] `json_parser.py` — Generic JSON object per line
- [x] `csv_parser.py` — Generic CSV / TSV
- [x] `cj_parser.py` — cj.log 8-field JSON array (primary data source)
- [x] `windows_event_parser.py` — Windows Security Event Log (XML) — EventIDs 4624, 4625, 4688, 4720, 4740 etc.
- [x] `cisco_asa_parser.py` — Cisco ASA / Firepower FTD native syslog (%ASA-n-NNNNNN:)
- [x] `paloalto_parser.py` — Palo Alto PAN-OS Traffic + Threat logs (CSV) — registers 2 parsers
- [x] `cloudtrail_parser.py` — AWS CloudTrail API call records (JSON Records wrapper)
- [x] `xml_parser.py` — Generic XML fallback parser (any XML-structured log)

### Live Ingestion Layer (`src/ingestion/`) ✅ P2
- [x] `syslog_listener.py` — Real-time UDP/TCP Syslog receiver (port 514)
- [x] `file_watcher.py` — Live log file tail watcher (like `tail -f`)
- [x] `rest_receiver.py` — HTTP REST webhook receiver (`POST /ingest`, `POST /ingest/batch`, `GET /health`, `GET /stats`)

### Live Visualization Dashboard (`demo/`) ✅ P3
- [x] `demo/server.py` — Pure Python standard library HTTP server (zero external dependencies):
  - In-memory thread-safe ring buffer (`collections.deque(maxlen=10000)`)
  - Server-Sent Events (SSE) live streaming (`GET /api/events/stream`)
  - REST endpoints (`/api/stats`, `/api/events`, `/api/ingest`, `/api/process`, `/api/parsers`, `/api/alerts`, `/api/simulate`, `/api/model/info`)
  - Background file tailer for output files
- [x] `demo/index.html` — Cyber-operations operations console:
  - 3 tabs: ⚡ Live Perimeter Stream, 🔬 Interactive Log Analyzer, 🛡️ Threat Alerts & Correlation
  - 5 KPI cards with real-time counters & throughput EPS
  - 3 Chart.js dynamic visualizations
  - Live table with search, format/severity/action filters, and accordion drawers
  - 10 preset samples + 3 one-click attack simulation triggers
  - ML Engine status badge in header + per-row ML prediction pills (`ML:ATTACK`, `ML:BENIGN`, `ML:UNCERTAIN`)
- [x] `demo/demo_data_generator.py` — Multi-format traffic simulator
- [x] CLI integration: `python -m ulpf demo` and `python ulpf.py demo`

---

## 🛡️ Contextual Enrichment Layer (`src/enrichment/`) ✅ P4 COMPLETE

- [x] `geoip.py` — **Offline GeoIP & ASN Resolver**:
  - RFC 1918 private network classification (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`)
  - Embedded offline CIDR routing table for major global clouds, CDNs, ISPs, and regional blocks
  - Resolves `src_country`, `src_city`, `src_asn`, `is_src_private`, and `dst_country`
  - 100% offline (air-gapped ready)
- [x] `threat_intel.py` — **Offline Threat Reputation Engine**:
  - Curated malicious IP/CIDR blocklists for Tor exit nodes, botnets, Shodan/Masscan scanners, and C2 pools
  - Computes `threat_intel_score` (0.0 to 1.0), assigns `threat_intel_source`, flags `is_malicious`
  - Supports loading external custom IP blocklists from disk
- [x] `mitre_mapper.py` — **MITRE ATT&CK Taxonomy Classifier**:
  - Maps threat signatures, event actions, and log payloads to standardized ATT&CK enterprise tactics and technique IDs:
    - Web Application Attacks -> **T1190** (*Exploit Public-Facing Application*, Initial Access)
    - Brute Force & Auth Failures -> **T1110** (*Brute Force*, Credential Access)
    - Port Scans & Probes -> **T1046** (*Network Service Discovery*, Discovery)
    - Command Injection & Web Shells -> **T1059** (*Command and Scripting Interpreter*, Execution)
    - C2 Beacons & Botnets -> **T1071** (*Application Layer Protocol*, Command and Control)
    - Denial of Service & Floods -> **T1498** (*Network Denial of Service*, Impact)
    - Cloud IAM Privilege Escalation -> **T1078** (*Valid Accounts*, Privilege Escalation)
- [x] `enrichment_pipeline.py` — **Master Enrichment Coordinator**:
  - Single-call pipeline: `enrichment_pipeline.enrich(event)`
- [x] `configs/enrichment.yaml` — Master enrichment configuration

---

## ⚡ Correlation Engine & Alert Generation (`src/correlation/`) ✅ P5 COMPLETE

- [x] `alert.py` — **Canonical SecurityAlert Schema**:
  - `alert_id`, `timestamp_utc`, `rule_name`, `incident_type`, `severity`, `primary_ip`, `target_ip`, `event_count`
  - Full traceability with `correlated_event_uids` mapping to canonical `UnifiedEvent.event_uid`s
  - MITRE tags (`mitre_tactic`, `mitre_technique_id`, `mitre_technique_name`)
  - `to_dict()`, `to_json()`, and `create()` factory
- [x] `rule_engine.py` — **Stateful Sliding-Window Correlation Engine**:
  - In-memory event deques per entity (`src_ip`) with thread-safe lock
  - Automated sliding-window pruning (max window 300s)
  - Cooldown suppression dictionary to prevent alert flooding
  - 5 built-in multi-event rules (`PORT_SCAN_SWEEP`, `BRUTE_FORCE_CAMPAIGN`, `CROSS_DEVICE_CAMPAIGN`, `MALICIOUS_C2_BEACON`, `HIGH_SEVERITY_MULTI_VECTOR`)
- [x] `configs/correlation_rules.yaml` — Declarative YAML rules definition
- [x] Pipeline CLI integration: `--correlate`, `--no-correlate`, `--alerts-file <path>`
- [x] Live Dashboard integration: 3rd Tab **`🛡️ Threat Alerts`**, active alerts pulsing KPI card, alert drawers

---

## 🤖 Machine Learning Classification & Inference (`src/models/`) ✅ P6 COMPLETE

- [x] `feature_extractor.py` — **Standardized 24-Dimensional Feature Extractor**:
  - Converts any `UnifiedEvent` (from all 12 formats) into numerical vector: ports, protocols, actions, severities, temporal sin/cos, private IP, threat intel score, MITRE presence, and user-agent length
- [x] `train.py` — **Model Training & Calibration**:
  - Synthetic & historical perimeter event training generator
  - Random Forest classifier with balanced class weights
  - Sigmoid probability calibration (`CalibratedClassifierCV`) on validation split
  - Serializes to `models/classifier.joblib` and `models/metadata.json`
- [x] `inference.py` — **Serialized Inference Engine**:
  - `LogClassifier` with `predict()`, `predict_batch()`, `annotate_event()`, `annotate_batch()`
  - Explicit abstention (`"uncertain"`) when confidence < 0.60
  - Auto-bootstrapping fallback if artifact is absent
- [x] `evaluate.py` — **Standalone Evaluation & Diagnostic Script**:
  - Full metric evaluation: Accuracy, Precision, Recall, F1, Balanced Accuracy, MCC, ROC-AUC, Brier score, Confusion Matrix
  - Outputs to `outputs/model_evaluation_report.json`
- [x] `notebooks/practical_09_classification.ipynb` — **Academic Practical 9 Notebook**:
  - 4 baselines (Majority class, static rule, Logistic Regression, Random Forest)
  - Zero-variance training-fitted feature screening
  - Calibration assessment & abstention analysis
- [x] CLI & Dashboard Integration:
  - `python ulpf.py ingest --classify`
  - `python ulpf.py train --samples 3000`
  - `python ulpf.py evaluate --model models/classifier.joblib`
  - Live demo dashboard: `GET /api/model/info` + UI status badge + per-event ML badges

---

## 🔗 Master End-to-End Pipeline & Provenance Verification (`src/pipeline.py`) ✅ P7 COMPLETE

- [x] `run_pipeline(...)` — **Unified Multi-Stage Processing Pipeline**:
  - Stage 1: Dynamic format detection across 12 perimeter standards
  - Stage 2: Canonical UES normalization & lossless field mapping
  - Stage 3: Contextual enrichment (GeoIP, ASN, Threat Intel, MITRE ATT&CK)
  - Stage 4: Machine learning calibrated inference & confidence scoring
  - Stage 5: Stateful sliding-window correlation engine & SecurityAlert generation
  - Stage 6: Multi-format serialization (JSON-lines, CEF, CSV) + cryptographic manifest
- [x] `generate_manifest(...)` — **Cryptographic Provenance Manifest Engine**:
  - Computes SHA-256 digests for all input files, canonical output files, and threat alerts
  - Records execution metadata, event counts, time ranges, and system provenance
  - Outputs tamper-evident audit document: `outputs/provenance_manifest.json`
- [x] `verify_manifest(...)` & `verify_manifest_details(...)` — **Tamper Detection Engine**:
  - Recomputes SHA-256 digests on-disk against the recorded manifest
  - Identifies single-byte tampering, adversary file modification, and missing outputs
- [x] `notebooks/practical_10_pipeline.ipynb` — **Academic Practical 10 Notebook**:
  - Concludes the 10-part academic practical series
  - Demonstrates heterogeneous perimeter log parsing across Cisco ASA, Palo Alto, and Snort
  - Validates ML classification, contextual enrichment, and sliding-window correlation alerts
  - Features an interactive SHA-256 provenance integrity check and tamper-detection simulation
- [x] CLI Master Subcommands:
  - `python ulpf.py pipeline --input <path> --output <path> --manifest <path>`
  - `python ulpf.py verify-manifest --manifest <path>`
- [x] `tests/test_e2e_pipeline.py` — 9 dedicated end-to-end integration and tamper-detection tests

---

## 🔬 Academic Practicals Status

| Practical | Name | Status |
|---|---|---|
| Practical 1 | Log Exploration | ✅ COMPLETE |
| Practical 2 | Log Structuring | ✅ COMPLETE |
| Practical 3 | Preprocessing & Validation | ✅ COMPLETE |
| Practical 4 | Weak Labeling | ✅ COMPLETE |
| Practical 5 | Feature Engineering | ✅ COMPLETE |
| Practical 6 | Imbalance Handling | ✅ COMPLETE |
| Practical 7 | Data Wrangling & Aggregation | ✅ COMPLETE |
| Practical 8 | EDA & Visualization | ✅ COMPLETE |
| Practical 9 | Classification & Calibration | ✅ COMPLETE |
| Practical 10 | End-to-End Pipeline Integration | ✅ COMPLETE |

---

## 🧪 Tests
- [x] `tests/test_parsers.py` — 75 parser tests passing
- [x] `tests/test_schema.py` — 21 schema validation tests passing
- [x] `tests/test_demo_server.py` — 9 live endpoint & SSE streaming tests passing
- [x] `tests/test_enrichment.py` — 16 GeoIP, Threat Intel, and MITRE ATT&CK tests passing
- [x] `tests/test_correlation.py` — 10 correlation & alert tests passing
- [x] `tests/test_classifier.py` — 12 feature extraction, training & inference tests passing
- [x] `tests/test_e2e_pipeline.py` — 9 end-to-end pipeline and tamper detection tests passing
- [x] **Total: 152 tests, 152 passing (100% pass rate) ✅**

---

## ✅ PRIORITY 8 — Documentation & SIH Presentation Materials — COMPLETE
- [x] Master `README.md`:
  - Executive Badges (Tests 152/152 passing, Python 3.10+, 12 Formats, UES Canonical, SHA-256 Provenance)
  - Full ASCII & Mermaid system architecture diagram
  - Comprehensive 12-format coverage reference table
  - Canonical UES JSON schema specification
  - Complete CLI usage reference for all 7 subcommands (`pipeline`, `verify-manifest`, `ingest`, `listen`, `demo`, `train`, `evaluate`)
  - REST & SSE live streaming API documentation
  - Cryptographic provenance manifest specification
  - 10-part academic curriculum alignment table
- [x] `requirements.txt`:
  - Pinned production and testing dependencies (`pyyaml`, `scikit-learn`, `joblib`, `numpy`, `pytest`)
- [x] `docs/SETUP.md`:
  - Step-by-step setup guide for Linux, macOS, and Windows
  - Instructions for virtual environment, dependencies, tests, pipeline runs, and dashboard
- [x] `docs/architecture.md`:
  - Comprehensive technical design document with end-to-end data flow and lifecycle breakdown
- [x] `docs/sih_presentation.md`:
  - Dedicated SIH Hackathon deck outline with Problem Statement alignment, architecture breakdown, innovation highlights, and judge evaluation checklist
- [x] `docs/demo_script.md`:
  - Rehearsal-ready 5-minute live demo script with exact terminal commands, GUI walkthrough steps, and tamper-detection showcase

