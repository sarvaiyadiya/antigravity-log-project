# Project Overview: Confidence-Aware Log Intrusion Detection

## One-sentence summary

This project converts messy security logs into traceable, machine-learning-ready evidence while preserving uncertainty, avoiding future-data leakage, and keeping every decision explainable.

## Simple explanation

Imagine a security guard receives more than two million notes about visitors. Some notes are incomplete, several are joined together on one line, and none says with certainty whether the visitor was harmful.

Our system first separates and checks every note. It gives each occurrence a unique receipt, preserves the original information, records why an event looks suspicious, and says “uncertain” when the evidence is insufficient. It then converts previous behaviour into numerical signals that a future machine-learning model can study. Finally, it prevents large attack bursts from unfairly dominating training and keeps later events separate for an honest exam.

The project is not yet a finished intrusion detector. It is currently a verified data, labeling, feature, and evaluation foundation for the classifier that will be developed in later practicals.

## What was provided

The professor provided a practical list and a folder containing security-log resources. The current pipeline uses the raw `cj.log` file as its primary evidence source. Existing notebooks and derived CSV files in the supplied folder are treated as reference material, not as authoritative ground truth.

The raw log contains:

- 2,062,361 valid event records;
- 934 blank physical lines;
- 911 physical lines containing more than one record array;
- eight original fields: category type, sub-key, timestamp, client IP, source port, user agent, language, and metadata;
- events from 8 January 2023 to 19 February 2024;
- 16,680 distinct clients.

Important fields normally found in web-access logs—such as HTTP method, response status, response size, and referrer—are not available. The project does not invent them.

There is also no authoritative human-created attack/benign ground truth. Consequently, the current labels are explicitly described as **weak labels**, not proven facts.

## How the path from input to output was chosen

```text
Raw cj.log
   ↓ inspect without modifying the professor's files
Streaming exploration
   ↓ understand the real format and data quality
Structured event records
   ↓ preserve source location, occurrence identity, and content identity
Validated and conservatively cleaned records
   ↓ keep valid evidence; add normalized fields instead of overwriting originals
Confidence-aware weak labels
   ↓ store evidence, conflicts, and abstention separately
Leakage-aware causal features
   ↓ use current information and previously observed behaviour only
Frozen temporal splits and training-only weights
   ↓
Future aggregation, analysis, classification, and reusable pipeline
```

At every stage, `event_id` and `record_hash` align sidecar files with the same event. SHA-256 fingerprints and JSON manifests record which input, code version, policy, and output produced each artifact.

## Work completed through Practical 6

| Practical | Technical work | Simple meaning |
|---|---|---|
| 1. Log exploration | Streamed the raw file, discovered concatenated arrays, measured missingness and concentration, and inspected values safely. | We learned what the data truly contains before changing it. |
| 2. Structuring | Parsed all 2,062,361 events, retained source line and array position, created `event_id` and `record_hash`, preserved null versus empty string, and provided quarantine handling. | Every note received a traceable receipt without losing its original meaning. |
| 3. Cleaning | Validated every timestamp, IP, and port; preserved all valid rows; added normalized fields; did not impute, deduplicate, overwrite, or sort the evidence. | We checked and standardized the notes without silently “fixing” or deleting them. |
| 4. Weak labeling | Created attack, benign-like, and uncertain labels with confidence, evidence codes, conflict flags, and versioning. Labels are event-local and do not spread through an IP's future history. | The system states what it suspects, why, and how certain the rule is. It can also say “I do not know.” |
| 5. Feature engineering | Produced 21 numerical features: 11 event-local and 10 past-only behavioural features. Client state is updated only after the current event is transformed and remains correct across file chunks. | The system translates logs into patterns a model can understand without peeking ahead. |
| 6. Imbalance handling | Rejected a misleading event-percentage split, froze calendar-based train/validation/test periods, and calculated class- and confidence-aware weights using training labels only. | Training is made fairer without copying, deleting, or manufacturing events, and later data remains an honest exam. |

## Key results so far

### Weak-label results

| Label | Records | Meaning |
|---|---:|---|
| Attack | 1,830,340 | Event-local rules found scanner or payload evidence. |
| Benign-like | 191,584 | Browser-style evidence appeared without detected attack evidence; this is not proof of safety. |
| Uncertain | 40,437 | Evidence was insufficient, so the system abstained. |

There are 21,728 records with conflicting evidence. Only 2,418 attack labels contain payload-pattern evidence; most attack labels rely on a declared scanner user agent. This dependence is documented because user-agent text can be spoofed.

### Feature results

- All 2,062,361 events received 21 aligned features.
- Features include cyclic time, port ranges, language structure, previous-event timing, repeated-port behaviour, unique-port history, and exponentially decayed activity over 60, 300, and 3,600 seconds.
- Exactly 585 source-order timestamp reversals were preserved as an explicit feature.
- `is_privileged_port` has zero variance because all observed source ports are above 1023. It remains in the immutable artifact but is excluded from modeling.
- Direct IP values, weak-label evidence sources, and target metadata are forbidden as primary model inputs.

### Split and balancing results

| Split | Period | Attack | Benign | Uncertain | Purpose |
|---|---|---:|---:|---:|---|
| Train | 2023 | 130,243 | 102,811 | 33,198 | Learn model parameters. |
| Validation | January 2024 | 393,419 | 83,642 | 3,416 | Select and tune the model. |
| Test | February 2024 | 1,306,678 | 5,131 | 3,823 | Measure future performance under severe drift and attack bursts. |

The original 70/15/15 event-count split was rejected because a major scanner burst compressed validation into only a few hours with just 24 benign records. Complete calendar periods provide more defensible evaluation.

Training weights are approximately 0.895 for attack records and 1.133 for benign records. Confidence is normalized within each class, so the lower benign confidence policy does not cancel minority-class balancing. The weighted effective sample size is approximately 229,796 of 233,054 supervised training records, showing that weighting has not concentrated influence into a small number of examples.

## Important technical terms in plain language

| Technical term | Plain-language meaning |
|---|---|
| Provenance | A record of where data came from and what happened to it. |
| Weak label | An evidence-based suggestion, not verified truth. |
| Confidence | The strength assigned by the documented labeling policy; it is not yet a calibrated probability. |
| Abstention | The system says “uncertain” instead of forcing an unsafe answer. |
| Feature engineering | Converting raw information into numerical signals a model can use. |
| Past-only or causal feature | A signal calculated without looking at later events. |
| Target leakage | Accidentally giving the model information that already reveals the answer. |
| Class imbalance | One outcome occurs much more often than another. |
| Sample weight | How strongly one training example influences learning. |
| Sidecar | A smaller aligned file containing labels, features, or weights without duplicating the complete log. |
| Manifest | A machine-readable receipt describing inputs, outputs, policies, counts, and fingerprints. |
| Idempotent execution | Rerunning the same step safely reuses a verified result instead of silently overwriting it. |

## What is distinctive about the project

The main distinction is the combination of safeguards across the complete data path:

1. **Occurrence and content are represented separately.** `event_id` preserves each occurrence, while `record_hash` identifies identical content. Repeated events therefore remain countable instead of being incorrectly deleted.
2. **Uncertainty is first-class data.** Labels retain confidence, supporting evidence, conflicts, abstention, and policy version.
3. **Labels are not propagated through complete client histories.** This avoids assuming that every event from an IP belongs to one person or one intent and prevents future information from altering earlier labels.
4. **Feature generation is arrival-causal.** The current event is measured from previous state before it updates that state. The result is invariant to CSV chunk boundaries.
5. **Labeling evidence is separated from primary model features.** The future classifier must learn behaviour rather than merely reproduce the weak-label rules.
6. **Balancing preserves real events.** Training-only class and within-class confidence weighting replaces blind SMOTE, oversampling, or deletion.
7. **Evaluation responds to temporal drift.** A misleading percentage split was rejected, and a frozen calendar test preserves the real February attack burst.

This integrated design is a strong research foundation, but it must not yet be described as patented or legally novel. Patentability requires a formal prior-art search and a precisely defined new mechanism. A promising future research direction is a dynamic, time-causal evidence-reliability and conflict-aware abstention method; that extension has not yet been implemented or validated.

## Advantages and disadvantages

| Advantages | Disadvantages or current limitations |
|---|---|
| Every transformation is traceable and fingerprinted. | There is no authoritative human-labeled ground truth. |
| Valid evidence is preserved instead of aggressively deleted or imputed. | Most attack labels depend on declared scanner user agents, which can be spoofed. |
| Uncertain and conflicting cases remain visible. | “Benign-like” at confidence 0.55 does not prove an event is harmless. |
| Streaming and chunked processing handle more than two million events. | Generated CSV artifacts are large and require local storage. |
| Causal features reduce future-data leakage. | Stateful feature generation uses memory for client and port history. |
| Training, validation, and testing follow time order. | February has extreme distribution drift, so accuracy alone will be misleading. |
| The original logs and sensitive generated data remain outside GitHub. | Timestamps have no known timezone, and the schema lacks several common HTTP fields. |
| Modules and notebooks provide both reusable code and academic explanation. | Classification accuracy, calibration, latency, and production performance have not yet been measured. |

## Intended uses and consumers

### Current consumers

- **Professor or examiner:** evaluate data-science concepts, engineering correctness, reasoning, and reproducibility.
- **Student or researcher:** study log parsing, weak supervision, temporal leakage, behavioural features, drift, and uncertainty.
- **Machine-learning engineer:** reuse the provenance, feature-contract, sidecar, manifest, and split patterns.

### Future operational consumers

- **Security analyst or SOC team:** receive prioritized events together with supporting evidence and uncertainty.
- **Website or service owner:** obtain earlier warning of scanning or suspicious behaviour.
- **Incident investigator:** trace a prediction back to the original event and processing policy.

The current project should be used for research and supervised analysis, not as an autonomous blocking system. A weak label or future model prediction should not by itself block an IP, accuse a person, or delete evidence.

## How to explain the project

### To a nontechnical person

> We are building a careful security assistant for a very large collection of server notes. It organizes every note, keeps proof of where it came from, marks suspicious activity with reasons, admits when it is unsure, and learns patterns only from the past. We are currently preparing trustworthy training material; the final prediction model comes later.

### To a professor or technical reviewer

> The project implements a provenance-preserving, chunked log pipeline over 2,062,361 events. It produces event-local weak labels with confidence, conflict, and abstention; constructs leakage-restricted event-local and online causal features; and freezes calendar-based evaluation partitions with training-only class and within-class confidence normalization. All sidecars are aligned by event identity and verified through manifests and SHA-256 fingerprints.

## Current boundary and next work

Completed: exploration, structuring, conservative preprocessing, weak labeling, causal feature engineering, and leakage-safe imbalance handling.

Not completed yet: Practical 7 aggregation, Practical 8 exploratory analysis and visualization, Practical 9 classifier training and evaluation, Practical 10 reusable end-to-end pipeline, operational deployment, and formal patent prior-art assessment.

