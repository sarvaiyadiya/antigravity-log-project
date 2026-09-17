# Future Development and Research Plan

## Purpose

This document defines how the current academic work can progress from completed practicals into a defensible research project and, only if novelty is established, a patent candidate.

The central goal is not merely to obtain a high classification score. It is to build an intrusion-detection method that can explain its evidence, recognize conflict, adapt to changes over time, preserve uncertainty, and be evaluated without data leakage.

This is a living plan. Decisions may change when experiments or prior-art searches provide new evidence, but every change should be recorded and versioned.

## Starting point

Practicals 1–6 have established the foundation:

- 2,062,361 raw log events were parsed and preserved;
- original values, event occurrence, content identity, and source position remain traceable;
- timestamps, ports, and IP addresses were validated without deleting valid rows;
- event-local weak labels retain confidence, evidence, conflict, and abstention;
- 21 leakage-aware features were generated using current and past-only information;
- calendar-based train, validation, and future-test periods were frozen;
- training-only class and confidence weights were generated without resampling real events;
- every major artifact has a manifest and SHA-256 fingerprint.

The project does **not** yet have a trained final classifier, verified ground truth, production deployment, proven research novelty, or a patentable claim.

## Guiding rules

| Rule | Technical reason | Simple meaning |
|---|---|---|
| Preserve raw evidence | Enables provenance and later correction. | Never destroy the original note. |
| Use only past information | Prevents temporal leakage. | Do not let the model see the future. |
| Keep label evidence out of the primary model | Prevents rule-reproduction leakage. | Do not secretly give the answer to the model. |
| Preserve uncertainty | Weak labels are not ground truth. | Allow “I do not know.” |
| Split before fitting or balancing | Keeps evaluation independent. | Prepare the exam before studying the answers. |
| Never balance validation or test data | Preserves real operating conditions. | Do not make the exam artificially easier. |
| Keep the repository private during novelty assessment | Public disclosure may affect patent options. | Do not publish the invention before checking it. |
| Freeze the test set | Prevents repeated tuning on future results. | Use the final exam only at the end. |

## Planned project flow

```text
COMPLETED FOUNDATION
Raw logs → structure → conservative cleaning → weak labels
         → causal features → frozen splits and training weights

ACADEMIC COMPLETION
         → Practical 7: multi-level aggregation
         → Practical 8: leakage-aware EDA and drift analysis
         → Practical 9: baselines, calibration, and evaluation
         → Practical 10: reusable end-to-end pipeline

RESEARCH DEVELOPMENT
         → audited reference labels
         → literature and patent prior-art review
         → formal research questions and frozen hypotheses
         → temporal evidence-reliability model
         → conflict-aware fusion and abstention
         → ablation, drift, and unseen-client experiments

RESEARCH/PRODUCT DECISION
         → paper-quality evidence
         → patentability review if novelty survives
         → analyst-facing prototype if performance is useful
```

## Academic roadmap: Practicals 7–10

### Practical 7 — Data wrangling and aggregation

**Technical work**

- Build event-, client-, time-window-, and behavioural-regime views.
- Aggregate counts, unique ports, activity intensity, label proportions, conflict rates, and uncertainty rates.
- Separate descriptive aggregates from model inputs.
- Use pseudonymous client keys in displayed results.
- Preserve links from every aggregate back to its source events and manifest.

**Simple meaning**

Turn millions of individual notes into summaries such as “what happened during this hour?” and “how did this client behave?” without losing the ability to trace the original events.

**Planned outputs**

- `notebooks/practical_07_data_wrangling.ipynb`
- `src/aggregation.py`
- versioned daily, hourly, and client summary sidecars
- aggregation manifest and validation checks

**Completion gate**

Aggregated event totals must reconcile with 2,062,361 source events, and grouping must not expose raw client IP addresses in reports.

### Practical 8 — Exploratory data analysis and visualization

**Technical work**

- Measure class, feature, client, and temporal distributions.
- Analyze the January-to-February change in behaviour.
- Separate ordinary periods, attack-burst periods, and post-burst periods.
- Inspect feature drift with distribution distances rather than relying only on averages.
- Compare event-weighted and client-weighted views so one high-volume client cannot hide the rest of the population.
- Visualize weak-label confidence and evidence conflicts.

**Simple meaning**

Understand how the environment changes over time and prevent one extremely noisy attacker from controlling the entire story.

**Planned outputs**

- `notebooks/practical_08_eda_visualization.ipynb`
- privacy-safe charts and summary tables under `outputs/`
- documented observations, limitations, and hypotheses

**Completion gate**

Every chart must state its population, time period, unit of analysis, and whether uncertain events are included.

### Practical 9 — Classification and trustworthy evaluation

**Technical work**

- Train a simple interpretable baseline first, followed by suitable tree-based models.
- Fit preprocessing and feature selection on training data only.
- Exclude the zero-variance feature using training-fitted logic.
- Use the balancing sidecar's training weights.
- Select thresholds and hyperparameters using January validation only.
- Open the frozen February test once for final evaluation.
- Evaluate both discrimination and calibration.
- Report performance separately for time periods and clients, not only for records.

**Simple meaning**

Start with a model we can understand, compare stronger models fairly, and test them on genuinely later activity.

**Required baselines**

1. Majority-class baseline.
2. Static weak-label rule baseline.
3. Leakage-safe logistic-regression baseline.
4. Leakage-safe tree-based baseline.
5. Rule-reproduction audit using restricted evidence features, reported separately and never presented as the primary result.

**Required metrics**

- precision, recall, and F1 for both supervised classes;
- macro F1 and balanced accuracy;
- Matthews correlation coefficient;
- precision-recall area under the curve;
- false-positive rate and false-negative rate;
- Brier score and calibration error for probabilities;
- risk-coverage performance when the model can abstain;
- per-day and per-client macro results during drift.

Accuracy alone is insufficient because February is approximately 99% attack-labeled.

**Completion gate**

The model must outperform trivial baselines on validation without using restricted label evidence. Test results, failures, and confidence intervals must be reported even if performance is poor.

### Practical 10 — Reusable end-to-end pipeline

**Technical work**

- Convert notebook logic into configuration-driven modules and commands.
- Add schema contracts, version checks, atomic outputs, manifests, and restart-safe execution.
- Add unit, integration, chunk-boundary, leakage, and reproducibility tests.
- Provide a safe sanitized sample and execution instructions.
- Keep raw and generated private data outside GitHub.

**Simple meaning**

Turn the experiment into a repeatable process that another authorized person can run and verify.

**Planned outputs**

- `src/pipeline.py` or a small command-line entry point
- versioned configuration files
- automated tests under `tests/`
- updated README and architecture documentation
- final practical report

**Completion gate**

A clean environment must reproduce verified artifacts from an authorized input using one documented workflow, without silently overwriting mismatched results.

## Proposed research direction

### Working concept

**Temporal Provenance-Aware Evidence Fusion with Abstention (T-PEFA)** is a provisional name for the research direction. The name describes a candidate method; it does not claim novelty or patentability.

The proposed method would combine five elements:

1. **Independent evidence channels:** transparent rules, causal behavioural model, and optional analyst feedback remain distinguishable.
2. **Time-varying reliability:** an evidence source's influence can change when its historical audited performance changes.
3. **Conflict measurement:** opposing signals are measured rather than silently resolved.
4. **Explicit abstention:** high conflict or insufficient support produces “uncertain.”
5. **Provenance-carrying output:** each decision records evidence, reliability versions, model version, and source-event identity.

### Why this direction fits the dataset

The current fixed weak labels rely heavily on scanner user-agent declarations. A malicious client can spoof a browser, and a benign tool can identify itself as a scanner. Meanwhile, behavioural patterns and traffic regimes change sharply over time. A system that treats every evidence source as permanently reliable may therefore become confidently wrong.

The proposed research asks whether reliability can be updated using past audited outcomes while preserving causality and whether conflict-aware abstention improves safety during drift.

## Preliminary mathematical formulation

The formulas below use plain-text blocks so they remain visible in GitHub, VS Code, and Markdown viewers without mathematical-rendering support.

### Symbols

| Symbol | Technical meaning | Simple meaning |
|---|---|---|
| `t` | Current event position in arrival order | The event being examined now |
| `j` | Evidence-source index | Which rule or evidence channel is speaking |
| `e[j,t]` | Evidence direction and strength | Whether source `j` supports attack, benign, or neither |
| `r[j,t]` | Past-only reliability of source `j` | How much source `j` is currently trusted |
| `z[j,t-1]` | Audited correctness of the earlier evidence | Whether the source was right when a trusted reviewer checked it |
| `p[t]` | Calibrated behavioural-model attack probability | How suspicious the ML model finds the event |
| `lambda` | Reliability learning rate | How quickly trust changes after feedback |
| `beta` | Behavioural-model influence | How much influence the ML model receives |
| `epsilon` | Small positive safety value | Prevents division by zero |
| `I(condition)` | 1 when the condition is true, otherwise 0 | A mathematical on/off switch |

### Step 1 — Represent each evidence source

For event `t`, source `j` produces a value from `-1` to `+1`:

```text
-1 <= e[j,t] <= +1

e[j,t] > 0   supports ATTACK
e[j,t] < 0   supports BENIGN
e[j,t] = 0   source j has no opinion / abstains
```

Example: a strong payload signature might return `+1`, browser-like evidence might return `-0.5`, and an unavailable rule returns `0`.

### Step 2 — Maintain past-only reliability

Every evidence source has a reliability between zero and one:

```text
0 <= r[j,t] <= 1
```

When a trusted audit of an earlier event becomes available, reliability may be updated as follows:

```text
r[j,t] = (1 - lambda) * r[j,t-1]
         + lambda * z[j,t-1]
```

Interpretation:

- `r[j,t-1]` is the source's previous reliability;
- `z[j,t-1]` describes whether its earlier evidence agreed with the trusted audit;
- a small `lambda` changes trust slowly;
- a large `lambda` reacts quickly but may be unstable.

Only an audit from an earlier event may affect the current reliability. Future feedback must never rewrite an earlier decision.

If trusted audit feedback is unavailable, reliability is not updated from assumed correctness or majority agreement. This avoids reinforcing errors through circular reasoning.

### Step 3 — Convert the ML probability into a signed signal

The behavioural model returns attack probability `p[t]` between zero and one. Convert it to the same negative-to-positive direction as rule evidence:

```text
model_signal[t] = 2 * p[t] - 1
```

Therefore:

```text
p[t] = 0.00  -> model_signal[t] = -1.00  (strong benign support)
p[t] = 0.50  -> model_signal[t] =  0.00  (neutral)
p[t] = 1.00  -> model_signal[t] = +1.00  (strong attack support)
```

### Step 4 — Fuse rules and behavioural evidence

First calculate the signed support contributed by all rule sources:

```text
rule_support[t] = SUM over j of (r[j,t] * e[j,t])
```

Then calculate the total reliability of sources that actually produced evidence:

```text
active_reliability[t]
    = SUM over j of (r[j,t] * I(e[j,t] != 0))
```

The provisional fused score is:

```text
score[t]
    = (rule_support[t] + beta * model_signal[t])
      / (epsilon + active_reliability[t] + beta)
```

The result is intended to remain near `-1` to `+1`:

- a positive score supports attack;
- a negative score supports benign;
- a score near zero indicates weak or balanced support.

`beta` must be selected using validation data only. It must not be chosen from final test performance.

### Step 5 — Measure evidence conflict

Total evidence strength ignores direction:

```text
total_evidence_strength[t]
    = SUM over j of (r[j,t] * ABS(e[j,t]))
```

Conflict is then estimated by comparing the remaining signed support with total evidence strength:

```text
conflict[t]
    = 1 - ABS(rule_support[t])
          / (epsilon + total_evidence_strength[t])
```

Interpretation:

```text
conflict[t] near 0  -> evidence mostly agrees
conflict[t] near 1  -> strong opposing evidence cancels out
```

No active evidence is handled separately as insufficient evidence rather than being interpreted as meaningful conflict.

### Step 6 — Make a selective decision

The system does not force every event into attack or benign:

```text
IF there is insufficient active evidence:
    decision = UNCERTAIN

ELSE IF score[t] >= attack_threshold
        AND conflict[t] <= maximum_allowed_conflict:
    decision = ATTACK

ELSE IF score[t] <= -benign_threshold
        AND conflict[t] <= maximum_allowed_conflict:
    decision = BENIGN

ELSE:
    decision = UNCERTAIN
```

The attack, benign, and conflict thresholds must be selected from validation data and frozen before final testing.

### Worked example

Suppose two rules and the behavioural model produce:

| Source | Evidence | Reliability | Weighted evidence |
|---|---:|---:|---:|
| Payload rule | `+1.0` | `0.8` | `+0.8` |
| Browser-style rule | `-1.0` | `0.6` | `-0.6` |
| Behavioural model | `p[t] = 0.75` | `beta = 1.0` | `model_signal = +0.5` |

Ignoring the very small `epsilon` only for this illustration:

```text
rule_support = (+0.8) + (-0.6)
             = +0.2

active_reliability = 0.8 + 0.6
                   = 1.4

score = (0.2 + 1.0 * 0.5) / (1.4 + 1.0)
      = 0.7 / 2.4
      = 0.292

conflict = 1 - ABS(0.2) / (0.8 + 0.6)
         = 1 - 0.2 / 1.4
         = 0.857
```

The fused score leans toward attack, but the conflict is very high because two trusted rules disagree. A conflict-aware system may therefore return `UNCERTAIN` and request review instead of issuing an overconfident attack decision.

### Status of the formulation

These formulas are starting hypotheses, not final validated equations. They must be compared with existing evidence-fusion, weak-supervision, online-learning, concept-drift, uncertainty, and selective-classification methods. Each component must also pass ablation and robustness tests before it can be treated as a research contribution.

## Research questions and hypotheses

### Research questions

1. Can past-only behavioural features generalize across future traffic regimes without direct label-rule features?
2. Does time-varying evidence reliability outperform fixed weak-label confidence during drift?
3. Does conflict-aware abstention reduce harmful errors while retaining useful coverage?
4. Do event-weighted results hide poor performance on low-volume clients?
5. Can every alert remain reproducible when rules, reliability, and model versions change?

### Hypotheses to freeze before final experiments

- **H1:** Dynamic past-only reliability improves future macro F1 or precision-recall performance over fixed evidence weights.
- **H2:** Conflict-aware abstention reduces error at matched prediction coverage.
- **H3:** Causal behavioural features generalize better than client identity or full-history aggregates on future and client-disjoint tests.
- **H4:** Client-weighted and event-weighted evaluations differ materially during concentrated attack bursts.
- **H5:** Provenance-carrying decisions can be reconstructed exactly from versioned artifacts.

Hypotheses, primary metrics, and decision thresholds must be written before final test evaluation to reduce result-driven changes.

## Reference-label plan

Weak labels alone cannot prove research performance. A smaller trusted reference set is required.

The sample should be stratified across:

- attack, benign-like, and uncertain weak labels;
- high and low confidence;
- conflicting and non-conflicting evidence;
- ordinary, burst, and post-burst periods;
- frequent and rare clients;
- scanner-only and payload-supported attack evidence.

At least two reviewers should independently label the selected records using a written rubric. Disagreement should be retained and measured, for example with Cohen's kappa, before adjudication. The sample size should be chosen from available expert-review capacity and a statistical power or confidence-interval analysis rather than guessed in advance.

Reference labels must remain separate from weak labels. They may calibrate reliability or evaluate models only according to a frozen protocol.

## Experimental design

### Evaluation views

1. **Frozen future test:** February 2024, unchanged and naturally imbalanced.
2. **Temporal sub-regimes:** ordinary days, 8–9 February burst, and post-burst days, defined before model comparison.
3. **Client-disjoint stress test:** a secondary test in which selected clients do not appear during fitting.
4. **Event-weighted evaluation:** every event contributes equally.
5. **Client-weighted evaluation:** every client contributes equally, limiting domination by a single high-volume source.

The frozen February test remains primary. Secondary tests answer different questions and must not replace an unfavorable primary result.

### Required ablation studies

Each proposed component must be removed one at a time:

- fixed reliability instead of dynamic reliability;
- no conflict term;
- no abstention;
- no confidence normalization;
- no causal activity-decay features;
- one decay scale instead of multiple scales;
- event-only versus event-plus-past behaviour;
- random-row split versus frozen temporal split, shown only as a leakage demonstration;
- event-weighted versus client-weighted evaluation.

An ablation answers: “Did this component actually help?” Without it, a complex method cannot justify its added complexity.

### Robustness tests

- user-agent spoofing or removal;
- missing optional fields;
- changed attack prevalence;
- new clients and previously unseen port behaviour;
- timestamp reversals and delayed arrival;
- concentrated bursts from one client;
- modified weak-label thresholds;
- corrupted or mismatched artifact fingerprints.

## Literature and patent prior-art plan

No formal prior-art conclusion has been reached yet.

The search should cover two different bodies of evidence:

### Academic literature

- weak supervision and label models;
- intrusion detection from web and application logs;
- online and prequential learning;
- concept-drift detection and adaptation;
- uncertainty calibration and selective classification;
- evidence fusion and conflict measurement;
- temporal and entity leakage in security datasets;
- explainable and provenance-aware security analytics.

For every relevant paper, record its problem, assumptions, method, equations, datasets, evaluation split, limitations, and exact difference from the proposed method.

### Patent databases

Search Google Patents, WIPO PATENTSCOPE, Espacenet, and the relevant national patent database using combinations of:

- intrusion detection + evidence fusion;
- dynamic evidence reliability + security events;
- temporal confidence + anomaly detection;
- conflict-aware classification + abstention;
- provenance-aware security alert;
- weak supervision + cybersecurity;
- online reliability weighting + intrusion detection.

Record publication number, priority date, independent claims, diagrams, legal status, and overlapping elements. Similar titles are less important than overlapping claim elements.

### Novelty decision gate

Proceed toward a patent draft only if the search supports a specific mechanism that is:

1. new compared with earlier publications;
2. not an obvious combination of known methods;
3. technically useful and experimentally supported;
4. described precisely enough to reproduce;
5. broader than one dataset but narrow enough to define clearly.

A patent professional should review the result before filing. This project plan is technical guidance, not legal advice.

## Candidate contribution versus existing foundation

| Component | Current status | Research role |
|---|---|---|
| Provenance-preserving parser | Implemented | Reproducible data foundation, not assumed novel. |
| Confidence-aware weak labels | Implemented with fixed policy | Baseline and source of uncertainty. |
| Past-only causal features | Implemented | Leakage-safe behavioural input. |
| Calendar split and training weights | Implemented | Defensible evaluation foundation. |
| Trusted audited subset | Not implemented | Needed for reliable evaluation and reliability updates. |
| Time-varying evidence reliability | Proposed | Candidate research component. |
| Formal conflict score | Proposed | Candidate research component. |
| Selective prediction/abstention | Proposed | Candidate safety component. |
| Provenance-carrying fused alert | Proposed | Candidate system-level contribution. |
| Patentable claim | Not established | Requires prior art, experiments, and professional review. |

## Product direction

The first product should be an analyst-assistance prototype, not an autonomous blocking system.

### Suggested progression

1. **Research notebook:** prove the method and limitations.
2. **Reproducible command-line pipeline:** process an authorized log file and create verified artifacts.
3. **Offline analyst report:** rank suspicious events and show evidence, conflict, confidence, and source identity.
4. **Review interface:** allow analysts to confirm, reject, or mark events uncertain; preserve reviewer provenance.
5. **Near-real-time service:** maintain causal client state and score new events as they arrive.
6. **Controlled response integration:** only after false-positive risk, security, latency, and governance are validated.

### Intended consumers

- academic evaluators and students;
- cybersecurity researchers;
- SOC analysts and incident responders;
- website or application operators;
- ML engineers building auditable security systems.

### Useful outputs for an analyst

- risk score and prediction;
- abstention or review-needed status;
- contributing and conflicting evidence;
- behavioural change from the client's past;
- model, rule, and reliability versions;
- event and record identifiers for investigation.

## Risks and controls

| Risk | Planned control |
|---|---|
| Weak labels are wrong | Create audited reference labels and report label uncertainty. |
| User agents are spoofed | Keep behavioural evidence independent and run spoofing ablations. |
| One attacker dominates records | Report client-weighted and time-regime metrics. |
| Test results influence redesign | Freeze hypotheses and open the final test only at the defined gate. |
| Model copies label rules | Enforce the feature contract and keep a separate leakage audit baseline. |
| Drift breaks calibration | Measure calibration by time period and test dynamic reliability. |
| Raw IPs or logs are exposed | Keep data ignored/private and pseudonymize displayed identities. |
| Patent rights are weakened | Keep the repository private and maintain a disclosure log until reviewed. |
| Complex method adds no value | Require baseline comparisons and component ablations. |
| Automated action harms users | Keep a human reviewer in the loop until operational safety is demonstrated. |

## Evidence required before making claims

Do not claim that the system is accurate, production-ready, superior, novel, or patentable until the corresponding evidence exists.

Before a research claim:

- trusted reference labels exist;
- baselines use the same splits and information;
- uncertainty or confidence intervals are reported;
- ablations isolate each contribution;
- temporal and client-level results are included;
- negative and failed results are documented.

Before a product claim:

- operational latency and resource use are measured;
- security and privacy review is complete;
- model drift and failure monitoring exist;
- analyst workflow and appeal/correction mechanisms exist;
- autonomous blocking remains disabled unless separately validated.

Before a patent claim:

- prior-art searches are documented;
- the candidate mechanism is precisely defined;
- inventorship and disclosure history are recorded;
- experimental utility is demonstrated;
- a qualified patent professional has reviewed it.

## Immediate next sequence

1. Complete Practical 7 with provenance-preserving event, client, and time-window aggregates.
2. Complete Practical 8 and define temporal regimes before viewing model results.
3. Write and freeze the Practical 9 evaluation protocol.
4. Train interpretable and tree-based leakage-safe baselines.
5. Evaluate on validation; freeze the chosen model and threshold.
6. Evaluate once on the February future test and document failure modes.
7. Build the reusable Practical 10 pipeline and automated checks.
8. Design the audited reference-label study with the professor or a security-domain reviewer.
9. Conduct formal literature and patent prior-art searches.
10. Decide whether T-PEFA remains a defensible contribution; revise or reject it based on evidence.
11. Run proposed-method, ablation, robustness, and calibration experiments.
12. Choose the appropriate outcome: academic report, research paper, patent consultation, analyst prototype, or a combination.

## Decision record to maintain

For every major change, record:

- date and author;
- question or problem;
- evidence inspected;
- alternatives considered;
- chosen decision and reason;
- affected versions and artifacts;
- whether validation or test information influenced the decision.

This decision record is essential for research credibility and for reconstructing the development history of a possible invention.
