# Technical Evaluation Report: AI-Powered Behavioral Anomaly Detection

**Honeywell Hackathon / Assessment Official Specification Deliverable #7**

---

## Executive Summary & Official Requirement Mapping

This technical report documents the design, mathematical formulation, evaluation methodology, and measured benchmark performance of the **Honeywell AI-Powered Behavioral Anomaly Detection System**.

The system strictly complies with every item of the official HirePro assessment problem statement.

### Official Requirement Mapping Table

| Official Requirement | Implementation File / Module | Compliance Status |
| :--- | :--- | :--- |
| **Synthetic Generator** | `data_gen/generator.py` | Complete (11 official fields, 0.5–3.0% anomaly rate) |
| **Extreme Class Imbalance** | `data_gen/generator.py` | Complete (2.56% malicious anomaly injection rate) |
| **Baseline Profiler** | `detection/baseline.py` | Complete (Statistical baselines + Isolation Forest) |
| **Sequence-Aware Model** | `detection/sequence_model.py` | Complete (N-gram Markov transition probability model) |
| **Attack Detection** | `detection/risk_fusion.py` | Complete (Fuses baseline, N-gram sequence, & rules) |
| **Attack Classification** | `detection/classifier.py` | Complete (Stage 2: 6 malicious categories + insider_drift) |
| **Explainability Layer** | `detection/explainer.py` | Complete (Evidence-based SHAP/Z-score feature attributions) |
| **Cold Start Strategy** | `detection/cold_start.py` | Complete (Cohort priors + linear history blending) |
| **Concept Drift Strategy** | `detection/drift.py` | Complete (EWMA rolling update + anti-poisoning filter) |
| **Risk Score Fusion** | `detection/risk_fusion.py` | Complete (Continuous risk score in [0, 100]) |
| **Top-1% Alert Budget** | `backend/store.py`, `Analytics.jsx` | Complete (Top 1% budget Precision, Recall, FPR metrics) |
| **Analyst Dashboard** | `frontend/src/` (React Vite) | Complete (Navigable 6-view industrial SOC console) |
| **Entity History View** | `EntityInvestigate.jsx` | Complete (Visual baseline vs activity overlay + strategy badge) |
| **Technical Report** | `REPORT.md` | Complete (This document) |

---

## 1. Official Data Schema (11 Fields)

The synthetic data generator produces log records matching the exact 11-field official specification:

1. `entity_id`: Unique identifier for user or device (`USR_001`, `DEV_042`).
2. `entity_type`: Category of entity (`user`, `service_account`, `edge_device`).
3. `timestamp`: ISO 8601 connection time (`YYYY-MM-DD HH:MM:SS`).
4. `source_ip`: Originating IPv4 address.
5. `geo_location`: Geographic location string and lat/lon coordinates.
6. `resource_accessed`: Target endpoint, cloud app, BMS controller, or SCADA HMI.
7. `auth_method`: Authentication protocol (`password`, `token`, `certificate`, `biometric`).
8. `session_duration`: Active connection duration in seconds.
9. `command_sequence`: Ordered sequence of session actions (`login -> vpn_connect -> pull`).
10. `device_fingerprint`: OS version, MAC address, and protocol details.
11. `label`: Ground-truth tag (`normal`, `brute_force`, `impossible_travel`, `credential_stuffing`, `lateral_movement`, `device_spoofing`, `low_and_slow_exfiltration`, `insider_drift`).

---

## 2. Prevention of Ground-Truth Label Leakage

To guarantee rigorous evaluation integrity, ground-truth `label` values are **structurally eliminated** before log records enter the inference pipeline:

```text
Labeled Dataset (CSV/JSONL)
        │
        ├── Ground-Truth Labels ───────────────► Evaluation Store ONLY
        │
        ▼
   [drop("label")]
        │
        ▼
Inference Detection Pipeline (baseline, sequence_model, rule_engine, risk_fusion, classifier, explainer)
```

Every inference component (`baseline.py`, `sequence_model.py`, `rule_engine.py`, `risk_fusion.py`, `classifier.py`, `explainer.py`, `cold_start.py`, `drift.py`) contains a hard assertion:
`assert "label" not in event, "LABEL LEAKAGE DETECTED"`

Failing to strip `label` triggers an immediate runtime crash.

---

## 3. Behavior Taxonomy & Class Imbalance

### Synthetic Generation Parameters:
- **Total Generated Sessions**: 1,526
- **Normal Sessions**: 1,481 (97.05%)
- **Non-Malicious Insider Drift Edge Cases**: 6 (0.39%)
- **Malicious Attack Sessions**: 39 (**2.56% Anomaly Rate**)

### Official Taxonomy Categories:
1. `brute_force`: Rapid failed authentication attempts from a single source.
2. `impossible_travel`: Physical velocity infeasibility (> 550 mph between distant geo-locations).
3. `credential_stuffing`: Password spraying (many `entity_id`s, single `source_ip`, high failure rate).
4. `lateral_movement`: Compromised entity accessing unusual resource sequences or crossing from IT to OT controllers.
5. `device_spoofing`: Device identity appearing with mismatched OS/MAC fingerprint.
6. `low_and_slow_exfiltration`: Gradual small off-hours resource access over extended days/weeks.
7. `insider_drift` (**Non-Malicious Edge Case**): Legitimate entity slowly expanding access footprint over time. Scored as low-risk to avoid false alarms.

---

## 4. Machine Learning & Detection Architecture

### A. Cold-Start Strategy (`detection/cold_start.py`)
For entities with fewer than $N=10$ historical events:
- Falls back to `entity_type` **cohort baselines** (`user`, `service_account`, `edge_device`).
- Linear blending formulation as interaction history $c$ accumulates:
  $$\text{weight} = \min\left(1.0, \frac{c}{N}\right)$$
  $$\text{Baseline}_{\text{effective}} = (1 - \text{weight}) \cdot \text{Baseline}_{\text{cohort}} + \text{weight} \cdot \text{Baseline}_{\text{personal}}$$

### B. Concept-Drift Strategy (`detection/drift.py`)
- Updates entity baselines using an **Exponentially Weighted Moving Average (EWMA)** ($\alpha = 0.1$).
- **Anti-Poisoning Filter**: Only trusted low-risk observations ($\text{risk\_score} < 45.0$) update the profile. High-risk attack events are ignored to prevent baseline poisoning.

### C. Sequence-Aware Model (`detection/sequence_model.py` - Deliverable #3)
- Models `resource_accessed` and `command_sequence` transitions using an N-gram Markov transition probability model with Laplace additive smoothing ($\alpha = 1.0$) and floor probability ($1 \times 10^{-5}$):
  $$\text{anomaly\_raw} = \text{mean}\left(-\log P(\text{state}_{i+1} \mid \text{state}_i)\right)$$
- Calibrated to $[0.0, 1.0]$ scale ($0 = \text{expected}$, $1 = \text{unusual}$).

### D. Stage 1 Detection vs Stage 2 Classification Separation
- **Detection (Stage 1)**: Evaluates whether an event is anomalous ($\text{risk\_score} \in [0, 100]$).
- **Classification (Stage 2)**: Classifies flagged anomalies into exact official categories (`brute_force`, `impossible_travel`, `credential_stuffing`, `lateral_movement`, `device_spoofing`, `low_and_slow_exfiltration`, `insider_drift`).

---

## 5. Measured Quantitative Benchmark Results

### Overall Performance Metrics:
- **Total Log Events Evaluated**: 1,526
- **True Positives (TP)**: 18
- **False Positives (FP)**: 1
- **True Negatives (TN)**: 1,486
- **False Negatives (FN)**: 21
- **Overall Precision**: **94.7%**
- **Overall Recall**: **46.2%**
- **F1-Score**: **0.6207**

### Evaluation Criterion #3: Top-1% Analyst Alert Budget Metrics:
- **Analyst Alert Budget ($K = \lceil 0.01 \times 1,526 \rceil$)**: **16 Sessions**
- **Precision @ Top 1%**: **100.0%** (16 out of 16 top-ranked alerts are true malicious attacks)
- **Recall @ Top 1%**: **41.0%**
- **False Positive Rate (FPR) @ Top 1%**: **0.0%**

---

## 6. Known Real-World Limitations

1. **Synthetic Feature Independence**: Synthetic generators approximate human behavior with Gaussian/von Mises distributions; real enterprise access logs contain complex organizational dependencies.
2. **N-Gram Transition Memory**: The primary sequence model uses bigram/trigram context; complex multi-week stateful dependency chains benefit from full recurrent state representations.
3. **Static Role Grouping**: Cohort priors currently group entities by `entity_type`; expanding to organizational unit hierarchy would further refine cold-start accuracy.

---

## 7. How to Run the Demonstration

```bash
# 1. Navigate to project root
cd C:\Users\meghna\.gemini\antigravity\scratch\honeywell_cyber_anomaly_detection

# 2. Run automated test suite (11 acceptance gates)
python tests/test_pipeline.py

# 3. Launch Web Application (< 2s cold boot)
python start_server.py
```
Open **`http://localhost:8000`** in your browser.
