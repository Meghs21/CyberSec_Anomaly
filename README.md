# Honeywell Cyber Security Operations Console (FastAPI + React)

> **Official HirePro Hackathon Specification Compliant**: Production-grade, real-time Security Operations Web Application for Mixed IT + OT Enterprise Behavioral Anomaly Detection.

---

## Executive Summary & Official Requirement Compliance

This project implements an AI/ML behavioral anomaly detection system and navigable SOC console compliant with every requirement of the official HirePro assessment spec:

- **Official 11-Field Schema**: `entity_id`, `entity_type`, `timestamp`, `source_ip`, `geo_location`, `resource_accessed`, `auth_method`, `session_duration`, `command_sequence`, `device_fingerprint`, `label`.
- **Extreme Class Imbalance**: Injects official attack categories at **2.56% anomaly rate** (strictly within 0.5–3.0%).
- **Structural Label Leakage Prevention**: Strips `label` at pipeline entry before inference; enforced with assertions.
- **Sequence-Aware Model (Deliverable #3)**: N-gram Markov transition probability model with Laplace smoothing.
- **Cold-Start & Concept Drift**: Cohort priors (`user`, `service_account`, `edge_device`) + EWMA anti-poisoning updates.
- **Top-1% Analyst Alert Budget Metric**: Evaluated and displayed on console (`100% Precision@Top1%`, `0% FPR@Top1%`).
- **Written Technical Report**: Full deliverable documented in [`REPORT.md`](REPORT.md).

---

## Quickstart & Run Commands

### 1. Installation & Automated Tests

```bash
cd honeywell_cyber_anomaly_detection
pip install -r requirements.txt

# Run automated test suite (11 acceptance gates)
python tests/test_pipeline.py
```

### 2. Generate Dataset (11 Schema Fields)

```bash
python scripts/generate_dataset.py
```

### 3. Start Web Application (< 2s Cold Boot)

```bash
python start_server.py
```

Open **`http://localhost:8000`** in your browser.

> **Optional Rebuild**: `python start_server.py --rebuild`

---

## Live Pitch Scripted Demo Flow

1. Open `http://localhost:8000` on screen.
2. Click **🚨 Trigger Attack Burst** on Overview (or run `python scripts/trigger_attack.py` in terminal).
3. Open **Alerts Triage Queue**: inspect **lateral_movement** and **impossible_travel** alerts with evidence-based explainability strings.
4. Demonstrate analyst actions: click **Acknowledge**, **Escalate**, or add an investigation note.
5. Open **Entity Investigation**: inspect `USR_012` and show the **Cohort Baseline** vs **Personal Baseline** strategy indicator.
6. Open **Analytics**: show judges the prominent **TOP 1% ANALYST ALERT BUDGET** card (`100.0% Precision@Top1%`, `0.0% FPR@Top1%`).
