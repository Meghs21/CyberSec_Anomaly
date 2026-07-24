# Honeywell Cyber Security Operations Console (FastAPI + React)

> **Honeywell Hackathon Project**: Production-grade, real-time Security Operations Web Application for Mixed IT + OT Enterprise Behavioral Anomaly Detection.

---

## Executive Summary & Application Overview

This project provides a complete, interactive **Security Operations Web Console** built with a **FastAPI backend** and a **React + Vite single-page frontend**, wrapped around a hybrid semi-supervised machine learning detection engine.

### Key Capabilities:
- **Navigable Industrial SOC Console**: 6 active views (Overview, Live Feed, Alerts Triage Queue, Entity Investigation, Analytics, Settings).
- **Stateful Analyst Workflow**: Analysts can **Acknowledge**, **Mark False Positives**, **Escalate**, and **Add Investigation Notes** with real-time state persistence.
- **Real-Time WebSocket Streaming**: `/api/events/stream` streams live access events directly to the console.
- **Honeywell Domain Relevance**: Specifically targets mixed **IT + OT environments** (laptops, VPN alongside Honeywell Forge, BMS HVAC controllers, SCADA HMIs).
- **Fast Cold Boot (< 2s)**: Single deployable Python script (`start_server.py`) serves pre-built static React assets instantly.

---

## Quickstart & Run Instructions

### 1. Installation

Ensure Python 3.9+ and Node.js 18+ are installed.

```bash
cd honeywell_cyber_anomaly_detection
pip install -r requirements.txt
```

### 2. Start Web Application (Single Command)

Run the unified server script:

```bash
python start_server.py
```

Open `http://localhost:8000` in your browser.

> **Optional Rebuild**: To rebuild React frontend assets prior to starting:
> `python start_server.py --rebuild`

---

## Live Pitch Scripted Demo Flow

1. Open `http://localhost:8000` on screen.
2. Click **🚨 Trigger Attack Burst** on the Overview page (or run `python scripts/trigger_attack.py` in a separate terminal).
3. Navigate to **Alerts Triage Queue**: show the newly flagged **IT-OT Crossover** alert on **Honeywell Forge Gateway**.
4. Open the Alert Drawer: inspect the **Explainability Attribution** string and raw metadata.
5. Demonstrate stateful analyst actions: click **Acknowledge** or **Escalate**, add an investigation note, and show status updating live.
6. Navigate to **Entity Investigation**: search for `USR_012` to visually compare baseline login hours against the anomalous attack burst.
7. Navigate to **Analytics**: show judges the quantitative **Precision (70-88%)** and **Recall (92%)** performance breakdown across all 6 attack scenario types.

---

## Judge Q&A Defense Guide

### Q1: "How do you detect zero-day attacks without signature labels?"
> **Answer**: The detection engine is **semi-supervised**. Trained strictly on normal entity behavior using Isolation Forests and Z-score deviation metrics, any novel attack causes multi-dimensional deviation from normal baseline, triggering elevated risk scores without needing attack labels.

### Q2: "How do you handle cold-start and concept drift?"
> **Answer**: New entities (< 10 logs) fall back to **global role domain priors** with a +10 point threshold padding to prevent false alerts. For concept drift, baselines update using **Exponentially Weighted Moving Averages (EWMA)**, allowing routine habit shifts to adapt smoothly while isolating sudden attack spikes.

### Q3: "Why is IT + OT crossover significant for Honeywell?"
> **Answer**: Honeywell is a market leader in building management and industrial OT cybersecurity (Honeywell Forge). Generic security tools miss OT controllers. Our system explicitly flags **IT-to-OT lateral movement crossover**, catching compromised corporate accounts before they can tamper with critical building/plant automation controllers.
