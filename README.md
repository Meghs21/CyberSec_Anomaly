# AI-Powered Behavioral Anomaly Detection for Cybersecurity (Honeywell Hackathon)

> **Honeywell Hackathon Project**: Real-Time Signature-Less Behavioral Anomaly Detection System for Mixed IT + OT Enterprise Environments.

---

## Executive Summary & Hackathon Pitch

Traditional cybersecurity tools rely on signature-based detection — matching known attack hashes and patterns. This leaves industrial and corporate networks vulnerable to **novel zero-day attacks, insider threats, credential misuse, and lateral movement**.

This system builds an **AI/ML-based behavioral anomaly detection engine** that learns normal behavior for every user and device across a mixed **IT + OT (Operational Technology)** enterprise — regular employee endpoints (laptops, VPN, cloud apps) alongside industrial building systems (Honeywell Forge Gateway, BMS controllers, HVAC panels, SCADA workstations).

### Key Differentiators for Honeywell:
1. **Domain Relevance**: Designed specifically for Honeywell's core business in building management, industrial automation, and OT cybersecurity (Honeywell Forge / Cyber Insights).
2. **IT-to-OT Crossover Alerts**: Explicitly detects and visually flags high-severity lateral movement when corporate IT accounts attempt unauthorized access to critical OT controllers.
3. **Semi-Supervised ML & Zero-Day Defense**: Trained strictly on normal traffic without needing attack labels.
4. **Human-Readable Explainability**: Every alert includes clear, bulleted reasons (e.g. impossible travel speed calculations, Z-score hour deviations, device mismatches).

---

## Injected Attack Scenario Taxonomy

The synthetic dataset includes realistic ground-truth attack scenarios across all three core anomaly taxonomy categories:

| Taxonomy Category | Attack Scenario | Description |
| :--- | :--- | :--- |
| **Point Anomaly** | **Rapid Brute Force** | Spike of 8+ failed login attempts in seconds followed by success. |
| **Contextual Anomaly** | **Off-Hours Exfiltration** | Endpoint uploading 4.8 GB payload at 2:30 AM to external IP. |
| **Contextual Anomaly** | **Device Mismatch OT** | Unknown Linux device connecting to critical BMS HVAC controller. |
| **Collective Anomaly** | **Impossible Travel** | Account authenticates from NY, then 12 mins later from Singapore (33,900 mph). |
| **Collective Anomaly** | **Dormant Reactivation** | Inactive admin account (90+ days silent) hopping across Active Directory & BMS. |
| **Collective Anomaly** | **IT-OT Crossover** | Finance/HR account initiating unauthorized SSH access to Honeywell Forge Gateway. |

---

## Quickstart & Execution Guide

### 1. Prerequisites & Installation

Ensure Python 3.9+ is installed. Clone/download the codebase and install dependencies:

```bash
cd honeywell_cyber_anomaly_detection
pip install -r requirements.txt
```

### 2. Generate Synthetic Dataset

Pre-render synthetic access logs representing 60 users over 14 days with balanced attack scenario injections:

```bash
python scripts/generate_dataset.py
```

### 3. Launch Analyst Dashboard

Launch the interactive Streamlit dashboard:

```bash
streamlit run dashboard/app.py
```

Open `http://localhost:8501` in your browser.

---

## Live Pitch Scripted Demo Instructions

During your presentation to hackathon judges, you can trigger a live attack burst in real time to demonstrate how the dashboard immediately catches high-severity threats:

1. Keep the Streamlit dashboard open on screen.
2. In a separate terminal, run the scripted attack trigger:
   ```bash
   python scripts/trigger_attack.py
   ```
3. Or click the **🚨 Trigger Attack Scenario** button directly on the dashboard sidebar!
4. The dashboard reloads and immediately displays glowing crimson **IT-OT Crossover** and **Impossible Travel** alerts with complete explainability attribution.

---

## Judge Q&A Defense Guide

### Q1: "How do you detect attacks you've never seen labeled before?"
> **Answer**: Our model is **semi-supervised**. During baseline profiling, it learns the mathematical probability distribution of normal behavior (login hours, locations, devices, transfer sizes) per entity using Isolation Forests and z-score metrics. When an attack occurs, it causes multi-dimensional deviation from normal behavior, raising the risk score without needing predefined signatures or prior attack labels.

### Q2: "How do you handle cold-start for new users and concept drift as behavior changes?"
> **Answer**: For **cold-start**, entities with fewer than 10 events fall back to global domain priors (role-level baseline standards) with a slightly wider alert threshold. For **concept drift**, entity profiles update using an Exponentially Weighted Moving Average (EWMA), allowing normal shift changes or routine habit changes to dynamically update the baseline while isolating sudden anomalous spikes.

### Q3: "Why is the IT + OT mixed environment significant for Honeywell?"
> **Answer**: Honeywell operates at the intersection of building management, SCADA, and OT cybersecurity (Honeywell Forge). Traditional enterprise security tools ignore OT controllers, while OT monitoring tools lack IT identity context. Our system bridges both, specifically identifying IT-to-OT lateral movement crossover, which is one of the highest-severity threat vectors in modern industrial plants and smart buildings.
