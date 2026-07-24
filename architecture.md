# System Architecture & Technical Design

## Honeywell AI-Powered Behavioral Anomaly Detection System

This document details the architectural design, machine learning methodology, and domain decisions behind the **Honeywell AI-Powered Behavioral Anomaly Detection System** for mixed IT + OT enterprise environments.

---

## High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph Data Layer & Synthetic Environment
        A[Multi-Entity Log Generator] -->|Normal Traffic & Injected Scenarios| B[(Synthetic Stream CSV/JSONL)]
    end

    subgraph Hybrid Detection Pipeline
        B --> C[Entity Baseline Profiler\nRolling EWMA & Cold-Start Priors]
        B --> D[Deterministic Rule Assist\nImpossible Travel & Brute Force]
        B --> E[Unsupervised ML Engine\nIsolation Forest & Feature Z-Scores]
        
        C -->|Entity Stats & Z-Scores| E
        D -->|Hard Overrides & Flags| F[Continuous Risk Fusion Engine\nDynamic Smart Thresholding]
        E -->|Raw Anomaly Scores| F
        
        F -->|Risk Score 0-100| G[Taxonomy & Attack Classifier]
        F -->|Risk Score 0-100| H[SHAP/Z-Score Explainability Engine]
    end

    subgraph Analyst Triage Dashboard (Streamlit)
        G -->|Point / Contextual / Collective| I[Analyst Dashboard]
        H -->|Human-Readable Reasoning| I
        F -->|High Severity IT-OT Alerts| I
        C -->|Entity Baseline Visualizer| I
    end
```

---

## Honeywell Domain Framing: IT + OT Crossover Security

Unlike generic enterprise security tools that focus solely on corporate email or laptop logins, Honeywell's core business spans industrial automation, building management systems (BMS), and industrial cybersecurity (e.g., Honeywell Forge, Cyber Insights).

Our synthetic environment models a realistic **mixed IT + OT enterprise**:
- **IT Domain Assets**: Laptops, Corporate VPN, Active Directory, Workday, GitHub, AWS Cloud.
- **OT Domain Assets**: Honeywell Forge Gateway, BMS HVAC Controllers, SCADA HMIs, Building Access Control Gateways, Industrial PLCs.

### High-Severity IT-to-OT Crossover Detection
A critical attack vector in industrial cybersecurity occurs when an attacker compromises a standard IT corporate account (e.g., Finance or HR) and attempts lateral movement into OT control networks (e.g., accessing a BMS HVAC controller or SCADA workstation). Our hybrid pipeline explicitly flags IT-to-OT crossovers as high-severity alerts.

---

## Machine Learning & Anomaly Taxonomy Design

### 1. Semi-Supervised Anomaly Scoring
To defend against zero-day threats and signature-less attacks, the machine learning engine is framed as **semi-supervised**:
- **Training Phase**: The Isolation Forest and entity baseline statistics are trained **strictly on normal behavioral traffic**. No attack labels are seen during training.
- **Detection Phase**: Incoming events are scored based on their mathematical deviation from the learned normal distribution.

### 2. Anomaly Taxonomy Mapping
Every flagged event is classified into one of three core anomaly taxonomy categories:
- **Point Anomalies**: Single events that are inherently abnormal (e.g., rapid failed login bursts during brute-force attacks).
- **Contextual Anomalies**: Events normal in isolation but abnormal given context (e.g., off-hours 4.8 GB exfiltration or unrecognized Linux devices connecting to OT controllers).
- **Collective Anomalies**: Sequences of events that are suspicious together (e.g., impossible travel across 6,000 miles in 12 minutes, or dormant account reactivation across IT and OT systems).

---

## Solutions to Key ML Challenges

### 1. Cold-Start Problem (New Users/Devices)
- **Challenge**: New entities have no historical log data to build a baseline.
- **Solution**: When an entity has `< 10` historical events, the system falls back to **global domain priors** (standard working hour means and transfer sizes for IT vs OT roles) and widens the alert threshold (+10 points) to avoid false positives until the entity profile matures.

### 2. Concept Drift (Evolving Normal Behavior)
- **Challenge**: User behavior naturally changes over time (e.g., shift schedule changes, new project assignments).
- **Solution**: Entity baselines update using an **Exponentially Weighted Moving Average (EWMA)** with a decay factor ($\alpha = 0.1$). Older behaviors decay while recent normal interactions dynamically update the baseline mean and variance.

### 3. Class Imbalance (Rare Attack Events)
- **Challenge**: Attacks constitute `< 5%` of total log volume; models risk collapsing to "everything is normal."
- **Solution**: Isolation Forest contamination parameter is set to $0.04$, and risk scores are normalized to a $0-100$ continuous scale with dynamic thresholding to maintain high recall on rare events without inflating false positives.

---

## Explainability Engine (SHAP & Z-Score Feature Attribution)

For every alert raised on the dashboard, the explainability engine outputs clear bulleted text explaining *why* the score was elevated:
- `⚡ IMPOSSIBLE TRAVEL: Traveled 6,780 miles at calculated speed of 33,900 mph`
- `⚠️ IT-OT CROSSOVER: IT Role (Finance_Manager) accessed critical OT Asset 'Honeywell_Forge_Gateway'`
- `🕒 UNUSUAL TIME: Access at 02:30 AM (historical avg: 09:15 AM ± 1.2 hrs)`
- `📦 HIGH DATA VOLUME: 4,800 MB transferred (historical entity baseline: 45.0 MB)`
