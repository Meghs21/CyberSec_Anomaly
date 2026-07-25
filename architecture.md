# System Architecture & Technical Design

## Honeywell AI-Powered Cyber Operations Console (FastAPI + React)

This document details the architectural design, machine learning methodology, sequence modeling, and serving layer of the **Honeywell Cyber Operations Web Application** for mixed IT + OT enterprise environments.

---

## High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph Data Layer & Synthetic Engine
        A[Multi-Entity IT+OT Log Generator\n0.5-3.0% Anomaly Rate] -->|Official 11-Field Schema| B[(Synthetic Log Store CSV/JSONL)]
    end

    subgraph Hybrid Detection Pipeline (Python Core Library)
        B -->|Strip Ground-Truth Label| C[Entity Baseline Profiler\nCold-Start Cohorts & EWMA Drift]
        B -->|Strip Ground-Truth Label| D[Deterministic Rule Assist\nGeo-Velocity & Brute Force Rules]
        B -->|Strip Ground-Truth Label| E[Unsupervised ML Engine\nIsolation Forest & Feature Z-Scores]
        B -->|Strip Ground-Truth Label| F[Sequence-Aware Model\nN-Gram Markov Transition Probabilities]
        
        C -->|Cohort + Personal Stats| G[Continuous Risk Fusion Engine\nDynamic Thresholding & Score Fusion]
        D -->|Hard Overrides & Flags| G
        E -->|Raw Anomaly Scores| G
        F -->|Sequence Anomaly Score| G
        
        G -->|Stage 1: Is Weird?| H[Taxonomy & Attack Classifier\nStage 2: What Category?]
        G -->|Stage 1: Is Weird?| I[SHAP/Z-Score Explainability Engine]
    end

    subgraph Evaluation & Serving Layer (FastAPI)
        H --> J[FastAPI Application Server]
        I --> J
        J --> K[Top-1% Analyst Alert Budget Metrics\nPrecision@Top1%, Recall@Top1%, FPR@Top1%]
        J --> L[WebSocket Server\n/api/events/stream]
        J --> M[REST API Layer]
    end

    subgraph Industrial SOC Frontend (React Single-Page App)
        L -->|Real-Time Event Stream| N[React 18 Console]
        M <-->|Stateful Analyst Actions| N
        
        subgraph Navigable Views
            N --> O[1. Overview Dashboard & Alert Sparkline]
            N --> P[2. Live Event Feed WebSocket Table]
            N --> Q[3. Alerts & Triage Queue\nAcknowledge / FP / Escalate / Notes]
            N --> R[4. Entity Investigation & Cold-Start Badges]
            N --> S[5. Analytics & Top-1% Alert Budget Card]
            N --> T[6. Model Tuning & Dynamic Thresholds]
        end
    end
```

---

## Key Pipeline Principles

1. **Stage 1 Detection vs Stage 2 Classification**:
   - **Detection**: Answers *"Is this behavior anomalous?"* ($\text{risk\_score} \in [0, 100]$).
   - **Classification**: Answers *"If anomalous, what official category does it resemble?"* (`brute_force`, `impossible_travel`, `credential_stuffing`, `lateral_movement`, `device_spoofing`, `low_and_slow_exfiltration`, `insider_drift`).

2. **Structural Label Leakage Prevention**:
   - `label` is ground-truth and is stripped at the pipeline entry point before passing into inference modules.

3. **Cold-Start & Concept Drift**:
   - `ColdStartManager` uses cohort baselines (`user`, `service_account`, `edge_device`) for entities with $< 10$ events.
   - `ConceptDriftAdapter` uses EWMA updates with anti-poisoning filtering (only trusted low-risk observations update baselines).
