# System Architecture & Technical Design

## Honeywell AI-Powered Cyber Operations Console (FastAPI + React)

This document details the architectural design, machine learning methodology, and serving layer of the **Honeywell Cyber Operations Web Application** for mixed IT + OT enterprise environments.

---

## High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph Data Layer & Synthetic Engine
        A[Multi-Entity IT+OT Log Generator] -->|Normal Traffic & Injected Scenarios| B[(Synthetic Log Store CSV/JSONL)]
    end

    subgraph Hybrid Detection Pipeline (Python Core Library)
        B --> C[Entity Baseline Profiler\nRolling EWMA & Cold-Start Priors]
        B --> D[Deterministic Rule Assist\nImpossible Travel & Brute Force]
        B --> E[Unsupervised ML Engine\nIsolation Forest & Feature Z-Scores]
        
        C -->|Entity Stats & Z-Scores| E
        D -->|Hard Overrides & Flags| F[Continuous Risk Fusion Engine\nDynamic Smart Thresholding]
        E -->|Raw Anomaly Scores| F
        
        F -->|Risk Score 0-100| G[Taxonomy & Attack Classifier]
        F -->|Risk Score 0-100| H[SHAP/Z-Score Explainability Engine]
    end

    subgraph Backend Serving Layer (FastAPI)
        G --> I[FastAPI App Engine]
        H --> I
        I --> J[(Alert State & Action Store)]
        I --> K[WebSocket Server\n/api/events/stream]
        I --> L[REST APIs\nAlerts, Entities, Metrics, Settings]
    end

    subgraph Industrial SOC Frontend (React Single-Page App)
        K -->|Real-Time Event Stream| M[React 18 Console]
        L <-->|Stateful Analyst Actions| M
        
        subgraph Navigable Views
            M --> N[1. Overview Dashboard & Sparkline]
            M --> O[2. Live Event Feed]
            M --> P[3. Alerts & Triage Queue\nAcknowledge / FP / Escalate / Notes]
            M --> Q[4. Entity Investigation & Baselines]
            M --> R[5. Analytics & Scenario Breakdown]
            M --> S[6. Model Tuning & Dynamic Thresholds]
        end
    end
```

---

## Serving & State Management Architecture

1. **FastAPI Serving Engine (`backend/`)**:
   - Wraps the detection pipeline and exposes asynchronous REST endpoints alongside a WebSocket streaming channel.
   - Serves static pre-built React production bundle (`frontend/dist`) directly at `http://localhost:8000`.

2. **Real-Time WebSocket Event Stream (`/api/events/stream`)**:
   - Emits access log events in real time to connected analyst web clients without requiring HTTP polling.

3. **Stateful Analyst Triage Store (`backend/store.py`)**:
   - Tracks analyst triage decisions (**ACKNOWLEDGED**, **FALSE_POSITIVE**, **ESCALATED**) and timestamped investigation notes, persisting state immediately across UI interactions.

---

## Machine Learning & Honeywell Domain Rationale

- **Semi-Supervised Anomaly Scoring**: Isolation Forest models trained strictly on normal traffic distributions enable signature-less zero-day threat detection.
- **Cold-Start & Concept Drift**: Role domain priors handle cold-start entities (< 10 logs), while EWMA rolling baselines adjust for natural habit evolution.
- **IT-to-OT Crossover Alerts**: Explicitly flags corporate IT accounts attempting unauthorized access to critical OT controllers (Honeywell Forge, BMS, SCADA), highlighting industrial cybersecurity value for Honeywell.
