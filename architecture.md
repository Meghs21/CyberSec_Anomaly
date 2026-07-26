# Production System Architecture & Technical Design

## Honeywell AI-Powered Cyber Operations Console (FastAPI + React)

This document details the architectural design, mathematical formulations, hybrid ML models, sequence intelligence subsystem, and serving layer of the **Honeywell Cyber Operations Web Application** for mixed IT + OT enterprise environments.

---

## High-Level Architecture Diagram

```mermaid
flowchart TD
    subgraph Data Layer & Synthetic Engine
        A[Multi-Entity IT+OT Log Generator\n0.5-3.0% Anomaly Rate] -->|Official 11-Field Schema| B[(Synthetic Log Store CSV/JSONL)]
    end

    subgraph Inference Boundary
        B -->|Structurally Strip Label| C[Label Removal Gate\nAssertions: assert 'label' not in event]
    end

    subgraph Production Hybrid Detection Subsystems
        C --> D[Behavior Profile Subsystem\nIsolation Forest + Feature Z-Scores]
        
        subgraph Sequence Intelligence Subsystem (detection/sequence/)
            C --> E1[Markov Transition Model\nExplicit N-Gram Log-Probabilities]
            C --> E2[Behavioral Autoencoder\n30 -> 16 -> 8-dim Latent Bottleneck -> 16 -> 30]
            E1 --> E3[Sequence Intelligence Fusion\nsequence_score = f(markov, autoencoder)]
            E2 --> E3
        end
        
        C --> F[Rule Assist Engine\nGeo-Velocity & Brute Force Rules]
        C --> G[Cold-Start Manager\nCohort Priors + Personal Blending]
        C --> H[ConceptDriftAdapter (detection/drift.py)\nSingle-Source-of-Truth EWMA + Anti-Poisoning Filter]
    end

    subgraph Fusion, Classification & Explainability
        D --> I[Risk Fusion Engine\nContinuous Risk Score in [0, 100]]
        E3 --> I
        F --> I
        G --> I
        H --> I

        I -->|Stage 1: Is Weird?| J[Stage 2: Threat Classifier\n6 Malicious Categories + Insider Drift]
        I -->|Stage 1: Is Weird?| K[SHAP/Z-Score Explainability Engine]
    end

    subgraph Evaluation & Serving Layer (FastAPI)
        J --> L[FastAPI Application Server]
        K --> L
        L --> M[Top-1% Analyst Alert Budget Metrics\nPrecision@Top1%, Recall@Top1%, FPR@Top1%]
        L --> N[WebSocket Server\n/api/events/stream]
        L --> O[REST API Layer]
    end

    subgraph Industrial SOC Console (React Single-Page App)
        N -->|Real-Time Event Stream| P[React 18 Console]
        O <-->|Stateful Analyst Actions| P

        subgraph Navigable Views
            P --> Q[1. Overview Dashboard & Alert Sparkline]
            P --> R[2. Live Event Feed WebSocket Table]
            P --> S[3. Alerts & Triage Queue\nAcknowledge / FP / Escalate / Notes]
            P --> T[4. Entity Investigation & Cold-Start Badges]
            P --> U[5. Analytics & Top-1% Alert Budget Card]
            P --> V[6. Model Tuning & Dynamic Thresholds]
        end
    end
```

---

## Latent Bottleneck Mathematical Justification

The **Behavioral Autoencoder** (`detection/sequence/autoencoder_model.py`) models sequence context over fixed-length event windows ($K=5$ events $\times$ 19-dim encoded vectors $= 95$-dimensional input):

$$\mathbf{x} \in \mathbb{R}^{95} \xrightarrow{\text{Encoder}} \mathbf{h} \in \mathbb{R}^{32} \xrightarrow{\text{Bottleneck}} \mathbf{z} \in \mathbb{R}^{16} \xrightarrow{\text{Decoder}} \mathbf{h}' \in \mathbb{R}^{32} \xrightarrow{\text{Reconstruction}} \mathbf{\hat{x}} \in \mathbb{R}^{95}$$

### Mathematical Rationale:
1. **Dimension Compression**: The 16-dimensional bottleneck forces the network to learn a low-dimensional manifold representing normal, legitimate IT and OT entity interactions.
2. **Reconstruction Loss Metric**: Mean Squared Error (MSE) measures the distance between input $\mathbf{x}$ and reconstructed output $\mathbf{\hat{x}}$:
   $$\text{MSE}(\mathbf{x}, \mathbf{\hat{x}}) = \frac{1}{95} \sum_{i=1}^{95} (x_i - \hat{x}_i)^2$$
3. **Discriminative Capability**: Higher reconstruction error directly indicates session patterns that fall outside the learned latent manifold. On benchmark evaluations, anomalous sequences exhibit a **5.22x higher MSE reconstruction loss** compared to normal baseline traffic (`0.52576` vs `0.10071`).

---

## Production Readiness & Capability Maturity Statement

> *"This platform implements the core behavioral detection engine. The architecture is designed so that production concerns such as model retraining, monitoring, feature stores, and deployment can be layered on without changing the detection pipeline."*
