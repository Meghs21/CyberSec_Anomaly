"""
Stateful Data Store & Detection Pipeline Coordinator.
Enforces structural label leakage prevention at the inference boundary,
coordinates baseline profiling, sequence modeling, cold-start blending, concept drift adaptation,
and calculates official evaluation metrics including Top-1% Analyst Alert Budget metrics.
"""

import sqlite3
import os
import sys
import math
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

# Ensure parent directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from data_gen.generator import SyntheticLogGenerator
from detection.baseline import EntityBaselineProfiler
from detection.cold_start import ColdStartManager
from detection.sequence import SequenceMarkovDetector, SequenceAutoencoderDetector, SequenceIntelligenceFusion
from detection.rule_engine import RuleAssistEngine
from detection.ml_detector import MLAnomalyDetector
from detection.risk_fusion import RiskFusionEngine
from detection.classifier import AnomalyClassifier
from detection.explainer import ExplainabilityEngine

class DataStore:
    def __init__(self, sequence_mode=None):
        self.raw_df = None
        self.analyzed_events = []
        self.ground_truth_labels = {}  # event_id -> true_label
        self.alert_states = {}         # alert_id -> {status, notes}
        self.current_threshold = 60.0
        self.sequence_mode = sequence_mode or os.getenv("SEQUENCE_MODEL_MODE", "ngram").lower()
        self.seq_fusion = SequenceIntelligenceFusion(mode=self.sequence_mode)
        self.db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "honeywell_cyber.db"))
        self._init_sqlite_db()
        self.load_and_process_data()

    def _init_sqlite_db(self):
        """Initializes real-time SQLite database schema on disk."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                event_index INTEGER,
                timestamp TEXT,
                entity_id TEXT,
                entity_type TEXT,
                role TEXT,
                domain TEXT,
                source_ip TEXT,
                geo_location TEXT,
                resource_accessed TEXT,
                auth_method TEXT,
                session_duration INTEGER,
                command_sequence TEXT,
                device_fingerprint TEXT,
                mb_transferred REAL,
                risk_score REAL,
                severity TEXT,
                is_alert INTEGER,
                predicted_taxonomy TEXT,
                explanation TEXT,
                baseline_type TEXT
            )
        """)

        # Alerts audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT,
                action_timestamp TEXT,
                action_type TEXT,
                note_text TEXT,
                analyst_status TEXT
            )
        """)

        conn.commit()
        conn.close()

    def load_and_process_data(self):
        data_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_access_logs.csv"))
        if os.path.exists(data_path):
            self.raw_df = pd.read_csv(data_path)
        else:
            gen = SyntheticLogGenerator(num_entities=50, num_days=14, anomaly_rate=0.015)
            self.raw_df = gen.generate_dataset(total_sessions=1500)
            os.makedirs(os.path.dirname(data_path), exist_ok=True)
            self.raw_df.to_csv(data_path, index=False)

        self._run_pipeline()

    def _run_pipeline(self):
        import pickle
        cache_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "models_cache.pkl"))
        
        cold_start = ColdStartManager(min_events_threshold=10)
        rule_engine = RuleAssistEngine()
        risk_fusion = RiskFusionEngine(base_alert_threshold=self.current_threshold)
        classifier = AnomalyClassifier()
        explainer = ExplainabilityEngine()

        events_raw = self.raw_df.to_dict("records")
        TRAINING_SPLIT_SIZE = 300
        training_events = events_raw[:TRAINING_SPLIT_SIZE]
        live_events = events_raw[TRAINING_SPLIT_SIZE:]
        normal_train_split = [e for e in training_events if e.get("label", "normal") == "normal"]

        # Attempt to load pre-analyzed events & pre-trained models from disk for sub-1s cold boot
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "rb") as f:
                    cached = pickle.load(f)
                    self.analyzed_events = cached.get("analyzed_events", [])
                    self.ground_truth_labels = cached.get("ground_truth_labels", {})
                    self.alert_states = cached.get("alert_states", {})
                    if self.analyzed_events:
                        print("[MODEL PERSISTENCE] Successfully loaded pre-analyzed events & models from models_cache.pkl (< 0.2s)")
                        self._sync_to_sqlite()
                        return
            except Exception as e:
                print(f"[MODEL PERSISTENCE] Warning: Could not load cache ({e}). Re-analyzing dataset...")

        ml_detector = MLAnomalyDetector(contamination=0.02)
        sequence_detector = SequenceMarkovDetector(min_cohort_events=10)
        autoencoder_detector = SequenceAutoencoderDetector()

        # Fit all models using a SEPARATE, disposable fitting_profiler instance for training pass
        fitting_profiler = EntityBaselineProfiler()
        print(f"[MODEL PERSISTENCE] Fitting models baseline on N={TRAINING_SPLIT_SIZE} training split using isolated profiler...")
        ml_detector.fit_normal_baseline(training_events, fitting_profiler)
        sequence_detector.fit_normal_baseline(normal_train_split)
        autoencoder_detector.fit_normal_baseline(normal_train_split)

        try:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, "wb") as f:
                pickle.dump({
                    "ml_detector": ml_detector,
                    "sequence_detector": sequence_detector,
                    "autoencoder_detector": autoencoder_detector
                }, f)
            print("[MODEL PERSISTENCE] Saved trained models to models_cache.pkl")
        except Exception as e:
            print(f"[MODEL PERSISTENCE] Could not save model cache: {e}")

        # Main live pipeline loop starts with a FRESH profiler and processes ONLY held-out live_events
        profiler = EntityBaselineProfiler()
        self.analyzed_events = []
        self.ground_truth_labels = {}
        entity_histories = {}

        for idx, ev in enumerate(live_events):
            alert_id = f"ALT-{idx+1:04d}"
            
            true_label = str(ev.get("label", "normal"))
            self.ground_truth_labels[alert_id] = true_label
            
            ev_inference = {k: v for k, v in ev.items() if k != "label"}
            assert "label" not in ev_inference, "LABEL LEAKAGE DETECTED at pipeline entry point!"

            entity_id = ev_inference["entity_id"]
            entity_type = ev_inference.get("entity_type", "user")

            if entity_id not in entity_histories:
                entity_histories[entity_id] = []
            entity_histories[entity_id].append(ev_inference)

            # 1. Baseline & Cold Start Profiling
            personal_profile = profiler.get_profile(entity_id)
            effective_baseline = cold_start.get_effective_baseline(entity_id, entity_type, personal_profile)

            # 2. Rule Evaluation
            rule_signals = rule_engine.evaluate_rules(ev_inference, effective_baseline)

            # 3. ML Feature Extraction & Scoring
            feat_vec = ml_detector.extract_features(ev_inference, effective_baseline)
            ml_score = ml_detector.predict_raw_score(feat_vec)

            # 4. Sequence Anomaly Scoring (N-Gram & Autoencoder)
            prev_ev = entity_histories[entity_id][-2] if len(entity_histories[entity_id]) >= 2 else None
            ngram_score = sequence_detector.calculate_sequence_score(ev_inference, personal_profile, prev_event=prev_ev)
            ae_score, ae_mse, ae_attr = autoencoder_detector.calculate_autoencoder_score(ev_inference, entity_histories[entity_id])

            # 5. Sequence Score Fusion (Single Source of Truth: SequenceIntelligenceFusion)
            fused_seq_score = self.seq_fusion.fuse_sequence_scores(ngram_score, ae_score)

            # 6. Risk Score Fusion
            risk_score, severity, dynamic_thresh = risk_fusion.fuse_risk_score(
                ev_inference, rule_signals, ml_score, fused_seq_score, effective_baseline
            )

            # 7. Attack Classification (Stage 2)
            tax_cat, attack_cat = classifier.classify_anomaly(
                ev_inference, rule_signals, feat_vec, fused_seq_score, effective_baseline, risk_score
            )

            # 8. Explainability Attribution (Deliverable #5)
            reason = explainer.generate_explanation(
                ev_inference, rule_signals, feat_vec, fused_seq_score, effective_baseline, tax_cat
            )

            # 8. Anti-Poisoning Concept Drift & Sequence Transition Updates
            profiler.update_profile(ev_inference, inferred_risk_score=risk_score)
            prev_ev_for_update = entity_histories[entity_id][-2] if len(entity_histories[entity_id]) >= 2 else None
            sequence_detector.update_transitions_online(ev_inference, inferred_risk_score=risk_score, prev_event=prev_ev_for_update)

            is_alert = (risk_score >= dynamic_thresh and tax_cat not in ["normal", "insider_drift"])
            
            existing_state = self.alert_states.get(alert_id, {
                "status": "NEW",
                "notes": []
            })

            res = {
                "id": alert_id,
                "event_index": int(idx),
                "timestamp": str(ev_inference["timestamp"]),
                "entity_id": str(ev_inference["entity_id"]),
                "entity_type": str(ev_inference["entity_type"]),
                "role": str(ev_inference.get("role", "Unknown")),
                "domain": str(ev_inference.get("domain", "IT")),
                "source_ip": str(ev_inference["source_ip"]),
                "geo_location": str(ev_inference["geo_location"]),
                "resource_accessed": str(ev_inference["resource_accessed"]),
                "auth_method": str(ev_inference["auth_method"]),
                "session_duration": int(ev_inference["session_duration"]),
                "command_sequence": str(ev_inference["command_sequence"]),
                "device_fingerprint": str(ev_inference["device_fingerprint"]),
                "mb_transferred": float(ev_inference.get("mb_transferred", 0.0)),
                "risk_score": float(risk_score),
                "severity": str(severity),
                "is_alert": bool(is_alert),
                "predicted_taxonomy": str(attack_cat if is_alert or tax_cat == "insider_drift" else "Normal Baseline"),
                "predicted_attack_type": str(tax_cat),
                "explanation": str(reason),
                "baseline_type": str(effective_baseline["baseline_type"]),
                "weight_personal": float(effective_baseline["weight_personal"]),
                "status": str(existing_state["status"]),
                "notes": list(existing_state["notes"])
            }

            self.analyzed_events.append(res)
            self.alert_states[alert_id] = existing_state

        try:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            with open(cache_path, "wb") as f:
                pickle.dump({
                    "analyzed_events": self.analyzed_events,
                    "ground_truth_labels": self.ground_truth_labels,
                    "alert_states": self.alert_states
                }, f)
            print("[MODEL PERSISTENCE] Successfully saved pre-analyzed events & cache to models_cache.pkl")
        except Exception as e:
            print(f"[MODEL PERSISTENCE] Could not save cache: {e}")

        self._sync_to_sqlite()

    def _sync_to_sqlite(self):
        """Batch upserts self.analyzed_events into SQLite data/honeywell_cyber.db."""
        if not self.analyzed_events:
            return
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            for ev in self.analyzed_events:
                cursor.execute("""
                    INSERT OR REPLACE INTO events (
                        id, event_index, timestamp, entity_id, entity_type, role, domain, source_ip,
                        geo_location, resource_accessed, auth_method, session_duration, command_sequence,
                        device_fingerprint, mb_transferred, risk_score, severity, is_alert,
                        predicted_taxonomy, explanation, baseline_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ev["id"], ev["event_index"], ev["timestamp"], ev["entity_id"], ev["entity_type"],
                    ev["role"], ev["domain"], ev["source_ip"], ev["geo_location"], ev["resource_accessed"],
                    ev["auth_method"], ev["session_duration"], ev["command_sequence"], ev["device_fingerprint"],
                    ev["mb_transferred"], ev["risk_score"], ev["severity"], 1 if ev["is_alert"] else 0,
                    ev["predicted_taxonomy"], ev["explanation"], ev["baseline_type"]
                ))
            conn.commit()
            conn.close()
            print(f"[SQLITE DB ENGINE] Successfully synced {len(self.analyzed_events)} events into honeywell_cyber.db")
        except Exception as e:
            print(f"[SQLITE DB WARNING] Could not sync to SQLite: {e}")

    def update_threshold(self, new_threshold: float):
        self.current_threshold = new_threshold
        for ev in self.analyzed_events:
            ev["is_alert"] = (ev["risk_score"] >= self.current_threshold and ev["predicted_attack_type"] not in ["normal", "insider_drift"])

    def perform_action(self, alert_id: str, action_type: str, note_text: str = None):
        if alert_id not in self.alert_states:
            return None
        
        state = self.alert_states[alert_id]
        if action_type == "ACKNOWLEDGE":
            state["status"] = "ACKNOWLEDGED"
        elif action_type == "MARK_FALSE_POSITIVE":
            state["status"] = "FALSE_POSITIVE"
        elif action_type == "ESCALATE":
            state["status"] = "ESCALATED"

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if note_text:
            state["notes"].append(f"[{ts[:16]}] {note_text}")

        # Real-Time SQLite Audit Log Insertion
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts_audit_log (alert_id, action_timestamp, action_type, note_text, analyst_status)
                VALUES (?, ?, ?, ?, ?)
            """, (alert_id, ts, action_type, note_text or "", state["status"]))
            conn.commit()
            conn.close()
            print(f"[SQLITE DB AUDIT] Action '{action_type}' for {alert_id} written to honeywell_cyber.db")
        except Exception as e:
            print(f"[SQLITE DB WARNING] Could not insert audit log: {e}")

        for ev in self.analyzed_events:
            if ev["id"] == alert_id:
                ev["status"] = state["status"]
                ev["notes"] = state["notes"]
                return ev
        return None

    def get_overview_metrics(self):
        alerts = [e for e in self.analyzed_events if e["is_alert"]]
        malicious_labels = ["brute_force", "impossible_travel", "credential_stuffing", "lateral_movement", "device_spoofing", "low_and_slow_exfiltration"]
        
        y_true = [1 if self.ground_truth_labels[e["id"]] in malicious_labels else 0 for e in self.analyzed_events]
        y_pred = [1 if e["is_alert"] else 0 for e in self.analyzed_events]

        p = float(precision_score(y_true, y_pred) * 100) if any(y_pred) else 0.0
        r = float(recall_score(y_true, y_pred) * 100) if any(y_true) else 0.0
        f1 = float(f1_score(y_true, y_pred)) if any(y_pred) else 0.0

        df = pd.DataFrame(self.analyzed_events)
        df["date"] = df["timestamp"].apply(lambda x: str(x).split(" ")[0])
        time_series = df.groupby("date")["is_alert"].sum().to_dict()

        # Severity breakdown for Splunk-style Donut chart
        severity_counts = {
            "CRITICAL": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
            "HIGH": sum(1 for a in alerts if a["severity"] == "HIGH"),
            "MEDIUM": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
            "LOW": sum(1 for a in alerts if a["severity"] == "LOW")
        }

        # Calculate Top-1% Precision for quick metric tile
        N = len(self.analyzed_events)
        k_top1 = max(1, math.ceil(N * 0.01))
        sorted_events = sorted(self.analyzed_events, key=lambda x: x["risk_score"], reverse=True)
        top1_slice = sorted_events[:k_top1]
        top1_tp = sum(1 for e in top1_slice if self.ground_truth_labels[e["id"]] in malicious_labels)
        top1_p = (top1_tp / k_top1 * 100.0) if k_top1 > 0 else 0.0

        return {
            "total_events": len(self.analyzed_events),
            "active_alerts": len(alerts),
            "it_alerts_count": sum(1 for a in alerts if a["domain"] == "IT"),
            "ot_alerts_count": sum(1 for a in alerts if a["domain"] == "OT"),
            "crossover_alerts_count": sum(1 for a in alerts if a["predicted_attack_type"] == "lateral_movement"),
            "precision": round(p, 1),
            "recall": round(r, 1),
            "f1_score": round(f1, 3),
            "top1_precision": round(top1_p, 1),
            "severity_counts": severity_counts,
            "alert_volume_timeseries": time_series,
            "current_threshold": self.current_threshold
        }

    def get_evaluation_metrics(self):
        """
        Computes overall metrics + Top-1% Analyst Alert Budget Metrics (Evaluation Criterion #3).
        """
        malicious_labels = ["brute_force", "impossible_travel", "credential_stuffing", "lateral_movement", "device_spoofing", "low_and_slow_exfiltration"]
        
        y_true = [1 if self.ground_truth_labels[e["id"]] in malicious_labels else 0 for e in self.analyzed_events]
        y_pred = [1 if e["is_alert"] else 0 for e in self.analyzed_events]

        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = [int(x) for x in cm.ravel()]

        p = float(precision_score(y_true, y_pred) * 100) if any(y_pred) else 0.0
        r = float(recall_score(y_true, y_pred) * 100) if any(y_true) else 0.0
        f1 = float(f1_score(y_true, y_pred)) if any(y_pred) else 0.0

        # --- EVALUATION CRITERION #3: TOP-1% ANALYST ALERT BUDGET METRIC ---
        N = len(self.analyzed_events)
        k_top1 = max(1, math.ceil(N * 0.01))
        
        # Sort all events descending by risk_score
        sorted_events = sorted(self.analyzed_events, key=lambda x: x["risk_score"], reverse=True)
        top1_slice = sorted_events[:k_top1]
        
        top1_y_true = [1 if self.ground_truth_labels[e["id"]] in malicious_labels else 0 for e in top1_slice]
        top1_tp = sum(top1_y_true)
        top1_fp = k_top1 - top1_tp
        
        total_malicious = sum(y_true)
        total_benign = N - total_malicious
        
        top1_precision = (top1_tp / k_top1 * 100.0) if k_top1 > 0 else 0.0
        top1_recall = (top1_tp / total_malicious * 100.0) if total_malicious > 0 else 0.0
        top1_fpr = (top1_fp / total_benign * 100.0) if total_benign > 0 else 0.0
        # ------------------------------------------------------------------

        # Per scenario performance breakdown across official taxonomy
        scenarios = ["brute_force", "impossible_travel", "credential_stuffing", "lateral_movement", "device_spoofing", "low_and_slow_exfiltration"]
        breakdown = []

        for sc in scenarios:
            sc_events = [e for e in self.analyzed_events if self.ground_truth_labels[e["id"]] == sc]
            if sc_events:
                sc_tp = sum(1 for e in sc_events if e["is_alert"])
                sc_total = len(sc_events)
                sc_rec = (sc_tp / sc_total * 100.0) if sc_total > 0 else 100.0
                breakdown.append({
                    "scenario": sc,
                    "total_injected": int(sc_total),
                    "detected_count": int(sc_tp),
                    "recall_rate": round(float(sc_rec), 1)
                })

        return {
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "precision": round(p, 1),
            "recall": round(r, 1),
            "f1_score": round(f1, 4),
            "top1_alert_budget": {
                "budget_k": int(k_top1),
                "precision_at_1pct": round(float(top1_precision), 1),
                "recall_at_1pct": round(float(top1_recall), 1),
                "fpr_at_1pct": round(float(top1_fpr), 2)
            },
            "scenario_breakdown": breakdown
        }

# Global store instance
store = DataStore()
