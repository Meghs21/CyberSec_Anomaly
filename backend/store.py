"""
Stateful Alert & Security Operations Data Store.
Tracks analyzed events, alerts, analyst workflow actions (Acknowledge, FP, Escalate, Notes),
and dynamic alert threshold settings.
"""

import os
import sys
from datetime import datetime
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

# Ensure parent directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from data_gen.generator import SyntheticLogGenerator
from detection.baseline import EntityBaselineProfiler
from detection.rule_engine import RuleAssistEngine
from detection.ml_detector import MLAnomalyDetector
from detection.risk_fusion import RiskFusionEngine
from detection.classifier import AnomalyClassifier
from detection.explainer import ExplainabilityEngine

class DataStore:
    def __init__(self):
        self.raw_df = None
        self.analyzed_events = []
        self.alert_states = {}  # alert_id -> {status, notes, timestamp}
        self.current_threshold = 60.0
        self.load_and_process_data()

    def load_and_process_data(self):
        data_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_access_logs.csv"))
        if os.path.exists(data_path):
            self.raw_df = pd.read_csv(data_path)
        else:
            gen = SyntheticLogGenerator(num_users=50, num_days=14)
            raw_df = gen.generate_logs(target_events=1000)
            self.raw_df = gen.inject_attack_scenarios(raw_df)
            os.makedirs(os.path.dirname(data_path), exist_ok=True)
            self.raw_df.to_csv(data_path, index=False)

        self._run_pipeline()

    def _run_pipeline(self):
        profiler = EntityBaselineProfiler()
        rule_engine = RuleAssistEngine()
        ml_detector = MLAnomalyDetector()
        risk_fusion = RiskFusionEngine(base_alert_threshold=self.current_threshold)
        classifier = AnomalyClassifier()
        explainer = ExplainabilityEngine()

        events = self.raw_df.to_dict("records")
        ml_detector.fit_normal_baseline(events[:300], profiler)

        self.analyzed_events = []
        
        for idx, ev in enumerate(events):
            user_id = ev["user_id"]
            user_domain = ev.get("domain", "IT")
            
            baseline_stats = profiler.get_baseline_stats(user_id, user_domain)
            rule_signals = rule_engine.evaluate_rules(ev, baseline_stats)
            feat_vec = ml_detector.extract_features(ev, baseline_stats)
            ml_score = ml_detector.predict_raw_score(feat_vec)
            
            risk_score, severity, dynamic_thresh = risk_fusion.fuse_risk_score(ev, rule_signals, ml_score, baseline_stats)
            tax_cat, attack_cat = classifier.classify_anomaly(ev, rule_signals, feat_vec, baseline_stats)
            reason = explainer.generate_explanation(ev, rule_signals, feat_vec, baseline_stats, attack_cat)
            
            profiler.update_profile(ev)
            
            is_alert = risk_score >= self.current_threshold
            alert_id = f"ALT-{idx+1:04d}"
            
            # Maintain analyst workflow state if previously modified
            existing_state = self.alert_states.get(alert_id, {
                "status": "NEW",
                "notes": []
            })
            
            res = {
                "id": str(alert_id),
                "event_index": int(idx),
                "timestamp": str(ev["timestamp"]),
                "user_id": str(ev["user_id"]),
                "role": str(ev["role"]),
                "domain": str(ev["domain"]),
                "target_resource": str(ev["target_resource"]),
                "asset_domain": str(ev["asset_domain"]),
                "ip_address": str(ev["ip_address"]),
                "latitude": float(ev["latitude"]),
                "longitude": float(ev["longitude"]),
                "location_name": str(ev["location_name"]),
                "device_id": str(ev["device_id"]),
                "mb_transferred": float(ev["mb_transferred"]),
                "auth_result": str(ev["auth_result"]),
                "is_attack": bool(ev["is_attack"]),
                "attack_type": str(ev["attack_type"]),
                "taxonomy": str(ev["taxonomy"]),
                "risk_score": float(risk_score),
                "severity": str(severity),
                "is_alert": bool(is_alert),
                "predicted_taxonomy": str(tax_cat if is_alert else "Normal"),
                "predicted_attack_type": str(attack_cat if is_alert else "None"),
                "explanation": str(reason if is_alert else "Normal activity."),
                "status": str(existing_state["status"]),
                "notes": list(existing_state["notes"])
            }
            
            self.analyzed_events.append(res)
            self.alert_states[alert_id] = existing_state

    def update_threshold(self, new_threshold: float):
        self.current_threshold = new_threshold
        for ev in self.analyzed_events:
            ev["is_alert"] = ev["risk_score"] >= self.current_threshold

    def perform_action(self, alert_id: str, action_type: str, note_text: str = None):
        """Performs analyst triage action and persists state."""
        if alert_id not in self.alert_states:
            return None
        
        state = self.alert_states[alert_id]
        if action_type == "ACKNOWLEDGE":
            state["status"] = "ACKNOWLEDGED"
        elif action_type == "MARK_FALSE_POSITIVE":
            state["status"] = "FALSE_POSITIVE"
        elif action_type == "ESCALATE":
            state["status"] = "ESCALATED"
            
        if note_text:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M")
            state["notes"].append(f"[{ts}] {note_text}")

        # Update event record in memory
        for ev in self.analyzed_events:
            if ev["id"] == alert_id:
                ev["status"] = state["status"]
                ev["notes"] = state["notes"]
                return ev
        return None

    def get_overview_metrics(self):
        alerts = [e for e in self.analyzed_events if e["is_alert"]]
        it_alerts = [a for a in alerts if a["asset_domain"] == "IT"]
        ot_alerts = [a for a in alerts if a["asset_domain"] == "OT"]
        crossovers = [a for a in alerts if a["predicted_attack_type"] == "IT-OT Crossover"]
        
        y_true = [int(e["is_attack"]) for e in self.analyzed_events]
        y_pred = [int(e["is_alert"]) for e in self.analyzed_events]
        
        p = precision_score(y_true, y_pred) if any(y_pred) else 0.0
        r = recall_score(y_true, y_pred) if any(y_true) else 0.0
        f1 = f1_score(y_true, y_pred) if any(y_pred) else 0.0

        # Time series sparkline data (count per day/time window)
        df = pd.DataFrame(self.analyzed_events)
        df["date"] = df["timestamp"].apply(lambda x: str(x).split(" ")[0])
        time_series = df.groupby("date")["is_alert"].sum().to_dict()

        return {
            "total_events": len(self.analyzed_events),
            "active_alerts": len(alerts),
            "it_alerts_count": len(it_alerts),
            "ot_alerts_count": len(ot_alerts),
            "crossover_alerts_count": len(crossovers),
            "precision": round(float(p * 100), 1),
            "recall": round(float(r * 100), 1),
            "f1_score": round(float(f1), 3),
            "alert_volume_timeseries": time_series,
            "current_threshold": self.current_threshold
        }

    def get_evaluation_metrics(self):
        y_true = [int(e["is_attack"]) for e in self.analyzed_events]
        y_pred = [int(e["is_alert"]) for e in self.analyzed_events]
        
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = [int(x) for x in cm.ravel()]
        
        p = float(precision_score(y_true, y_pred) * 100) if any(y_pred) else 0.0
        r = float(recall_score(y_true, y_pred) * 100) if any(y_true) else 0.0
        f1 = float(f1_score(y_true, y_pred)) if any(y_pred) else 0.0
        
        # Per scenario performance breakdown
        scenarios = ["Impossible Travel", "Off-Hours Exfiltration", "Dormant Account Reactivation", "Device Mismatch OT", "Brute Force", "IT-OT Crossover"]
        breakdown = []
        
        for sc in scenarios:
            sc_events = [e for e in self.analyzed_events if e.get("attack_type") == sc or e.get("predicted_attack_type") == sc]
            if sc_events:
                sc_true = [int(e["is_attack"]) for e in sc_events]
                sc_pred = [int(e["is_alert"]) for e in sc_events]
                sc_tp = sum(1 for t, p in zip(sc_true, sc_pred) if t == 1 and p == 1)
                sc_total = sum(sc_true)
                sc_rec = (sc_tp / sc_total * 100) if sc_total > 0 else 100.0
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
            "scenario_breakdown": breakdown
        }

# Global store instance
store = DataStore()
