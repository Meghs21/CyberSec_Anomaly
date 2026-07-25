"""
Risk Fusion Engine supporting 3-Way Sequence Model Ensemble Config:
SEQUENCE_MODEL_MODE = "ngram" | "autoencoder" | "both"
Merges behavioral baseline Z-scores, selected sequence anomaly signal(s),
and rule assist signals into a unified risk_score in [0.0, 100.0].
Enforces strict label leakage prevention.
"""

import os

class RiskFusionEngine:
    def __init__(self, base_alert_threshold=60.0):
        self.base_threshold = base_alert_threshold

    def fuse_risk_score(self, event, rule_signals, ml_score, ngram_score, ae_score, baseline_stats, sequence_mode=None):
        """
        Combines rule overrides, sequence score(s), and ML raw score into risk_score [0, 100].
        Supports 3-way toggle: 'ngram' (default), 'autoencoder', 'both'.
        Fails loudly if label leakage is detected.
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before risk fusion!"

        if sequence_mode is None:
            sequence_mode = os.getenv("SEQUENCE_MODEL_MODE", "ngram").lower()

        # Determine effective sequence score based on 3-way toggle
        if sequence_mode == "autoencoder":
            effective_seq_score = ae_score
        elif sequence_mode == "both":
            effective_seq_score = 0.5 * ngram_score + 0.5 * ae_score
        else:  # 'ngram' default path (100% identical to before)
            effective_seq_score = ngram_score

        # Hard overrides for severe deterministic rules
        if rule_signals.get("impossible_travel_flag"):
            return 98.0, "CRITICAL", 50.0

        if rule_signals.get("brute_force_flag"):
            return 92.0, "CRITICAL", 50.0

        if rule_signals.get("credential_stuffing_flag"):
            return 94.0, "CRITICAL", 50.0

        # Base score from ML anomaly model & selected sequence model signal(s)
        base_risk = min(50.0, max(0.0, ml_score * 20.0)) + (effective_seq_score * 30.0)

        # Rule Signal Contributions
        if rule_signals.get("lateral_movement_flag"):
            base_risk += 35.0

        if rule_signals.get("device_spoofing_flag"):
            base_risk += 30.0

        if rule_signals.get("low_slow_exfil_flag"):
            base_risk += 35.0
        elif rule_signals.get("off_hours_flag"):
            base_risk += 15.0

        # Dynamic threshold adjusting for cold-start entities
        if baseline_stats.get("baseline_type") == "cohort":
            dynamic_threshold = self.base_threshold + 10.0
        else:
            dynamic_threshold = self.base_threshold

        final_risk = min(100.0, round(base_risk, 1))

        if final_risk >= 85.0:
            severity = "CRITICAL"
        elif final_risk >= 70.0:
            severity = "HIGH"
        elif final_risk >= 45.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return final_risk, severity, dynamic_threshold
