"""
Risk Fusion Engine supporting 3-Way Sequence Model Ensemble Config.
Merges behavioral baseline Z-scores, pre-fused sequence anomaly score,
and rule assist signals into a unified risk_score in [0.0, 100.0].
Enforces strict label leakage prevention.
"""

class RiskFusionEngine:
    def __init__(self, base_alert_threshold=60.0):
        self.base_threshold = base_alert_threshold

    def fuse_risk_score(self, event, rule_signals, ml_score, sequence_score, baseline_stats):
        """
        Combines rule overrides, pre-fused sequence score, and ML raw score into risk_score [0, 100].
        Fails loudly if label leakage is detected.
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before risk fusion!"

        dynamic_threshold = (
            self.base_threshold + 10.0 if baseline_stats.get("baseline_type") == "cohort"
            else self.base_threshold
        )

        # Hard overrides for severe deterministic rules
        if rule_signals.get("impossible_travel_flag"):
            return 98.0, "CRITICAL", dynamic_threshold

        if rule_signals.get("brute_force_flag"):
            return 92.0, "CRITICAL", dynamic_threshold

        if rule_signals.get("credential_stuffing_flag"):
            return 94.0, "CRITICAL", dynamic_threshold

        # Base score from ML anomaly model & fused sequence score
        base_risk = min(50.0, max(0.0, ml_score * 20.0)) + (sequence_score * 30.0)

        # Rule Signal Contributions
        if rule_signals.get("lateral_movement_flag"):
            base_risk += 35.0

        if rule_signals.get("device_spoofing_flag"):
            base_risk += 30.0

        if rule_signals.get("low_slow_exfil_flag"):
            base_risk += 35.0
        elif rule_signals.get("off_hours_flag"):
            base_risk += 15.0

        final_risk = round(float(min(100.0, max(0.0, base_risk))), 1)

        if final_risk >= 85.0:
            severity = "CRITICAL"
        elif final_risk >= 70.0:
            severity = "HIGH"
        elif final_risk >= 50.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return final_risk, severity, dynamic_threshold
