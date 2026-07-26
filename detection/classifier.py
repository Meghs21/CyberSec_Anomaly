"""
Official Attack Taxonomy Classifier (Stage 2).
Classifies detected anomalies into exact official categories:
- brute_force
- impossible_travel
- credential_stuffing
- lateral_movement
- device_spoofing
- low_and_slow_exfiltration
- insider_drift (Non-malicious concept drift edge case)
- normal
Enforces strict label leakage prevention.
"""

class AnomalyClassifier:
    def classify_anomaly(self, event, rule_signals, feature_vec, sequence_score, baseline_stats, risk_score):
        """
        Classifies an event based strictly on observed signals and feature deviations.
        Fails loudly if ground-truth label leakage is detected!
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before classification!"

        # Deterministic rule-based classification mapping
        if rule_signals.get("impossible_travel_flag"):
            return "impossible_travel", "Collective Anomaly"

        if rule_signals.get("credential_stuffing_flag"):
            return "credential_stuffing", "Point Anomaly"

        if rule_signals.get("brute_force_flag"):
            return "brute_force", "Point Anomaly"

        if rule_signals.get("device_spoofing_flag") or feature_vec[3] > 0.5:
            return "device_spoofing", "Contextual Anomaly"

        if rule_signals.get("lateral_movement_flag") or sequence_score > 0.65:
            return "lateral_movement", "Collective Anomaly"

        if rule_signals.get("low_slow_exfil_flag") or (rule_signals.get("off_hours_flag") and feature_vec[1] > 1.8):
            return "low_and_slow_exfiltration", "Contextual Anomaly"

        # Check for insider_drift edge case (gradual legitimate expansion)
        if 20.0 <= risk_score < 50.0 and (feature_vec[5] > 0.5 or baseline_stats.get("baseline_type") == "blended"):
            return "insider_drift", "Behavioral Drift (Adapting)"

        if risk_score >= 60.0:
            return "lateral_movement", "Contextual Anomaly"

        return "normal", "Normal Baseline"
