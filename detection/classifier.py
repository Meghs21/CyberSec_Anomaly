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
- generic_behavioral_anomaly (Uncategorized high-risk behavioral anomaly)
- normal
Enforces strict label leakage prevention.
"""

class AnomalyClassifier:
    def classify_anomaly(self, event, rule_signals, feature_vec, sequence_score, baseline_stats, risk_score):
        """
        Classifies an event based strictly on observed signals and feature deviations.
        Feature Vector Layout (7 dims):
          [0]: hour_zscore
          [1]: mb_zscore
          [2]: dur_zscore
          [3]: dev_unusual  (1.0 if new device fingerprint relative to baseline)
          [4]: loc_unusual  (1.0 if new geo location relative to baseline)
          [5]: res_unusual  (1.0 if new resource accessed relative to baseline)
          [6]: auth_fail    (1.0 if failure detected in command sequence)

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

        # Fallback for unclassified high-risk behavioral anomalies (prevents mislabeling as lateral movement)
        if risk_score >= 60.0:
            return "generic_behavioral_anomaly", "Behavioral Anomaly"

        return "normal", "Normal Baseline"
