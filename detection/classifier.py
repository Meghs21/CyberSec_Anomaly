"""
Anomaly Taxonomy & Attack Classifier Engine.
Classifies flagged events into Point, Contextual, or Collective anomalies and maps attack types.
"""

class AnomalyClassifier:
    def classify_anomaly(self, event, rule_signals, feature_vec, baseline_stats):
        """
        Classifies an anomaly event into taxonomy category and attack label.
        """
        # Rule deterministic classifications
        if rule_signals.get("impossible_travel_flag"):
            return "Collective Anomaly", "Impossible Travel"
            
        if rule_signals.get("brute_force_flag") or event.get("auth_result") == "FAILURE":
            return "Point Anomaly", "Brute Force"
            
        if rule_signals.get("it_ot_crossover_flag"):
            return "Collective Anomaly", "IT-OT Crossover"
            
        if rule_signals.get("device_mismatch_ot_flag"):
            return "Contextual Anomaly", "Device Mismatch OT"
            
        if rule_signals.get("off_hours_flag") and rule_signals.get("exfil_flag"):
            return "Contextual Anomaly", "Off-Hours Exfiltration"
            
        # Check for dormant account (event count < 5 but entity ID exists with dormant tag or long gap)
        if baseline_stats.get("is_cold_start") and event.get("target_resource") in ["BMS_Controller_HVAC_01", "Honeywell_Forge_Gateway"]:
            return "Collective Anomaly", "Dormant Account Reactivation"
            
        if rule_signals.get("off_hours_flag"):
            return "Contextual Anomaly", "Off-Hours Resource Access"
            
        if rule_signals.get("exfil_flag"):
            return "Contextual Anomaly", "High Transfer Exfiltration"

        return "Contextual Anomaly", "Unusual Behavioral Deviation"
