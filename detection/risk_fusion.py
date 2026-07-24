"""
Risk Fusion & Dynamic Smart Thresholding Module.
Merges rule signals with ML continuous scores to output a unified 0-100 Risk Score.
"""

class RiskFusionEngine:
    def __init__(self, base_alert_threshold=65.0):
        self.base_threshold = base_alert_threshold

    def fuse_risk_score(self, event, rule_signals, ml_raw_score, baseline_stats):
        """
        Combines rule overrides and ML raw anomaly score into a 0-100 Risk Score.
        Handles dynamic thresholds based on cold-start status and entity domain.
        """
        # Hard overrides for physical impossibility or severe rules
        if rule_signals.get("impossible_travel_flag"):
            return 98.0, "CRITICAL", 50.0  # Threshold lowered to ensure alert
            
        if rule_signals.get("brute_force_flag"):
            return 92.0, "CRITICAL", 50.0

        # Base ML contribution scaled to 0-60 range
        base_risk = min(60.0, max(0.0, ml_raw_score * 25.0))
        
        # Add weights for specific suspicious patterns
        if rule_signals.get("it_ot_crossover_flag"):
            base_risk += 35.0  # Honeywell IT->OT crossover boost
            
        if rule_signals.get("device_mismatch_ot_flag"):
            base_risk += 30.0
            
        if rule_signals.get("off_hours_flag") and rule_signals.get("exfil_flag"):
            base_risk += 40.0
        elif rule_signals.get("off_hours_flag"):
            base_risk += 15.0
        elif rule_signals.get("exfil_flag"):
            base_risk += 25.0
            
        if baseline_stats.get("is_cold_start"):
            # Lower confidence during cold-start: widen threshold to prevent false positives
            dynamic_threshold = self.base_threshold + 10.0
        else:
            dynamic_threshold = self.base_threshold

        final_risk = min(100.0, round(base_risk, 1))
        
        # Determine risk severity band
        if final_risk >= 85.0:
            severity = "CRITICAL"
        elif final_risk >= 70.0:
            severity = "HIGH"
        elif final_risk >= 45.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return final_risk, severity, dynamic_threshold
