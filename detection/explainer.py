"""
Explainability Engine for Cyber Anomaly Alerts.
Generates human-readable feature attribution and reasoning strings for security analysts.
"""

class ExplainabilityEngine:
    def generate_explanation(self, event, rule_signals, feature_vec, baseline_stats, attack_type):
        """
        Builds bulleted explanation points identifying baseline deviations.
        """
        reasons = []
        
        # 1. Impossible Travel explanation
        if rule_signals.get("impossible_travel_flag"):
            dist = rule_signals.get("distance_miles", 0.0)
            speed = rule_signals.get("calculated_speed_mph", 0.0)
            reasons.append(f"⚡ IMPOSSIBLE TRAVEL: Traveled {dist:,} miles at calculated speed of {speed:,.0f} mph (max physically feasible: 550 mph).")

        # 2. IT-to-OT Crossover explanation
        if rule_signals.get("it_ot_crossover_flag"):
            reasons.append(f"⚠️ IT-OT CROSSOVER: IT Role ({event.get('role')}) accessed critical OT Asset '{event.get('target_resource')}'.")

        # 3. Off-Hours & Exfiltration
        hour = int(event["timestamp"].split(" ")[1].split(":")[0])
        avg_h = baseline_stats.get("avg_hour", 12.0)
        std_h = baseline_stats.get("std_hour", 2.0)
        if feature_vec[0] > 2.0 or rule_signals.get("off_hours_flag"):
            reasons.append(f"🕒 UNUSUAL TIME: Access at {hour:02d}:00 (historical avg for entity: {avg_h:.1f}:00 ± {std_h:.1f} hrs).")

        mb = float(event.get("mb_transferred", 0.0))
        avg_mb = baseline_stats.get("avg_mb", 50.0)
        if feature_vec[1] > 2.5 or rule_signals.get("exfil_flag"):
            reasons.append(f"📦 HIGH DATA VOLUME: {mb:,.1f} MB transferred (historical entity baseline: {avg_mb:,.1f} MB).")

        # 4. Device & Location Mismatch
        if rule_signals.get("device_mismatch_ot_flag") or feature_vec[2] > 0.5:
            reasons.append(f"💻 UNRECOGNIZED DEVICE: Device '{event.get('device_id')}' not in entity's historical device baseline.")

        if feature_vec[3] > 0.5:
            reasons.append(f"📍 UNUSUAL LOCATION: Login from '{event.get('location_name')}' outside historical geographic baseline.")

        # 5. Brute force
        if rule_signals.get("brute_force_flag") or event.get("auth_result") == "FAILURE":
            fails = baseline_stats.get("recent_failed_logins", 1)
            reasons.append(f"🔒 FAILED AUTHENTICATION SPIKE: {fails} consecutive failed login attempts detected.")

        if not reasons:
            reasons.append("⚡ MULTI-VARIABLE ANOMALY: Combined baseline deviation across time, location, and resource access patterns.")

        return " | ".join(reasons)
