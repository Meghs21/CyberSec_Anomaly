"""
Explainability Engine for Cyber Anomaly Alerts (Deliverable #5).
Produces evidence-based feature attributions, observed vs expected values,
and exact rule/sequence contributions.
Enforces strict label leakage prevention.
"""

class ExplainabilityEngine:
    def generate_explanation(self, event, rule_signals, feature_vec, sequence_score, baseline_stats, attack_type):
        """
        Generates human-readable evidence-based explainability strings.
        Fails loudly if ground-truth label leakage is detected!
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before explainability generation!"

        reasons = []

        # 1. Impossible Travel
        if rule_signals.get("impossible_travel_flag"):
            dist = rule_signals.get("distance_miles", 0.0)
            speed = rule_signals.get("calculated_speed_mph", 0.0)
            reasons.append(f"⚡ IMPOSSIBLE TRAVEL: Geo-velocity {speed:,.0f} mph over {dist:,} miles (max physical threshold: 550 mph)")

        # 2. Credential Stuffing & Brute Force
        if rule_signals.get("credential_stuffing_flag"):
            reasons.append(f"🔒 CREDENTIAL STUFFING: Single IP {event.get('source_ip')} targeting multiple entities with high failure rate")
        elif rule_signals.get("brute_force_flag"):
            fails = baseline_stats.get("recent_failed_logins", 5)
            reasons.append(f"🔒 BRUTE FORCE: {fails} rapid failed authentication attempts from source {event.get('source_ip')}")

        # 3. Device Spoofing
        if rule_signals.get("device_spoofing_flag"):
            reasons.append(f"💻 DEVICE SPOOFING: Fingerprint '{event.get('device_fingerprint')[:35]}...' mismatches entity baseline")

        # 4. Sequence Anomaly & Lateral Movement
        if sequence_score > 0.6:
            reasons.append(f"🔄 UNUSUAL COMMAND/RESOURCE SEQUENCE: N-gram transition anomaly score {sequence_score:.2f} (Markov log-probability deviation)")

        if rule_signals.get("lateral_movement_flag"):
            reasons.append(f"⚠️ LATERAL MOVEMENT: Entity accessed resource '{event.get('resource_accessed')}' outside historical footprint")

        # 5. Low-and-Slow Exfiltration & Time Deviation
        if rule_signals.get("low_slow_exfil_flag"):
            reasons.append(f"📦 LOW-AND-SLOW EXFILTRATION: Cumulative small off-hours resource accesses detected")

        timestamp = event["timestamp"]
        hour = int(timestamp.split(" ")[1].split(":")[0])
        avg_h = baseline_stats.get("avg_hour")
        avg_h = 12.0 if avg_h is None else float(avg_h)
        std_h = baseline_stats.get("std_hour")
        std_h = 2.0 if std_h is None else float(std_h)
        if feature_vec[0] > 2.0:
            reasons.append(f"🕒 UNUSUAL LOGIN TIME: Access at {hour:02d}:00 (historical entity baseline: {avg_h:.1f}:00 ± {std_h:.1f} hrs)")

        # 6. Insider Drift (Non-malicious concept drift)
        if attack_type == "insider_drift":
            return "🌱 BEHAVIORAL DRIFT: Entity behavior has gradually expanded to new legitimate resource patterns. Adaptive baseline is incorporating pattern."

        if not reasons:
            reasons.append("⚡ MULTI-VARIABLE ANOMALY: Combined baseline deviation across time, location, and resource access patterns")

        return " | ".join(reasons)
