"""
Rule-Assist Engine for Deterministic Cyber Anomalies.
Provides physical speed checks (impossible travel), brute-force thresholding, and IT-OT crossover rules.
"""

from datetime import datetime
import math

def haversine_miles(lat1, lon1, lat2, lon2):
    R = 3958.8
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

class RuleAssistEngine:
    def __init__(self, max_feasible_speed_mph=550.0, brute_force_fail_limit=5):
        self.max_speed_mph = max_feasible_speed_mph
        self.brute_force_limit = brute_force_fail_limit

    def evaluate_rules(self, event, baseline_stats):
        """Evaluates deterministic physics and threshold rules against event and entity baseline."""
        rule_signals = {
            "impossible_travel_flag": False,
            "calculated_speed_mph": 0.0,
            "distance_miles": 0.0,
            "brute_force_flag": False,
            "it_ot_crossover_flag": False,
            "device_mismatch_ot_flag": False,
            "off_hours_flag": False,
            "exfil_flag": False
        }
        
        # 1. Check Impossible Travel
        last_ts = baseline_stats.get("last_seen_timestamp")
        last_lat = baseline_stats.get("last_seen_lat")
        last_lon = baseline_stats.get("last_seen_lon")
        
        if last_ts and last_lat is not None and last_lon is not None:
            try:
                curr_dt = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
                last_dt = datetime.strptime(last_ts, "%Y-%m-%d %H:%M:%S")
                hours_diff = (curr_dt - last_dt).total_seconds() / 3600.0
                
                curr_lat = float(event["latitude"])
                curr_lon = float(event["longitude"])
                dist = haversine_miles(last_lat, last_lon, curr_lat, curr_lon)
                
                if hours_diff > 0.001 and dist > 100.0:  # Only evaluate if moved > 100 miles
                    speed = dist / hours_diff
                    rule_signals["distance_miles"] = round(dist, 1)
                    rule_signals["calculated_speed_mph"] = round(speed, 1)
                    if speed > self.max_speed_mph:
                        rule_signals["impossible_travel_flag"] = True
            except Exception:
                pass

        # 2. Check Brute Force
        if baseline_stats.get("recent_failed_logins", 0) >= self.brute_force_limit or event["auth_result"] == "FAILURE":
            if baseline_stats.get("recent_failed_logins", 0) >= self.brute_force_limit:
                rule_signals["brute_force_flag"] = True

        # 3. Check IT-OT Crossover (Honeywell Specific)
        user_domain = event.get("domain", "IT")
        asset_domain = event.get("asset_domain", "IT")
        if user_domain == "IT" and asset_domain == "OT":
            rule_signals["it_ot_crossover_flag"] = True

        # 4. Check Device Mismatch on OT
        known_devs = baseline_stats.get("known_devices", set())
        curr_dev = event.get("device_id", "")
        if asset_domain == "OT" and len(known_devs) > 0 and curr_dev not in known_devs:
            rule_signals["device_mismatch_ot_flag"] = True
            
        # 5. Check Off-Hours Access
        hour = int(event["timestamp"].split(" ")[1].split(":")[0])
        if hour in [1, 2, 3, 4]:
            rule_signals["off_hours_flag"] = True
            
        # 6. Check High Volume Exfiltration
        mb = float(event.get("mb_transferred", 0.0))
        if mb > 1500.0:
            rule_signals["exfil_flag"] = True

        return rule_signals
