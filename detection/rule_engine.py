"""
Rule-Assist Engine for Official Anomaly Behaviors.
Evaluates deterministic physics (impossible travel geo-velocity), brute force windows,
credential stuffing (password spraying), device spoofing, and lateral movement.
Enforces strict label leakage prevention.
"""

from datetime import datetime
import math
from collections import defaultdict

def haversine_miles(lat1, lon1, lat2, lon2):
    R = 3958.8
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

class RuleAssistEngine:
    def __init__(self, max_speed_mph=550.0):
        self.max_speed_mph = max_speed_mph
        # Track recent source IP entity targets for credential stuffing detection
        self.ip_target_history = defaultdict(set)
        self.ip_failure_counts = defaultdict(int)

    def evaluate_rules(self, event, baseline_stats):
        """
        Evaluates rules against event and entity baseline stats.
        Fails loudly if ground-truth label leakage occurs.
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before rule evaluation!"

        rule_signals = {
            "impossible_travel_flag": False,
            "calculated_speed_mph": 0.0,
            "distance_miles": 0.0,
            "brute_force_flag": False,
            "credential_stuffing_flag": False,
            "device_spoofing_flag": False,
            "lateral_movement_flag": False,
            "low_slow_exfil_flag": False,
            "off_hours_flag": False
        }

        # 1. Impossible Travel (Geo-velocity check)
        last_ts = baseline_stats.get("last_seen_timestamp")
        last_lat = baseline_stats.get("last_seen_lat")
        last_lon = baseline_stats.get("last_seen_lon")

        geo_str = event.get("geo_location", "")
        curr_lat, curr_lon = None, None
        if geo_str:
            import re
            match = re.search(r"\((-?\d+\.\d+),\s*(-?\d+\.\d+)\)", geo_str)
            if match:
                try:
                    curr_lat = float(match.group(1))
                    curr_lon = float(match.group(2))
                except Exception:
                    pass

        if last_ts and last_lat is not None and last_lon is not None and curr_lat is not None and curr_lon is not None:
            try:
                curr_dt = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S")
                last_dt = datetime.strptime(last_ts, "%Y-%m-%d %H:%M:%S")
                hours_diff = (curr_dt - last_dt).total_seconds() / 3600.0
                dist = haversine_miles(last_lat, last_lon, curr_lat, curr_lon)

                if hours_diff > 0.001 and dist > 100.0:
                    speed = dist / hours_diff
                    rule_signals["distance_miles"] = round(dist, 1)
                    rule_signals["calculated_speed_mph"] = round(speed, 1)
                    if speed > self.max_speed_mph:
                        rule_signals["impossible_travel_flag"] = True
            except Exception:
                pass

        # 2. Brute Force & Credential Stuffing
        src_ip = event.get("source_ip", "")
        entity_id = event["entity_id"]
        auth_method = event.get("auth_method", "")
        cmd_seq = event.get("command_sequence", "")

        if "auth_failed" in cmd_seq or "auth_failure" in cmd_seq or "fail" in cmd_seq.lower() or "failure" in auth_method.lower():
            self.ip_failure_counts[src_ip] += 1
            self.ip_target_history[src_ip].add(entity_id)

        if baseline_stats.get("recent_failed_logins", 0) >= 5:
            rule_signals["brute_force_flag"] = True

        # Credential Stuffing: single IP targeting many entities with high failure count
        if len(self.ip_target_history[src_ip]) >= 4 and self.ip_failure_counts[src_ip] >= 4:
            rule_signals["credential_stuffing_flag"] = True

        # 3. Device Spoofing (Fingerprint mismatch relative to entity baseline)
        known_devs = baseline_stats.get("known_devices", set())
        curr_dev = event.get("device_fingerprint", "")
        if len(known_devs) > 0 and curr_dev not in known_devs:
            # If OS/MAC in device_fingerprint is completely distinct
            rule_signals["device_spoofing_flag"] = True

        # 4. Lateral Movement (Resource novelty & IT-to-OT crossover)
        known_res = baseline_stats.get("known_resources", set())
        curr_res = event.get("resource_accessed", "")
        user_domain = event.get("domain", "IT")
        if (len(known_res) > 0 and curr_res not in known_res) or (user_domain == "IT" and ("BMS" in curr_res or "Honeywell_Forge" in curr_res or "SCADA" in curr_res)):
            rule_signals["lateral_movement_flag"] = True

        # 5. Low-and-Slow Exfiltration & Off-Hours
        hour = int(event["timestamp"].split(" ")[1].split(":")[0])
        if hour in [1, 2, 3, 4]:
            rule_signals["off_hours_flag"] = True

        mb = float(event.get("mb_transferred", 0.0))
        if rule_signals["off_hours_flag"] and 10.0 <= mb <= 300.0 and "exfil" in cmd_seq.lower():
            rule_signals["low_slow_exfil_flag"] = True

        return rule_signals
