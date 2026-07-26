"""
Per-Entity Behavioral Profiling Engine.
Maintains rolling baselines per entity and integrates with ColdStartManager & ConceptDriftAdapter.
Strictly enforces label leakage prevention.
"""

from collections import defaultdict
import numpy as np

class EntityBaselineProfiler:
    def __init__(self, min_events_for_baseline=10):
        self.min_events = min_events_for_baseline
        self.entity_profiles = defaultdict(self._default_profile)

    def _default_profile(self):
        return {
            "event_count": 0,
            "hours": [],
            "avg_hour": None,
            "std_hour": None,
            "mb_transferred": [],
            "avg_mb": None,
            "std_mb": None,
            "known_devices": set(),
            "known_locations": set(),
            "known_resources": set(),
            "last_seen_timestamp": None,
            "last_seen_lat": None,
            "last_seen_lon": None,
            "recent_failed_logins": 0
        }

    def get_profile(self, entity_id):
        return self.entity_profiles[entity_id]

    def update_profile(self, event, inferred_risk_score=0.0, trust_threshold=45.0):
        """
        Updates entity profile. Enforces label leakage assertion and anti-poisoning.
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before baseline updates!"

        # Ignore untrusted high-risk events to prevent baseline poisoning
        if inferred_risk_score >= trust_threshold and self.entity_profiles[event["entity_id"]]["event_count"] > 0:
            return

        entity_id = event["entity_id"]
        prof = self.entity_profiles[entity_id]

        timestamp = event["timestamp"]
        hour = int(timestamp.split(" ")[1].split(":")[0])
        mb = float(event.get("mb_transferred", 0.0))

        prof["event_count"] += 1
        prof["known_devices"].add(event["device_fingerprint"])
        prof["known_locations"].add(event["geo_location"])
        prof["known_resources"].add(event["resource_accessed"])

        if prof["avg_hour"] is None:
            prof["avg_hour"] = float(hour)
            prof["std_hour"] = 2.0
            prof["avg_mb"] = float(mb)
            prof["std_mb"] = max(20.0, float(mb) * 0.5)
        else:
            prof["avg_hour"] = 0.9 * prof["avg_hour"] + 0.1 * float(hour)
            prof["avg_mb"] = 0.9 * prof["avg_mb"] + 0.1 * float(mb)

            prof["hours"].append(hour)
            prof["mb_transferred"].append(mb)
            if len(prof["hours"]) > 5:
                prof["std_hour"] = float(np.std(prof["hours"][-30:])) + 0.5
                prof["std_mb"] = float(np.std(prof["mb_transferred"][-30:])) + 10.0

        if event.get("auth_method") != "auth_failed":
            prof["last_seen_timestamp"] = timestamp
            # Parse lat/lon from geo_location string if formatted like "Location (lat, lon)"
            geo_str = event.get("geo_location", "")
            if geo_str:
                import re
                match = re.search(r"\((-?\d+\.\d+),\s*(-?\d+\.\d+)\)", geo_str)
                if match:
                    try:
                        prof["last_seen_lat"] = float(match.group(1))
                        prof["last_seen_lon"] = float(match.group(2))
                    except Exception:
                        pass
            prof["recent_failed_logins"] = 0
        else:
            prof["recent_failed_logins"] += 1
