"""
Per-Entity Behavioral Profiling Engine.
Maintains rolling baselines per user/device to handle cold-start and concept drift.
"""

from collections import defaultdict
import numpy as np

class EntityBaselineProfiler:
    def __init__(self, min_events_for_baseline=10, decay_alpha=0.1):
        self.min_events = min_events_for_baseline
        self.alpha = decay_alpha  # Exponential weight decay for rolling updates
        self.user_profiles = defaultdict(self._default_profile)
        
        # Domain priors for cold-start (users with < min_events)
        self.domain_priors = {
            "IT": {"avg_hour": 13.0, "std_hour": 3.0, "avg_mb": 50.0, "std_mb": 100.0},
            "OT": {"avg_hour": 12.0, "std_hour": 4.0, "avg_mb": 80.0, "std_mb": 150.0}
        }

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
            "last_seen_timestamp": None,
            "last_seen_lat": None,
            "last_seen_lon": None,
            "recent_failed_logins": 0
        }

    def update_profile(self, event):
        user_id = event["user_id"]
        prof = self.user_profiles[user_id]
        
        # Parse timestamp hour
        timestamp = event["timestamp"]
        hour = int(timestamp.split(" ")[1].split(":")[0])
        mb = float(event["mb_transferred"])
        
        prof["event_count"] += 1
        prof["known_devices"].add(event["device_id"])
        prof["known_locations"].add(event["location_name"])
        
        # Update rolling statistics (handling concept drift via EWMA after min_events)
        if prof["avg_hour"] is None:
            prof["avg_hour"] = hour
            prof["std_hour"] = 2.0
            prof["avg_mb"] = mb
            prof["std_mb"] = max(20.0, mb * 0.5)
        else:
            prof["avg_hour"] = (1 - self.alpha) * prof["avg_hour"] + self.alpha * hour
            prof["avg_mb"] = (1 - self.alpha) * prof["avg_mb"] + self.alpha * mb
            
            # Simple std dev estimation
            prof["hours"].append(hour)
            prof["mb_transferred"].append(mb)
            if len(prof["hours"]) > 5:
                prof["std_hour"] = float(np.std(prof["hours"][-30:])) + 0.5
                prof["std_mb"] = float(np.std(prof["mb_transferred"][-30:])) + 10.0
                
        # Update last seen location/time
        if event["auth_result"] == "SUCCESS":
            prof["last_seen_timestamp"] = timestamp
            prof["last_seen_lat"] = float(event["latitude"])
            prof["last_seen_lon"] = float(event["longitude"])
            prof["recent_failed_logins"] = 0
        else:
            prof["recent_failed_logins"] += 1

    def get_baseline_stats(self, user_id, user_domain="IT"):
        """Returns entity profile if mature, else returns domain priors for cold-start."""
        prof = self.user_profiles.get(user_id)
        if not prof or prof["event_count"] < self.min_events:
            # Cold-start fallback to role domain priors
            prior = self.domain_priors.get(user_domain, self.domain_priors["IT"])
            return {
                "is_cold_start": True,
                "avg_hour": prior["avg_hour"],
                "std_hour": prior["std_hour"],
                "avg_mb": prior["avg_mb"],
                "std_mb": prior["std_mb"],
                "known_devices": prof["known_devices"] if prof else set(),
                "known_locations": prof["known_locations"] if prof else set(),
                "last_seen_timestamp": prof["last_seen_timestamp"] if prof else None,
                "last_seen_lat": prof["last_seen_lat"] if prof else None,
                "last_seen_lon": prof["last_seen_lon"] if prof else None,
                "recent_failed_logins": prof["recent_failed_logins"] if prof else 0
            }
        
        return {
            "is_cold_start": False,
            "avg_hour": prof["avg_hour"],
            "std_hour": max(0.8, prof["std_hour"]),
            "avg_mb": prof["avg_mb"],
            "std_mb": max(10.0, prof["std_mb"]),
            "known_devices": prof["known_devices"],
            "known_locations": prof["known_locations"],
            "last_seen_timestamp": prof["last_seen_timestamp"],
            "last_seen_lat": prof["last_seen_lat"],
            "last_seen_lon": prof["last_seen_lon"],
            "recent_failed_logins": prof["recent_failed_logins"]
        }
