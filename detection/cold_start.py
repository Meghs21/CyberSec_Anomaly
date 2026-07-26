"""
Explicit Cold-Start Module for New Entities.
Manages cohort-level baselines based on entity_type (user, service_account, edge_device)
and blends cohort priors with personal baselines as entity interaction history accumulates.
"""

from collections import defaultdict
import numpy as np

class ColdStartManager:
    def __init__(self, min_events_threshold=10):
        self.N = min_events_threshold
        # Cohort baselines per entity_type
        self.cohort_priors = {
            "user": {
                "avg_hour": 13.0, "std_hour": 3.0, "avg_duration": 1800.0, "std_duration": 900.0,
                "avg_mb": 50.0, "std_mb": 80.0
            },
            "service_account": {
                "avg_hour": 12.0, "std_hour": 6.0, "avg_duration": 300.0, "std_duration": 150.0,
                "avg_mb": 120.0, "std_mb": 200.0
            },
            "edge_device": {
                "avg_hour": 12.0, "std_hour": 6.0, "avg_duration": 600.0, "std_duration": 300.0,
                "avg_mb": 200.0, "std_mb": 300.0
            }
        }

    def get_effective_baseline(self, entity_id, entity_type, personal_profile):
        """
        Returns blended entity baseline stats.
        Blends cohort prior with personal profile according to history count.
        """
        cohort = self.cohort_priors.get(entity_type, self.cohort_priors["user"])
        count = personal_profile.get("event_count", 0) if personal_profile else 0

        if count == 0 or not personal_profile or personal_profile.get("avg_hour") is None:
            return {
                "baseline_type": "cohort",
                "weight_personal": 0.0,
                "avg_hour": cohort["avg_hour"],
                "std_hour": cohort["std_hour"],
                "avg_duration": cohort["avg_duration"],
                "std_duration": cohort["std_duration"],
                "avg_mb": cohort["avg_mb"],
                "std_mb": cohort["std_mb"]
            }

        # Linear blend weight: 0.0 at 0 events -> 1.0 at N events
        weight = min(1.0, float(count) / float(self.N))

        avg_h = (1.0 - weight) * cohort["avg_hour"] + weight * personal_profile["avg_hour"]
        std_h = (1.0 - weight) * cohort["std_hour"] + weight * max(0.8, personal_profile.get("std_hour", 2.0))
        
        avg_mb_personal = personal_profile.get("avg_mb") if personal_profile.get("avg_mb") is not None else cohort["avg_mb"]
        avg_mb = (1.0 - weight) * cohort["avg_mb"] + weight * avg_mb_personal
        std_mb = (1.0 - weight) * cohort["std_mb"] + weight * max(10.0, personal_profile.get("std_mb", 20.0))

        effective = {
            "baseline_type": "personal" if weight >= 1.0 else "blended",
            "weight_personal": round(weight, 2),
            "avg_hour": float(avg_h),
            "std_hour": float(std_h),
            "avg_mb": float(avg_mb),
            "std_mb": float(std_mb)
        }

        if personal_profile:
            effective.update({
                "last_seen_timestamp": personal_profile.get("last_seen_timestamp"),
                "last_seen_lat": personal_profile.get("last_seen_lat"),
                "last_seen_lon": personal_profile.get("last_seen_lon"),
                "recent_failed_logins": personal_profile.get("recent_failed_logins", 0),
                "known_devices": personal_profile.get("known_devices", set()),
                "known_resources": personal_profile.get("known_resources", set())
            })

        return effective
