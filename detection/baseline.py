"""
Per-Entity Behavioral Profiling Engine.
Maintains rolling baselines per entity and delegates online EWMA adaptation logic to ConceptDriftAdapter.
Strictly enforces label leakage prevention.
"""

from collections import defaultdict
from detection.drift import ConceptDriftAdapter

class EntityBaselineProfiler:
    def __init__(self, min_events_for_baseline=10, alpha=0.1, trust_risk_threshold=45.0):
        self.min_events = min_events_for_baseline
        self.drift_adapter = ConceptDriftAdapter(alpha=alpha, trust_risk_threshold=trust_risk_threshold)
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
            "durations": [],
            "avg_duration": None,
            "std_duration": None,
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
        Delegates online EWMA baseline adaptation and anti-poisoning filtering
        to the consolidated ConceptDriftAdapter single-source-of-truth implementation.
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before baseline updates!"
        prof = self.entity_profiles[event["entity_id"]]
        return self.drift_adapter.update_profile_safe(prof, event, inferred_risk_score, trust_threshold)
