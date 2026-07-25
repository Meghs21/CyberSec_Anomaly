"""
Explicit Concept Drift Module for Online Baseline Adaptation.
Updates entity baselines using Exponentially Weighted Moving Averages (EWMA).
Enforces strict anti-poisoning: ground-truth 'label' is never used at inference time;
only trusted low-risk observations (risk_score < trust_threshold) update the profile.
"""

import numpy as np

class ConceptDriftAdapter:
    def __init__(self, alpha=0.1, trust_risk_threshold=45.0):
        self.alpha = alpha
        self.trust_threshold = trust_risk_threshold

    def update_profile_safe(self, profile, event, inferred_risk_score):
        """
        Updates profile using EWMA if observation is trusted (low inferred risk).
        Prevents baseline poisoning from malicious high-risk events.
        MUST NOT rely on ground-truth label!
        """
        # Strict assertion against label leakage
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' must be stripped before inference updates!"

        # Ignore untrusted high-risk events to prevent baseline poisoning
        if inferred_risk_score >= self.trust_threshold:
            return profile

        timestamp = event["timestamp"]
        hour = int(timestamp.split(" ")[1].split(":")[0])
        mb = float(event.get("mb_transferred", 0.0))

        profile["event_count"] += 1
        profile["known_devices"].add(event["device_fingerprint"])
        profile["known_locations"].add(event["geo_location"])
        profile["known_resources"].add(event["resource_accessed"])

        # EWMA update of hour and transfer volume
        if profile["avg_hour"] is None:
            profile["avg_hour"] = float(hour)
            profile["std_hour"] = 2.0
            profile["avg_mb"] = float(mb)
            profile["std_mb"] = max(20.0, float(mb) * 0.5)
        else:
            profile["avg_hour"] = (1 - self.alpha) * profile["avg_hour"] + self.alpha * float(hour)
            profile["avg_mb"] = (1 - self.alpha) * profile["avg_mb"] + self.alpha * float(mb)

            profile["hours"].append(hour)
            profile["mb_transferred"].append(mb)
            if len(profile["hours"]) > 5:
                profile["std_hour"] = float(np.std(profile["hours"][-30:])) + 0.5
                profile["std_mb"] = float(np.std(profile["mb_transferred"][-30:])) + 10.0

        if event.get("auth_method") != "auth_failed":
            profile["last_seen_timestamp"] = timestamp

        return profile
