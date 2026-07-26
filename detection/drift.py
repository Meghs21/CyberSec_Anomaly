"""
Explicit Concept Drift Module for Online Baseline Adaptation.
Updates entity baselines using Exponentially Weighted Moving Averages (EWMA).
Enforces strict anti-poisoning: ground-truth 'label' is never used at inference time;
only trusted low-risk observations (risk_score < trust_threshold) update the profile.
"""

import re
import numpy as np

class ConceptDriftAdapter:
    def __init__(self, alpha=0.1, trust_risk_threshold=45.0):
        self.alpha = alpha
        self.trust_threshold = trust_risk_threshold

    def update_profile_safe(self, profile, event, inferred_risk_score=0.0, trust_threshold=None):
        """
        Updates profile using EWMA if observation is trusted (low inferred risk).
        Prevents baseline poisoning from malicious high-risk events.
        MUST NOT rely on ground-truth label!
        """
        threshold = trust_threshold if trust_threshold is not None else self.trust_threshold
        
        # Strict assertion against label leakage
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' must be stripped before inference updates!"

        # Ignore untrusted high-risk events to prevent baseline poisoning
        if inferred_risk_score >= threshold and profile.get("event_count", 0) > 0:
            return profile

        timestamp = event["timestamp"]
        hour = int(timestamp.split(" ")[1].split(":")[0])
        mb = float(event.get("mb_transferred", 0.0))
        dur = float(event.get("session_duration", 300.0))

        profile["event_count"] += 1
        profile["known_devices"].add(event["device_fingerprint"])
        profile["known_locations"].add(event["geo_location"])
        profile["known_resources"].add(event["resource_accessed"])

        # EWMA update of hour, transfer volume, and session duration
        if profile.get("avg_hour") is None:
            profile["avg_hour"] = float(hour)
            profile["std_hour"] = 2.0
        else:
            profile["avg_hour"] = (1.0 - self.alpha) * profile["avg_hour"] + self.alpha * float(hour)
            profile.setdefault("hours", []).append(hour)
            if len(profile["hours"]) > 5:
                profile["std_hour"] = float(np.std(profile["hours"][-30:])) + 0.5

        if profile.get("avg_mb") is None:
            profile["avg_mb"] = float(mb)
            profile["std_mb"] = max(20.0, float(mb) * 0.5)
        else:
            profile["avg_mb"] = (1.0 - self.alpha) * profile["avg_mb"] + self.alpha * float(mb)
            profile.setdefault("mb_transferred", []).append(mb)
            if len(profile.get("mb_transferred", [])) > 5:
                profile["std_mb"] = float(np.std(profile["mb_transferred"][-30:])) + 10.0

        if profile.get("avg_duration") is None:
            profile["avg_duration"] = float(dur)
            profile["std_duration"] = max(60.0, float(dur) * 0.3)
        else:
            profile["avg_duration"] = (1.0 - self.alpha) * profile["avg_duration"] + self.alpha * float(dur)
            profile.setdefault("durations", []).append(dur)
            if len(profile.get("durations", [])) > 5:
                profile["std_duration"] = float(np.std(profile["durations"][-30:])) + 30.0

        # Command sequence failure check for recent_failed_logins and last_seen updates
        cmd_seq = str(event.get("command_sequence", "")).lower()
        auth_meth = str(event.get("auth_method", "")).lower()
        is_failed_auth = "fail" in cmd_seq or "error" in cmd_seq or "failure" in auth_meth or "fail" in auth_meth

        if not is_failed_auth:
            profile["last_seen_timestamp"] = timestamp
            geo_str = event.get("geo_location", "")
            if geo_str:
                match = re.search(r"\((-?\d+\.\d+),\s*(-?\d+\.\d+)\)", geo_str)
                if match:
                    try:
                        profile["last_seen_lat"] = float(match.group(1))
                        profile["last_seen_lon"] = float(match.group(2))
                    except Exception:
                        pass
            profile["recent_failed_logins"] = 0
        else:
            profile["recent_failed_logins"] += 1

        return profile
