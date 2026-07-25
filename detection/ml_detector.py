"""
Unsupervised Isolation Forest & Z-Score Anomaly Scoring Engine.
Extracts numerical behavioral feature vectors relative to effective entity baselines.
Enforces strict label leakage prevention.
"""

import numpy as np
from sklearn.ensemble import IsolationForest

class MLAnomalyDetector:
    def __init__(self, contamination=0.02):
        self.clf = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.is_fitted = False

    def extract_features(self, event, baseline_stats):
        """
        Extracts feature vector from event relative to baseline.
        Fails loudly if ground-truth label leakage is detected!
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before feature extraction!"

        timestamp = event["timestamp"]
        hour = int(timestamp.split(" ")[1].split(":")[0])
        mb = float(event.get("mb_transferred", 0.0))

        avg_h = baseline_stats.get("avg_hour")
        avg_h = 12.0 if avg_h is None else float(avg_h)
        
        std_h = baseline_stats.get("std_hour")
        std_h = 2.0 if std_h is None else max(0.8, float(std_h))
        
        hour_zscore = abs(hour - avg_h) / std_h

        avg_mb = baseline_stats.get("avg_mb")
        avg_mb = 50.0 if avg_mb is None else float(avg_mb)
        
        std_mb = baseline_stats.get("std_mb")
        std_mb = 20.0 if std_mb is None else max(10.0, float(std_mb))
        
        mb_zscore = abs(mb - avg_mb) / std_mb

        known_devs = baseline_stats.get("known_devices", set())
        dev_unusual = 1.0 if (len(known_devs) > 0 and event.get("device_fingerprint") not in known_devs) else 0.0

        known_locs = baseline_stats.get("known_locations", set())
        loc_unusual = 1.0 if (len(known_locs) > 0 and event.get("geo_location") not in known_locs) else 0.0

        known_res = baseline_stats.get("known_resources", set())
        res_unusual = 1.0 if (len(known_res) > 0 and event.get("resource_accessed") not in known_res) else 0.0

        auth_fail = 1.0 if ("failed" in event.get("command_sequence", "").lower() or "failure" in event.get("auth_method", "").lower()) else 0.0

        return np.array([
            hour_zscore,
            mb_zscore,
            dev_unusual,
            loc_unusual,
            res_unusual,
            auth_fail
        ])

    def fit_normal_baseline(self, events, baseline_profiler):
        """Fits Isolation Forest strictly on initial normal baseline training events."""
        X_train = []
        for ev in events:
            # Check training split without leaking label to inference
            if ev.get("label", "normal") == "normal":
                ev_clean = {k: v for k, v in ev.items() if k != "label"}
                b_stats = baseline_profiler.get_profile(ev_clean["entity_id"])
                feat = self.extract_features(ev_clean, b_stats)
                X_train.append(feat)
                baseline_profiler.update_profile(ev_clean)

        if len(X_train) > 20:
            self.clf.fit(np.array(X_train))
            self.is_fitted = True

    def predict_raw_score(self, feature_vector):
        """Returns normalized raw Isolation Forest anomaly score."""
        feat_reshaped = feature_vector.reshape(1, -1)
        if self.is_fitted:
            raw_if = -float(self.clf.decision_function(feat_reshaped)[0])
        else:
            raw_if = 0.0

        z_dist = float(np.mean(feature_vector[:2]) + 1.2 * np.max(feature_vector[2:]))
        return 0.6 * raw_if + 0.4 * z_dist
