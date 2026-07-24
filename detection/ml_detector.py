"""
Unsupervised ML Detection Engine using Isolation Forest & Entity Z-Score Feature Matrix.
Trained strictly on normal behavioral features (semi-supervised framing).
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

class MLAnomalyDetector:
    def __init__(self, contamination=0.04):
        self.clf = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.is_fitted = False

    def extract_features(self, event, baseline_stats):
        """
        Extracts numerical behavioral deviation features per event relative to baseline.
        """
        timestamp = event["timestamp"]
        hour = int(timestamp.split(" ")[1].split(":")[0])
        mb = float(event["mb_transferred"])
        
        # Calculate Z-score for hour deviation
        avg_h = baseline_stats["avg_hour"]
        std_h = baseline_stats["std_hour"]
        hour_zscore = abs(hour - avg_h) / std_h
        
        # Calculate Z-score for transfer size deviation
        avg_mb = baseline_stats["avg_mb"]
        std_mb = baseline_stats["std_mb"]
        mb_zscore = abs(mb - avg_mb) / std_mb
        
        # Device unusualness (1 if new device, 0 if known)
        known_devs = baseline_stats.get("known_devices", set())
        device_unusual = 1.0 if (len(known_devs) > 0 and event["device_id"] not in known_devs) else 0.0
        
        # Location unusualness
        known_locs = baseline_stats.get("known_locations", set())
        loc_unusual = 1.0 if (len(known_locs) > 0 and event["location_name"] not in known_locs) else 0.0
        
        # Domain crossover indicator (IT user accessing OT asset)
        it_ot_cross = 1.0 if (event.get("domain") == "IT" and event.get("asset_domain") == "OT") else 0.0
        
        # Auth failure indicator
        auth_fail = 1.0 if event.get("auth_result") == "FAILURE" else 0.0

        return np.array([
            hour_zscore,
            mb_zscore,
            device_unusual,
            loc_unusual,
            it_ot_cross,
            auth_fail
        ])

    def fit_normal_baseline(self, events, baseline_profiler):
        """Fits Isolation Forest strictly on normal historical events."""
        X_train = []
        for ev in events:
            if not ev.get("is_attack", False):
                b_stats = baseline_profiler.get_baseline_stats(ev["user_id"], ev.get("domain", "IT"))
                feat = self.extract_features(ev, b_stats)
                X_train.append(feat)
                baseline_profiler.update_profile(ev)
                
        if len(X_train) > 20:
            X_mat = np.array(X_train)
            self.clf.fit(X_mat)
            self.is_fitted = True

    def predict_raw_score(self, feature_vector):
        """
        Computes continuous raw anomaly score (higher = more anomalous).
        Converts Isolation Forest decision_function into positive continuous score.
        """
        feat_reshaped = feature_vector.reshape(1, -1)
        if self.is_fitted:
            # IsolationForest decision_function returns negative for anomalies, positive for normal
            raw_if_score = -float(self.clf.decision_function(feat_reshaped)[0])
        else:
            raw_if_score = 0.0

        # Heuristic baseline distance (max of feature z-scores)
        z_distance = float(np.mean(feature_vector[:2]) + 1.5 * np.max(feature_vector[2:]))
        
        # Combined ML score
        combined_score = 0.6 * raw_if_score + 0.4 * z_distance
        return combined_score
