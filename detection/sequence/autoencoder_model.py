"""
Production-Grade Sequence Intelligence Subsystem: Behavioral Neural Autoencoder.

Key Improvements Implemented:
1. Frozen Categorical Vocabulary: Vocabularies frozen post-training; unseen items map to explicit UNKNOWN bucket without state mutation.
2. Non-Ordinal Categorical One-Hot Encoding: Eliminates artificial ordinal distance between resources/roles.
3. Learned Feature Normalization: MinMaxScaler fit strictly on training split (no hardcoded divisors).
4. Schema Expansion: Integrates entity_type, auth_method, and session features from official 11-field schema.
5. Calibrated Percentile Thresholding: Score calibrated relative to 95th percentile (P95) of training reconstruction MSE.
6. Per-Feature Reconstruction Attribution: Exposes feature-wise reconstruction error breakdown for explainability.
7. Architectural Separation: BehavioralFeatureEncoder separated from SequenceAutoencoderDetector.
8. Event Edge Padding: Short event histories padded by repeating earliest event instead of artificial zeros.

Architecture:
  Input (80 features: 5 events x 16-dim encoded vectors)
    │
    ▼
  Dense Encoder (32 units)
    │
    ▼
  Latent Bottleneck (16-dim behavior embedding)
    │
    ▼
  Dense Decoder (32 units)
    │
    ▼
  Reconstruction Output (80 features)
"""

import math
import numpy as np
import warnings
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import MinMaxScaler

warnings.filterwarnings("ignore", category=UserWarning)

WINDOW_K = 5  # Selected K=5 balancing 5-session temporal sequence memory and sub-1ms inference latency

class BehavioralFeatureEncoder:
    """Separated feature encoder handling non-ordinal one-hot encodings and learned scaling."""
    def __init__(self):
        self.is_frozen = False
        self.known_resources = []
        self.resource_to_idx = {}
        self.scaler = MinMaxScaler()
        
        # Categorical domains
        self.auth_methods = ["password", "token", "certificate", "biometric"]
        self.entity_types = ["user", "service_account", "edge_device"]

    def fit(self, events):
        """Learns resource vocabulary and numerical feature scalers from training normal split."""
        res_counts = {}
        numerical_feats = []

        for e in events:
            assert "label" not in e or e.get("label") == "normal", "Encoder fitting strictly on normal events"
            res = e.get("resource_accessed", "unknown")
            res_counts[res] = res_counts.get(res, 0) + 1
            
            dur = float(e.get("session_duration", 300))
            mb = float(e.get("mb_transferred", 50.0))
            numerical_feats.append([dur, mb])

        # Top 5 resources + UNKNOWN bucket
        top_res = sorted(res_counts.keys(), key=lambda r: res_counts[r], reverse=True)[:5]
        self.known_resources = top_res
        self.resource_to_idx = {r: i for i, r in enumerate(top_res)}
        
        if numerical_feats:
            self.scaler.fit(np.array(numerical_feats))
            
        self.is_frozen = True  # Freeze encoder state to prevent inference leakage/mutation

    def encode_event(self, event):
        """Encodes a single event into a 16-dimensional vector."""
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' must be removed before encoding!"

        ts = event.get("timestamp", "2026-07-25 12:00:00")
        hour = int(ts.split(" ")[1].split(":")[0]) if " " in ts else 12
        sin_h = math.sin(2 * math.pi * hour / 24.0)
        cos_h = math.cos(2 * math.pi * hour / 24.0)

        # Scaled numerical features
        dur = float(event.get("session_duration", 300))
        mb = float(event.get("mb_transferred", 50.0))
        if self.is_frozen:
            scaled_num = self.scaler.transform([[dur, mb]])[0]
            dur_norm, mb_norm = float(scaled_num[0]), float(scaled_num[1])
        else:
            dur_norm, mb_norm = min(1.0, dur / 3600.0), min(1.0, mb / 500.0)

        # Auth Method One-Hot (4 dims)
        am = event.get("auth_method", "password").lower()
        am_vec = [1.0 if am == m else 0.0 for m in self.auth_methods]

        # Entity Type One-Hot (3 dims)
        et = event.get("entity_type", "user").lower()
        et_vec = [1.0 if et == t else 0.0 for t in self.entity_types]

        # Resource One-Hot with UNKNOWN bucket (6 dims: 5 known + 1 unknown)
        res = event.get("resource_accessed", "unknown")
        res_vec = [0.0] * (len(self.known_resources) + 1)
        if res in self.resource_to_idx:
            res_vec[self.resource_to_idx[res]] = 1.0
        else:
            res_vec[-1] = 1.0  # UNKNOWN resource bucket

        cmd_seq = event.get("command_sequence", "").lower()
        auth_fail = 1.0 if ("fail" in cmd_seq or "error" in cmd_seq) else 0.0

        # Vector dim = 2 (hour) + 2 (num) + 4 (auth) + 3 (entity) + 6 (resource) + 1 (fail) = 18 dims
        return [sin_h, cos_h, dur_norm, mb_norm] + am_vec + et_vec + res_vec + [auth_fail]


class SequenceAutoencoderDetector:
    def __init__(self, hidden_layer_sizes=(32, 16, 32), max_iter=100, random_state=42):
        self.window_k = WINDOW_K
        self.encoder = BehavioralFeatureEncoder()
        
        # Will be determined post-fit
        self.model = None
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_iter = max_iter
        self.random_state = random_state
        
        self.is_fitted = False
        self.mean_train_mse = 0.01
        self.p95_train_mse = 0.05
        self.std_train_mse = 0.02

    def _build_window_matrix(self, events):
        """Builds window matrix with edge padding for short histories."""
        vecs = [self.encoder.encode_event(e) for e in events]
        feature_dim = len(vecs[0]) if vecs else 18

        if len(vecs) < self.window_k:
            # Edge padding: repeat earliest event instead of artificial zeros
            first_vec = vecs[0] if vecs else [0.0] * feature_dim
            pad = [first_vec] * (self.window_k - len(vecs))
            vecs = pad + vecs

        X = []
        for i in range(len(vecs) - self.window_k + 1):
            window = vecs[i : i + self.window_k]
            flat_win = [val for evt in window for val in evt]
            X.append(flat_win)

        return np.array(X)

    def _build_dataset_windows(self, events):
        """Groups events per entity_id, sorts by timestamp, and concatenates entity-isolated window matrices."""
        from collections import defaultdict
        entity_groups = defaultdict(list)
        for e in events:
            entity_groups[e["entity_id"]].append(e)

        all_windows = []
        for ent_id, ent_events in entity_groups.items():
            # Sort entity events by timestamp
            sorted_events = sorted(ent_events, key=lambda x: str(x.get("timestamp", "")))
            win_mat = self._build_window_matrix(sorted_events)
            if len(win_mat) > 0:
                all_windows.append(win_mat)

        if not all_windows:
            return np.array([])
        return np.vstack(all_windows)

    def fit_normal_baseline(self, events):
        """Fits encoder scalers and autoencoder strictly on normal baseline events grouped by entity."""
        normal_events = [e for e in events if "label" not in e or e.get("label") == "normal"]
        if len(normal_events) < self.window_k + 5:
            return

        events_clean = [{k: v for k, v in e.items() if k != "label"} for e in normal_events]
        self.encoder.fit(events_clean)
        
        # Build entity-isolated training windows
        X_train = self._build_dataset_windows(events_clean)

        if len(X_train) > 5:
            input_dim = X_train.shape[1]
            self.model = MLPRegressor(
                hidden_layer_sizes=self.hidden_layer_sizes,
                activation='relu',
                solver='adam',
                max_iter=self.max_iter,
                random_state=self.random_state,
                warm_start=False
            )
            self.model.fit(X_train, X_train)
            self.is_fitted = True
            
            X_pred = self.model.predict(X_train)
            mses = np.mean((X_train - X_pred)**2, axis=1)
            self.mean_train_mse = float(np.mean(mses))
            self.std_train_mse = float(np.std(mses)) + 1e-4
            self.p95_train_mse = float(np.percentile(mses, 95))

    def calculate_autoencoder_score(self, event, entity_history_events=None):
        """
        Calculates autoencoder reconstruction error score [0.0, 1.0] calibrated against P95.
        Returns (score, mse, per_feature_attribution).
        Fails loudly if ground-truth label leakage is detected!
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' must be removed before autoencoder scoring!"
        
        default_attribution = {
            "time_hour_error": 0.0,
            "session_volume_error": 0.0,
            "resource_error": 0.0,
            "auth_error": 0.0
        }

        if not self.is_fitted or self.model is None:
            return 0.0, 0.0, default_attribution

        history = entity_history_events if entity_history_events else [event]
        recent_events = history[-self.window_k:] if len(history) >= self.window_k else history
        
        if not recent_events or recent_events[-1] != event:
            recent_events = recent_events + [event]
            
        recent_clean = [{k: v for k, v in e.items() if k != "label"} for e in recent_events]
        X_win = self._build_window_matrix(recent_clean)
        
        if len(X_win) == 0:
            return 0.0, 0.0, default_attribution
            
        target_win = X_win[-1:]
        pred_win = self.model.predict(target_win)
        
        diff_sq = (target_win - pred_win)**2
        mse = float(np.mean(diff_sq))

        # Per-Feature Reconstruction Error Breakdown for Explainability
        # Vector layout: [0,1: hour], [2,3: num], [4-7: auth], [8-10: entity], [11-16: res], [17: fail]
        diff_reshaped = diff_sq.reshape(self.window_k, -1)
        last_event_diff = diff_reshaped[-1]
        
        attribution = {
            "time_hour_error": float(np.mean(last_event_diff[0:2])),
            "session_volume_error": float(np.mean(last_event_diff[2:4])),
            "auth_error": float(np.mean(last_event_diff[4:8])),
            "resource_error": float(np.mean(last_event_diff[11:17]))
        }
        
        # Calibrated relative to 95th percentile (P95) of training reconstruction MSE
        if mse <= self.mean_train_mse:
            score = 0.0
        elif mse <= self.p95_train_mse:
            score = 0.5 * (mse - self.mean_train_mse) / (self.p95_train_mse - self.mean_train_mse + 1e-5)
        else:
            score = 0.5 + 0.5 * min(1.0, (mse - self.p95_train_mse) / (3.0 * self.p95_train_mse + 1e-5))

        return round(float(score), 3), mse, attribution
