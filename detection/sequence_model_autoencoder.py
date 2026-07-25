"""
Secondary Sequence-Aware Neural Autoencoder Model.
Implements a dense Feedforward Autoencoder over fixed-length behavioral event windows (K=5).
Uses reconstruction MSE error relative to normal training distribution as a sequence anomaly signal.
Strictly enforces ground-truth label leakage prevention.
"""

import math
import numpy as np
from sklearn.neural_network import MLPRegressor

import warnings
warnings.filterwarnings("ignore", category=UserWarning)

FEATURE_DIM = 6
WINDOW_K = 5
INPUT_DIM = FEATURE_DIM * WINDOW_K

class SequenceAutoencoderDetector:
    def __init__(self, hidden_layer_sizes=(16, 8, 16), max_iter=100, random_state=42):
        self.window_k = WINDOW_K
        self.feature_dim = FEATURE_DIM
        self.input_dim = INPUT_DIM
        
        # Scikit-Learn MLPRegressor acts as Autoencoder when target Y == input X
        self.model = MLPRegressor(
            hidden_layer_sizes=hidden_layer_sizes,
            activation='relu',
            solver='adam',
            max_iter=max_iter,
            random_state=random_state,
            warm_start=False
        )
        self.is_fitted = False
        self.mean_train_mse = 0.01
        self.std_train_mse = 0.02
        self.resource_map = {}

    def _extract_event_vector(self, event):
        """Extracts fixed-size numeric feature vector for a single event."""
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before feature extraction!"
        
        ts = event.get("timestamp", "2026-07-25 12:00:00")
        hour = int(ts.split(" ")[1].split(":")[0]) if " " in ts else 12
        sin_h = math.sin(2 * math.pi * hour / 24.0)
        cos_h = math.cos(2 * math.pi * hour / 24.0)
        
        dur = float(event.get("session_duration", 300))
        dur_norm = min(1.0, dur / 3600.0)
        
        mb = float(event.get("mb_transferred", 50.0))
        mb_norm = min(1.0, mb / 500.0)
        
        res = event.get("resource_accessed", "unknown")
        if res not in self.resource_map:
            self.resource_map[res] = len(self.resource_map) % 15
        res_idx = self.resource_map[res] / 15.0
        
        cmd_seq = event.get("command_sequence", "").lower()
        auth_fail = 1.0 if ("fail" in cmd_seq or "error" in cmd_seq) else 0.0
        
        return [sin_h, cos_h, dur_norm, mb_norm, res_idx, auth_fail]

    def _build_window_matrix(self, events):
        """Builds flattened window matrix (N_windows, INPUT_DIM)."""
        X = []
        vecs = [self._extract_event_vector(e) for e in events]
        
        if len(vecs) < self.window_k:
            # Pad with zeros if fewer than K events
            pad = [[0.0]*self.feature_dim] * (self.window_k - len(vecs))
            vecs = pad + vecs

        for i in range(len(vecs) - self.window_k + 1):
            window = vecs[i : i + self.window_k]
            flat_win = [val for evt in window for val in evt]
            X.append(flat_win)

        return np.array(X)

    def fit_normal_baseline(self, events):
        """Fits neural autoencoder on normal baseline event windows."""
        normal_events = [e for e in events if "label" not in e or e.get("label") == "normal"]
        if len(normal_events) < self.window_k + 5:
            return

        events_clean = [{k: v for k, v in e.items() if k != "label"} for e in normal_events]
        X_train = self._build_window_matrix(events_clean)

        if len(X_train) > 5:
            # Train Autoencoder to predict X from X
            self.model.fit(X_train, X_train)
            self.is_fitted = True
            
            # Compute baseline reconstruction errors on normal training set
            X_pred = self.model.predict(X_train)
            mses = np.mean((X_train - X_pred)**2, axis=1)
            self.mean_train_mse = float(np.mean(mses))
            self.std_train_mse = float(np.std(mses)) + 1e-4

    def calculate_autoencoder_score(self, event, entity_history_events=None):
        """
        Calculates autoencoder reconstruction error score in [0.0, 1.0] and raw MSE.
        Fails loudly if ground-truth label leakage is detected!
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' field must be removed before autoencoder scoring!"
        
        if not self.is_fitted:
            return 0.0, 0.0

        history = entity_history_events if entity_history_events else [event]
        recent_events = history[-self.window_k:] if len(history) >= self.window_k else history
        
        # Ensure event is at end of window
        if not recent_events or recent_events[-1] != event:
            recent_events = recent_events + [event]
            
        recent_clean = [{k: v for k, v in e.items() if k != "label"} for e in recent_events]
        X_win = self._build_window_matrix(recent_clean)
        
        if len(X_win) == 0:
            return 0.0, 0.0
            
        target_win = X_win[-1:]  # Last window ending with current event
        pred_win = self.model.predict(target_win)
        mse = float(np.mean((target_win - pred_win)**2))
        
        # Z-score relative to normal baseline reconstruction error distribution
        z = (mse - self.mean_train_mse) / self.std_train_mse
        normalized_score = min(1.0, max(0.0, z / 4.0))
        return round(normalized_score, 3), mse
