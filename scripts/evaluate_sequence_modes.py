"""
Offline Validation Script to Evaluate Sequence Model Modes: 'ngram' | 'autoencoder' | 'both'.
Compares Precision, Recall, F1, Top-1% Alert Budget metrics, and Mean Reconstruction Error.
"""

import sys
import os
import pandas as pd
import numpy as np

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.store import DataStore
from detection.sequence_model_autoencoder import SequenceAutoencoderDetector

def evaluate_all_modes():
    modes = ["ngram", "autoencoder", "both"]
    results = []

    print("\n==========================================================================================")
    print("      OFFLINE COMPARISON EVALUATION: SEQUENCE MODEL ENSEMBLE MODES ('ngram' | 'autoencoder' | 'both')")
    print("==========================================================================================\n")

    for mode in modes:
        store = DataStore(sequence_mode=mode)
        metrics = store.get_evaluation_metrics()
        top1 = metrics["top1_alert_budget"]
        
        results.append({
            "mode": mode,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "precision_at_1pct": top1["precision_at_1pct"],
            "recall_at_1pct": top1["recall_at_1pct"],
            "fpr_at_1pct": top1["fpr_at_1pct"]
        })

    df_res = pd.DataFrame(results)
    print(df_res.to_string(index=False))

    # Evaluate Mean Reconstruction Error for Autoencoder mode
    print("\n--- Autoencoder Reconstruction Error Discriminative Check ---")
    gen_store = DataStore(sequence_mode="autoencoder")
    ae_det = SequenceAutoencoderDetector()
    events_raw = gen_store.raw_df.to_dict("records")
    normal_events = [e for e in events_raw[:300] if e.get("label", "normal") == "normal"]
    ae_det.fit_normal_baseline(normal_train_split := normal_events)

    normal_mses = []
    anomaly_mses = []
    
    entity_histories = {}
    for ev in events_raw:
        ent = ev["entity_id"]
        if ent not in entity_histories:
            entity_histories[ent] = []
        ev_clean = {k: v for k, v in ev.items() if k != "label"}
        entity_histories[ent].append(ev_clean)
        
        _, mse, _ = ae_det.calculate_autoencoder_score(ev_clean, entity_histories[ent])
        if ev.get("label", "normal") == "normal":
            normal_mses.append(mse)
        elif ev.get("label") not in ["normal", "insider_drift"]:
            anomaly_mses.append(mse)

    mean_norm_mse = np.mean(normal_mses) if normal_mses else 0.0
    mean_anom_mse = np.mean(anomaly_mses) if anomaly_mses else 0.0

    print(f"Mean Normal Sequence Reconstruction MSE Loss:   {mean_norm_mse:.6f}")
    print(f"Mean Anomalous Sequence Reconstruction MSE Loss: {mean_anom_mse:.6f}")
    print(f"Reconstruction Error Ratio (Anomalous / Normal): {mean_anom_mse / (mean_norm_mse + 1e-6):.2f}x")
    print("==========================================================================================\n")

    return results

if __name__ == "__main__":
    evaluate_all_modes()
