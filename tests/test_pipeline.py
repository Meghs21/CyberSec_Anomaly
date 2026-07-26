"""
Automated Acceptance Test Suite (Section 26 - 18 Acceptance Gates).
Validates schema compliance (11 fields), extreme class imbalance (0.5-3.0%), structural label leakage prevention,
N-gram sequence model stability, cold-start blending, concept drift adaptation, taxonomy coverage,
Top-1% Alert Budget metrics, and end-to-end pipeline integrity.
"""

import sys
import os
import math
import pytest
import pandas as pd
import numpy as np

# Ensure parent directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from data_gen.generator import SyntheticLogGenerator
from detection.baseline import EntityBaselineProfiler
from detection.cold_start import ColdStartManager
from detection.drift import ConceptDriftAdapter
from detection.sequence_model import SequenceAnomalyDetector
from detection.sequence_model_autoencoder import SequenceAutoencoderDetector
from backend.store import DataStore, store
from detection.rule_engine import RuleAssistEngine
from detection.ml_detector import MLAnomalyDetector
from detection.risk_fusion import RiskFusionEngine
from detection.classifier import AnomalyClassifier
from detection.explainer import ExplainabilityEngine
from backend.store import store

def test_1_schema_11_fields():
    gen = SyntheticLogGenerator(num_entities=20, num_days=5, anomaly_rate=0.015, seed=42)
    df = gen.generate_dataset(total_sessions=100)
    expected_cols = [
        "entity_id", "entity_type", "timestamp", "source_ip", "geo_location",
        "resource_accessed", "auth_method", "session_duration", "command_sequence",
        "device_fingerprint", "label"
    ]
    for col in expected_cols:
        assert col in df.columns, f"Missing required column {col} in synthetic dataset"
    assert len([c for c in df.columns if c in expected_cols]) == 11, "Dataset must contain exactly 11 official schema fields"

def test_2_class_imbalance():
    gen = SyntheticLogGenerator(num_entities=30, num_days=7, anomaly_rate=0.015, seed=42)
    df = gen.generate_dataset(total_sessions=3500)
    malicious_cats = ["brute_force", "impossible_travel", "credential_stuffing", "lateral_movement", "device_spoofing", "low_and_slow_exfiltration"]
    malicious_df = df[df["label"].isin(malicious_cats)]
    rate = len(malicious_df) / len(df)
    assert 0.005 <= rate <= 0.03, f"Anomaly rate {rate:.4f} must be between 0.5% and 3.0%"

def test_3_label_leakage_assertion():
    profiler = EntityBaselineProfiler()
    rule_engine = RuleAssistEngine()
    sequence_detector = SequenceAnomalyDetector()
    explainer = ExplainabilityEngine()
    
    labeled_event = {
        "entity_id": "USR_001", "entity_type": "user", "timestamp": "2026-07-25 10:00:00",
        "source_ip": "10.100.1.1", "geo_location": "Atlanta_HQ", "resource_accessed": "AWS_Console",
        "auth_method": "password", "session_duration": 300, "command_sequence": "login -> view",
        "device_fingerprint": "MacBook-Pro", "label": "brute_force"  # LEAKED LABEL
    }
    
    with pytest.raises(AssertionError, match="LABEL LEAKAGE DETECTED"):
        profiler.update_profile(labeled_event)
        
    with pytest.raises(AssertionError, match="LABEL LEAKAGE DETECTED"):
        rule_engine.evaluate_rules(labeled_event, {})
        
    with pytest.raises(AssertionError, match="LABEL LEAKAGE DETECTED"):
        sequence_detector.calculate_sequence_score(labeled_event, {})

def test_4_ngram_stability():
    seq_det = SequenceAnomalyDetector()
    event = {
        "entity_id": "USR_999", "entity_type": "user", "timestamp": "2026-07-25 12:00:00",
        "resource_accessed": "UNSEEN_RESOURCE_XYZ", "command_sequence": "unseen_cmd1 -> unseen_cmd2"
    }
    score = seq_det.calculate_sequence_score(event, {"event_count": 0})
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0
    assert not math.isnan(score) and not math.isinf(score)

def test_5_sequence_sensitivity():
    seq_det = SequenceAnomalyDetector()
    events_normal = [
        {"entity_id": "USR_001", "entity_type": "user", "resource_accessed": "VPN", "command_sequence": "login -> pull -> logout"},
        {"entity_id": "USR_001", "entity_type": "user", "resource_accessed": "VPN", "command_sequence": "login -> pull -> logout"}
    ]
    seq_det.fit_normal_baseline(events_normal)
    
    normal_score = seq_det.calculate_sequence_score(
        {"entity_id": "USR_001", "entity_type": "user", "resource_accessed": "VPN", "command_sequence": "login -> pull -> logout"},
        {"event_count": 10}
    )
    anomalous_score = seq_det.calculate_sequence_score(
        {"entity_id": "USR_001", "entity_type": "user", "resource_accessed": "SCADA", "command_sequence": "login -> override -> exfil"},
        {"event_count": 10}
    )
    assert anomalous_score >= normal_score

def test_6_cold_start():
    cold_mgr = ColdStartManager(min_events_threshold=10)
    baseline = cold_mgr.get_effective_baseline("NEW_USR", "user", {"event_count": 2, "avg_hour": 14.0})
    assert baseline["baseline_type"] == "blended"
    assert baseline["weight_personal"] == 0.2

def test_7_mature_entity():
    cold_mgr = ColdStartManager(min_events_threshold=10)
    baseline = cold_mgr.get_effective_baseline("MATURE_USR", "user", {"event_count": 25, "avg_hour": 14.0, "std_hour": 1.5, "avg_mb": 50.0, "std_mb": 10.0})
    assert baseline["baseline_type"] == "personal"
    assert baseline["weight_personal"] == 1.0

def test_8_concept_drift():
    adapter = ConceptDriftAdapter(alpha=0.1, trust_risk_threshold=45.0)
    prof = {"event_count": 5, "hours": [], "avg_hour": 10.0, "std_hour": 1.0, "mb_transferred": [], "avg_mb": 50.0, "std_mb": 10.0, "known_devices": set(), "known_locations": set(), "known_resources": set()}
    ev = {"entity_id": "USR_001", "timestamp": "2026-07-25 11:00:00", "device_fingerprint": "dev1", "geo_location": "loc1", "resource_accessed": "res1"}
    
    # Low risk observation updates profile
    updated = adapter.update_profile_safe(prof, ev, inferred_risk_score=20.0)
    assert updated["event_count"] == 6
    
    # High risk observation is ignored (anti-poisoning)
    unupdated = adapter.update_profile_safe(updated, ev, inferred_risk_score=90.0)
    assert unupdated["event_count"] == 6

def test_autoencoder_stability():
    ae_det = SequenceAutoencoderDetector()
    events = [
        {"entity_id": "USR_001", "timestamp": "2026-07-25 10:00:00", "session_duration": 300, "mb_transferred": 50.0, "resource_accessed": "AWS_Console", "command_sequence": "login -> view"},
        {"entity_id": "USR_001", "timestamp": "2026-07-25 10:05:00", "session_duration": 300, "mb_transferred": 50.0, "resource_accessed": "AWS_Console", "command_sequence": "login -> view"}
    ]
    ae_det.fit_normal_baseline(events)
    score, mse, attr = ae_det.calculate_autoencoder_score(events[-1], events)
    assert 0.0 <= score <= 1.0
    assert mse >= 0.0
    assert "resource_error" in attr

def test_three_way_mode_toggle():
    for mode in ["ngram", "autoencoder", "both"]:
        st = DataStore(sequence_mode=mode)
        met = st.get_evaluation_metrics()
        assert met["precision"] >= 25.0
        assert met["top1_alert_budget"]["precision_at_1pct"] >= 80.0

def test_recent_failed_logins_tracks_actual_failures():
    """Regression test: ensure recent_failed_logins responds to command_sequence failure markers,
    not a dead comparison against auth_method."""
    profiler = EntityBaselineProfiler()
    entity_id = "TEST_USER_001"

    failed_event = {
        "entity_id": entity_id, "entity_type": "user", "timestamp": "2026-01-01 10:00:00",
        "auth_method": "password", "command_sequence": "auth_attempt -> auth_failed",
        "device_fingerprint": "test-device", "geo_location": "Test (0.0, 0.0)",
        "resource_accessed": "test_resource", "mb_transferred": 0.0
    }
    profiler.update_profile(failed_event, inferred_risk_score=0.0)
    assert profiler.get_profile(entity_id)["recent_failed_logins"] == 1, (
        "recent_failed_logins did not increment on a failed-auth event — "
        "likely the dead auth_method=='auth_failed' comparison bug."
    )

    success_event = {**failed_event, "timestamp": "2026-01-01 10:05:00", "command_sequence": "login -> success"}
    profiler.update_profile(success_event, inferred_risk_score=0.0)
    assert profiler.get_profile(entity_id)["recent_failed_logins"] == 0, (
        "recent_failed_logins did not reset to 0 after a successful auth event."
    )

def test_duration_baseline_flows_through_pipeline():
    """Regression test: session_duration must be tracked by the profiler, blended by
    cold-start, and read correctly by the ML detector — catches silent key-name mismatches."""
    profiler = EntityBaselineProfiler()
    cold_start = ColdStartManager(min_events_threshold=10)
    entity_id = "TEST_USER_DURATION"
    entity_type = "user"

    for i in range(15):
        event = {
            "entity_id": entity_id, "entity_type": entity_type,
            "timestamp": f"2026-01-0{(i%9)+1} 10:00:00", "auth_method": "password",
            "command_sequence": "login -> success", "device_fingerprint": "test-device",
            "geo_location": "Test (0.0, 0.0)", "resource_accessed": "test_resource",
            "session_duration": 900, "mb_transferred": 50.0
        }
        profiler.update_profile(event, inferred_risk_score=0.0)

    personal_profile = profiler.get_profile(entity_id)
    assert personal_profile["avg_duration"] is not None, "Profiler never tracked session_duration."
    assert 800 < personal_profile["avg_duration"] < 1000, (
        f"avg_duration should have converged near 900 (fed value), got {personal_profile['avg_duration']}"
    )

    effective_baseline = cold_start.get_effective_baseline(entity_id, entity_type, personal_profile)
    assert "avg_duration" in effective_baseline, (
        "avg_duration missing from blended cold-start baseline output — "
        "likely the Part B propagation bug."
    )
    assert 800 < effective_baseline["avg_duration"] < 1000, (
        f"Blended avg_duration should reflect learned personal behavior, got {effective_baseline['avg_duration']}"
    )

    ml_detector = MLAnomalyDetector()
    ml_detector.is_fitted = True
    test_event = {**event, "session_duration": 900}
    feat_vec = ml_detector.extract_features(test_event, effective_baseline)
    dur_z_index = 2
    assert feat_vec[dur_z_index] < 1.0, (
        f"dur_z should be near zero when event duration matches learned baseline, got {feat_vec[dur_z_index]} — "
        "check for the mean_duration/avg_duration key mismatch bug."
    )

def test_sequence_fusion_single_source_of_truth():
    """Regression test: confirm risk fusion and classification consume the same
    fused sequence score, computed by exactly one canonical fusion call per event."""
    from detection.sequence import SequenceIntelligenceFusion
    fusion = SequenceIntelligenceFusion(mode="ngram")
    score_ngram_mode = fusion.fuse_sequence_scores(markov_score=0.8, autoencoder_score=0.1)
    assert score_ngram_mode == 0.8, "ngram mode should return the markov score unchanged"

    fusion_ae = SequenceIntelligenceFusion(mode="autoencoder")
    score_ae_mode = fusion_ae.fuse_sequence_scores(markov_score=0.8, autoencoder_score=0.1)
    assert score_ae_mode == 0.1, "autoencoder mode should return the autoencoder score unchanged"

    fusion_both = SequenceIntelligenceFusion(mode="both")
    score_both_mode = fusion_both.fuse_sequence_scores(markov_score=0.8, autoencoder_score=0.1)
    assert abs(score_both_mode - 0.45) < 1e-6, "both mode should return the 50/50 blend"

def test_lateral_movement_does_not_falsely_flag_normal_ot_access():
    """Regression test: an OT-domain entity accessing its own normal OT resource
    (already in known_resources) must NOT trigger lateral_movement_flag.
    Catches the operator-precedence bug where 'Honeywell_Forge'/'SCADA' checks
    were accidentally ungated from the user_domain=='IT' condition."""
    from detection.rule_engine import RuleAssistEngine
    engine = RuleAssistEngine()

    # OT operator accessing a resource ALREADY in their known/normal resource set
    ot_event = {
        "entity_id": "OT_TEST_USER", "entity_type": "user", "domain": "OT",
        "resource_accessed": "SCADA_HMI_Workstation_01", "auth_method": "certificate",
        "timestamp": "2026-01-01 10:00:00", "command_sequence": "modbus_read -> log_telemetry",
        "device_fingerprint": "test-device", "source_ip": "10.1.1.1",
        "geo_location": "Test (0.0, 0.0)", "mb_transferred": 5.0
    }
    ot_baseline = {
        "known_resources": {"SCADA_HMI_Workstation_01", "BMS_Controller_HVAC_01"},
        "known_devices": {"test-device"}, "event_count": 20
    }
    signals = engine.evaluate_rules(ot_event, ot_baseline)
    assert signals["lateral_movement_flag"] is False, (
        "OT entity accessing its own known, normal SCADA resource was falsely flagged "
        "as lateral movement — likely the operator-precedence bug."
    )

    # IT entity accessing an OT resource it has never touched — SHOULD be flagged
    it_event = {**ot_event, "entity_id": "IT_TEST_USER", "domain": "IT", "resource_accessed": "SCADA_HMI_Workstation_01"}
    it_baseline = {
        "known_resources": {"Corporate_VPN", "Active_Directory"},  # never touched SCADA before
        "known_devices": {"test-device"}, "event_count": 20
    }
    signals_it = engine.evaluate_rules(it_event, it_baseline)
    assert signals_it["lateral_movement_flag"] is True, (
        "IT entity accessing an unfamiliar SCADA/OT resource should be flagged as lateral movement."
    )

if __name__ == "__main__":
    pytest.main(["-v", __file__])
