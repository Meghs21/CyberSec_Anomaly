import pytest
from detection.sequence.markov_model import SequenceMarkovDetector

def test_markov_score_is_not_constant():
    """Regression test: ensure calculate_sequence_score varies across different inputs.
    Catches accidental stub/placeholder implementations that always return a fixed value."""
    detector = SequenceMarkovDetector()

    normal_events = [
        {
            "entity_id": "USR_001",
            "entity_type": "user",
            "timestamp": "2026-07-25 09:00:00",
            "resource_accessed": "FinanceDB",
            "auth_method": "password",
            "command_sequence": "login -> query -> logout",
            "label": "normal"
        },
        {
            "entity_id": "USR_001",
            "entity_type": "user",
            "timestamp": "2026-07-25 09:05:00",
            "resource_accessed": "PayrollSystem",
            "auth_method": "token",
            "command_sequence": "login -> read -> logout",
            "label": "normal"
        },
        {
            "entity_id": "USR_001",
            "entity_type": "user",
            "timestamp": "2026-07-25 09:10:00",
            "resource_accessed": "FinanceDB",
            "auth_method": "password",
            "command_sequence": "login -> query -> logout",
            "label": "normal"
        }
    ]

    detector.fit_normal_baseline(normal_events)

    profile = {"event_count": 20}

    # Normal expected transition
    normal_event = {
        "entity_id": "USR_001",
        "entity_type": "user",
        "timestamp": "2026-07-25 09:15:00",
        "resource_accessed": "PayrollSystem",
        "auth_method": "token",
        "command_sequence": "login -> read -> logout"
    }

    # Highly anomalous unseen transition (unusual resource & failed admin escalation sequence)
    anomalous_event = {
        "entity_id": "USR_001",
        "entity_type": "user",
        "timestamp": "2026-07-25 09:20:00",
        "resource_accessed": "SCADA_BMS_Controller",
        "auth_method": "certificate",
        "command_sequence": "sudo -> dump_hashes -> elevate_privileges -> exfiltrate"
    }

    normal_score = detector.calculate_sequence_score(normal_event, profile, prev_event=normal_events[-1])
    anomalous_score = detector.calculate_sequence_score(anomalous_event, profile, prev_event=normal_events[-1])

    # Assert that scores vary dynamically
    assert normal_score != anomalous_score, f"Expected scores to differ, but both were {normal_score}"

    # Assert that anomalous transition gets a higher risk score than normal transition
    assert anomalous_score > normal_score, f"Expected anomalous score ({anomalous_score}) to be > normal score ({normal_score})"

def test_markov_train_score_consistency():
    """Regression test: an event sequence identical to training data should score as
    low-anomaly. Catches training/scoring state-chain-shape mismatches."""
    detector = SequenceMarkovDetector()

    base_event = {
        "entity_id": "TEST_USER", "entity_type": "user",
        "resource_accessed": "Workday", "auth_method": "password",
        "command_sequence": "login -> select_dashboard -> logout",
        "timestamp": "2026-01-01 09:00:00"
    }
    prev_event = {
        "entity_id": "TEST_USER", "entity_type": "user",
        "resource_accessed": "Active_Directory", "auth_method": "password",
        "command_sequence": "login -> logout",
        "timestamp": "2026-01-01 08:55:00"
    }

    training_events = []
    for day in range(1, 11):
        training_events.append({**prev_event, "timestamp": f"2026-01-{day:02d} 08:55:00"})
        training_events.append({**base_event, "timestamp": f"2026-01-{day:02d} 09:00:00"})
    detector.fit_normal_baseline(training_events)

    entity_profile = {"event_count": 20}
    score = detector.calculate_sequence_score(base_event, entity_profile, prev_event=prev_event)

    assert score < 0.3, (
        f"Expected LOW anomaly score for a transition pattern seen repeatedly in training, got {score}. "
        "This likely indicates fit_normal_baseline() and calculate_sequence_score() are building "
        "different-shaped state chains (the training/scoring mismatch bug)."
    )
