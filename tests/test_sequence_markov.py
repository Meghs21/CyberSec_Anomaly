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

    assert normal_score != anomalous_score, (
        f"Markov score returned identical values ({normal_score}) for normal and anomalous inputs — "
        "likely a stub or state-mismatch implementation."
    )
    assert anomalous_score > normal_score, (
        f"Anomalous event ({anomalous_score}) should score higher than normal event ({normal_score})."
    )
