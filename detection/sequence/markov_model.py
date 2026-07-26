"""
Sequence Intelligence Subsystem: Markov Transition Model.
Implements N-gram Markov transition probability model over resource_accessed and command_sequence.
Provides interpretable transition probabilities with Laplace smoothing and cohort fallback.
Strictly enforces ground-truth label leakage prevention.
"""

from collections import defaultdict
import numpy as np

def _dict_int():
    return defaultdict(int)

def _dict_dict_int():
    return defaultdict(_dict_int)

class SequenceMarkovDetector:
    def __init__(self, min_cohort_events=10, smooth_alpha=1.0, min_prob_floor=1e-5):
        self.min_cohort_events = min_cohort_events
        self.alpha = smooth_alpha
        self.prob_floor = min_prob_floor
        
        # Per-entity transitions: entity_id -> state_from -> state_to -> count
        self.entity_transitions = defaultdict(_dict_dict_int)
        
        # Cohort transitions: entity_type -> state_from -> state_to -> count
        self.cohort_transitions = defaultdict(_dict_dict_int)
        
        # Unique state vocabulary per transition domain
        self.vocab = set()

    def _extract_states(self, event):
        """Extracts composite event state and command tokens."""
        assert "label" not in event, "LABEL LEAKAGE DETECTED in state extraction!"
        res = event.get("resource_accessed", "unknown")
        auth = event.get("auth_method", "password")
        event_state = f"{res}:{auth}"
        
        cmd_seq = event.get("command_sequence", "")
        tokens = [t.strip() for t in cmd_seq.split("->") if t.strip()]
        
        states = [event_state] + tokens if tokens else [event_state]
        for s in states:
            self.vocab.add(s)
        return states

    def fit_normal_baseline(self, events):
        """Fits transition counts strictly on initial normal baseline training events grouped by entity."""
        entity_groups = defaultdict(list)
        for ev in events:
            assert "label" not in ev or ev.get("label") == "normal", "Markov baseline training on normal events"
            ev_clean = {k: v for k, v in ev.items() if k != "label"}
            entity_groups[ev["entity_id"]].append(ev_clean)

        for entity_id, ent_events in entity_groups.items():
            sorted_events = sorted(ent_events, key=lambda x: str(x.get("timestamp", "")))

            for i, ev in enumerate(sorted_events):
                entity_type = ev.get("entity_type", "user")
                curr_states = self._extract_states(ev)

                if i > 0:
                    prev_ev = sorted_events[i - 1]
                    prev_state = f"{prev_ev.get('resource_accessed')}:{prev_ev.get('auth_method')}"
                    states = [prev_state] + curr_states
                else:
                    states = curr_states

                # Walk the FULL combined chain — same shape as calculate_sequence_score() builds at inference
                for j in range(len(states) - 1):
                    s_from, s_to = states[j], states[j + 1]
                    self.entity_transitions[entity_id][s_from][s_to] += 1
                    self.cohort_transitions[entity_type][s_from][s_to] += 1

    def calculate_sequence_score(self, event, entity_profile, prev_event=None):
        """
        Calculates Markov sequence anomaly score in [0.0, 1.0].
        0.0 = expected transition; 1.0 = highly unusual transition.
        Fails loudly if label leakage is detected!
        """
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' must be removed before Markov scoring!"
        
        entity_id = event["entity_id"]
        entity_type = event.get("entity_type", "user")
        curr_states = self._extract_states(event)
        
        # Combine inter-event and intra-event states
        if prev_event:
            prev_clean = {k: v for k, v in prev_event.items() if k != "label"}
            prev_state = f"{prev_clean.get('resource_accessed')}:{prev_clean.get('auth_method')}"
            states = [prev_state] + curr_states
        else:
            states = curr_states
            
        if len(states) < 2:
            return 0.0
            
        use_cohort = (entity_profile.get("event_count", 0) < self.min_cohort_events)
        trans_table = self.cohort_transitions[entity_type] if use_cohort else self.entity_transitions[entity_id]
        
        neg_log_probs = []
        V = max(10, len(self.vocab))
        
        for i in range(len(states) - 1):
            s_from, s_to = states[i], states[i+1]
            out_counts = trans_table.get(s_from, {})
            total_out = sum(out_counts.values())
            trans_count = out_counts.get(s_to, 0)
            
            # Laplace additive smoothing
            prob = (trans_count + self.alpha) / (total_out + self.alpha * V)
            prob = max(self.prob_floor, prob)
            neg_log_probs.append(-np.log(prob))
            
        mean_neg_log = float(np.mean(neg_log_probs))
        
        # Normalize negative log-probability into score range [0.0, 1.0]
        normalized_score = min(1.0, max(0.0, (mean_neg_log - 1.0) / 7.0))
        return round(float(normalized_score), 3)

    def update_transitions_online(self, event, inferred_risk_score, trust_threshold=45.0):
        """Online update of transitions for low-risk observations (anti-poisoning)."""
        assert "label" not in event, "LABEL LEAKAGE DETECTED: Ground-truth 'label' must be removed before online updates!"
        
        if inferred_risk_score >= trust_threshold:
            return
            
        entity_id = event["entity_id"]
        entity_type = event.get("entity_type", "user")
        states = self._extract_states(event)
        
        for i in range(len(states) - 1):
            s_from, s_to = states[i], states[i+1]
            self.entity_transitions[entity_id][s_from][s_to] += 1
            self.cohort_transitions[entity_type][s_from][s_to] += 1
