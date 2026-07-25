"""
Sequence Intelligence Subsystem: Sequence Fusion Engine.
Combines Markov transition model scores with Behavioral Autoencoder reconstruction scores.
Supports 3-way mode configuration: 'ngram' | 'autoencoder' | 'both'.
"""

import os

class SequenceIntelligenceFusion:
    def __init__(self, mode=None):
        self.mode = mode or os.getenv("SEQUENCE_MODEL_MODE", "both").lower()

    def fuse_sequence_scores(self, markov_score, autoencoder_score, mode_override=None):
        """
        Fuses Markov transition score and Autoencoder reconstruction score into unified sequence_score.
        """
        eff_mode = mode_override or self.mode
        
        if eff_mode == "ngram":
            return markov_score
        elif eff_mode == "autoencoder":
            return autoencoder_score
        else:  # 'both' ensemble mode
            # Calibrated combination of Markov transition risk and Autoencoder reconstruction error
            return round(0.5 * markov_score + 0.5 * autoencoder_score, 3)
