"""
CLI script to generate synthetic access logs for Honeywell IT + OT enterprise.
"""

import sys
import os

# Ensure parent directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from data_gen.generator import SyntheticLogGenerator

def main():
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "synthetic_access_logs.csv")
    
    print(f"Generating synthetic access logs for Honeywell IT + OT enterprise...")
    gen = SyntheticLogGenerator(num_users=60, num_days=14, seed=42)
    raw_df = gen.generate_logs(target_events=1200)
    final_df = gen.inject_attack_scenarios(raw_df)
    
    final_df.to_csv(out_path, index=False)
    print(f"[SUCCESS] Synthetic dataset successfully saved to: {out_path}")

if __name__ == "__main__":
    main()
