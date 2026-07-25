"""
CLI script to generate synthetic access logs for Honeywell IT + OT enterprise.
Matches the official 11-field schema and 0.5-3.0% anomaly rate.
"""

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from data_gen.generator import SyntheticLogGenerator

def main():
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "synthetic_access_logs.csv")

    print("Generating official synthetic access logs matching 11 schema fields...")
    gen = SyntheticLogGenerator(num_entities=50, num_days=14, anomaly_rate=0.015, seed=42)
    final_df = gen.generate_dataset(total_sessions=1500)

    final_df.to_csv(out_path, index=False)
    print(f"[SUCCESS] Synthetic dataset successfully saved to: {out_path}")

if __name__ == "__main__":
    main()
