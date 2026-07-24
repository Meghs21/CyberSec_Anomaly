"""
Live Demo Scripted Attack Runner.
Injects real-time attack events into the live stream dataset during hackathon judge presentations.
"""

from datetime import datetime
import os
import pandas as pd

def trigger_live_attack_burst(csv_path):
    if not os.path.exists(csv_path):
        print(f"Dataset path {csv_path} not found. Run generate_dataset.py first.")
        return

    df = pd.read_csv(csv_path)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    new_attacks = [
        {
            "timestamp": now_str,
            "user_id": "USR_012",
            "role": "Finance_Manager",
            "domain": "IT",
            "target_resource": "Honeywell_Forge_Gateway",
            "asset_domain": "OT",
            "ip_address": "10.200.45.88",
            "latitude": 29.7604,
            "longitude": -95.3698,
            "location_name": "Houston_Hub",
            "device_id": "Unrecognized-Kali-Linux-Box",
            "mb_transferred": 2400.0,
            "auth_result": "SUCCESS",
            "is_attack": True,
            "attack_type": "IT-OT Crossover",
            "taxonomy": "Collective Anomaly"
        },
        {
            "timestamp": now_str,
            "user_id": "USR_012",
            "role": "Finance_Manager",
            "domain": "IT",
            "target_resource": "BMS_Controller_HVAC_01",
            "asset_domain": "OT",
            "ip_address": "192.168.90.105",
            "latitude": 1.3521,
            "longitude": 103.8198,
            "location_name": "Singapore_Facility",
            "device_id": "Unrecognized-Kali-Linux-Box",
            "mb_transferred": 6800.0,
            "auth_result": "SUCCESS",
            "is_attack": True,
            "attack_type": "Impossible Travel",
            "taxonomy": "Collective Anomaly"
        }
    ]
    
    attack_df = pd.DataFrame(new_attacks)
    updated_df = pd.concat([df, attack_df], ignore_index=True)
    updated_df.to_csv(csv_path, index=False)
    print("!!! LIVE DEMO ATTACK BURST TRIGGERED !!!")
    print("Injected 2 High-Severity Attacks: IT-OT Crossover + Impossible Travel onto Honeywell Forge Gateway & BMS Controller.")

if __name__ == "__main__":
    data_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_access_logs.csv"))
    trigger_live_attack_burst(data_file)
