"""
Live Demo Scripted Attack Runner.
Injects real-time attack events matching official 11-field schema during live presentations.
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
            "entity_id": "USR_012",
            "entity_type": "user",
            "timestamp": now_str,
            "source_ip": "10.200.45.88",
            "geo_location": "Houston_Hub (29.7604, -95.3698)",
            "resource_accessed": "Honeywell_Forge_Gateway",
            "auth_method": "token",
            "session_duration": 1200,
            "command_sequence": "ssh_connect -> modbus_override_attempt",
            "device_fingerprint": "Kali-Linux 2024.1 | MAC: de:ad:be:ef:00:01 | Protocol: Raw-Socket",
            "label": "lateral_movement",
            "role": "Finance_Manager",
            "domain": "IT",
            "mb_transferred": 2400.0
        },
        {
            "entity_id": "USR_012",
            "entity_type": "user",
            "timestamp": now_str,
            "source_ip": "192.168.90.105",
            "geo_location": "Singapore_Facility (1.3521, 103.8198)",
            "resource_accessed": "BMS_Controller_HVAC_01",
            "auth_method": "token",
            "session_duration": 1800,
            "command_sequence": "login -> vpn_connect -> abnormal_jump",
            "device_fingerprint": "Kali-Linux 2024.1 | MAC: de:ad:be:ef:00:01 | Protocol: Raw-Socket",
            "label": "impossible_travel",
            "role": "Finance_Manager",
            "domain": "IT",
            "mb_transferred": 6800.0
        }
    ]

    attack_df = pd.DataFrame(new_attacks)
    updated_df = pd.concat([df, attack_df], ignore_index=True)
    updated_df.to_csv(csv_path, index=False)
    print("!!! LIVE DEMO ATTACK BURST TRIGGERED !!!")
    print("Injected 2 High-Severity Official Attacks: lateral_movement + impossible_travel onto Honeywell Forge Gateway & BMS Controller.")

if __name__ == "__main__":
    data_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_access_logs.csv"))
    trigger_live_attack_burst(data_file)
