"""
Official Synthetic Access Log Generator for Honeywell IT + OT Mixed Enterprise.
Generates multi-entity behavioral logs matching the exact 11-field official schema:
1. entity_id
2. entity_type (user / service_account / edge_device)
3. timestamp
4. source_ip
5. geo_location
6. resource_accessed
7. auth_method
8. session_duration
9. command_sequence
10. device_fingerprint
11. label (hidden at inference time)

Supports extreme class imbalance (0.5% - 3.0% anomaly rate) across 6 malicious attack categories
and 1 non-malicious behavioral drift edge case (insider_drift).
"""

import random
import json
import math
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

# Entity Types
ENTITY_TYPES = ["user", "service_account", "edge_device"]

# Roles & Domain Mappings
ROLES = {
    "IT_Analyst": {"entity_type": "user", "domain": "IT", "start_hour": 9, "end_hour": 17, "auth": "password"},
    "Software_Engineer": {"entity_type": "user", "domain": "IT", "start_hour": 10, "end_hour": 18, "auth": "token"},
    "HR_Specialist": {"entity_type": "user", "domain": "IT", "start_hour": 8, "end_hour": 16, "auth": "password"},
    "Finance_Manager": {"entity_type": "user", "domain": "IT", "start_hour": 8, "end_hour": 17, "auth": "biometric"},
    "BMS_Operator": {"entity_type": "user", "domain": "OT", "start_hour": 7, "end_hour": 19, "auth": "certificate"},
    "HVAC_Engineer": {"entity_type": "user", "domain": "OT", "start_hour": 8, "end_hour": 17, "auth": "certificate"},
    "SCADA_Specialist": {"entity_type": "user", "domain": "OT", "start_hour": 6, "end_hour": 18, "auth": "certificate"},
    "Forge_Sync_Service": {"entity_type": "service_account", "domain": "OT", "start_hour": 0, "end_hour": 23, "auth": "token"},
    "BMS_HVAC_Gateway_01": {"entity_type": "edge_device", "domain": "OT", "start_hour": 0, "end_hour": 23, "auth": "certificate"},
}

IT_RESOURCES = ["Corporate_VPN", "Active_Directory", "Workday", "GitHub_Enterprise", "AWS_Console", "Jira_Cloud"]
OT_RESOURCES = ["Honeywell_Forge_Gateway", "BMS_Controller_HVAC_01", "BMS_Controller_Lighting_02", 
                "SCADA_HMI_Workstation_01", "Access_Control_Gateway_03", "Industrial_PLC_Substation_01"]

GEO_LOCATIONS = {
    "Atlanta_HQ": {"lat": 33.7490, "lon": -84.3880, "ip_prefix": "10.100."},
    "Houston_Hub": {"lat": 29.7604, "lon": -95.3698, "ip_prefix": "10.200."},
    "Phoenix_Plant": {"lat": 33.4484, "lon": -112.0740, "ip_prefix": "192.168.50."},
    "London_Office": {"lat": 51.5074, "lon": -0.1278, "ip_prefix": "10.300."},
    "Singapore_Facility": {"lat": 1.3521, "lon": 103.8198, "ip_prefix": "192.168.90."}
}

DEVICE_FINGERPRINTS = {
    "MacBook-Pro": "macOS 14.2 | MAC: a4:83:e7:91:02:11 | Protocol: HTTPS/TLS1.3",
    "Windows-Workstation": "Windows 11 Enterprise | MAC: 00:1a:2b:3c:4d:5e | Protocol: RDP/SSH",
    "Honeywell-Toughbook": "Windows 10 IoT | MAC: 70:85:c2:14:99:aa | Protocol: Modbus/BACnet",
    "Linux-SCADA-HMI": "Ubuntu 22.04 LTS | MAC: 08:00:27:11:22:33 | Protocol: OPC-UA",
    "Edge-Gateway-Firmware": "Honeywell-Firmware v3.4 | MAC: 90:b1:1c:00:44:fe | Protocol: MQTT/TLS"
}

NORMAL_COMMAND_SEQUENCES = [
    "login -> authenticate -> select_dashboard -> view_logs -> logout",
    "connect_vpn -> fetch_repo -> git_pull -> build_code -> disconnect",
    "modbus_read -> check_temperature -> setpoint_verify -> log_telemetry",
    "ssh_connect -> check_service_status -> update_config -> service_restart -> exit",
    "token_auth -> sync_telemetry_batch -> push_forge_cloud -> close_session"
]

def haversine_miles(lat1, lon1, lat2, lon2):
    R = 3958.8
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

class SyntheticLogGenerator:
    def __init__(self, num_entities=50, num_days=14, anomaly_rate=0.015, seed=42):
        assert 0.005 <= anomaly_rate <= 0.03, f"Anomaly rate must be between 0.5% and 3.0%, got {anomaly_rate}"
        random.seed(seed)
        np.random.seed(seed)
        self.num_entities = num_entities
        self.num_days = num_days
        self.anomaly_rate = anomaly_rate
        self.entities = self._create_entity_profiles()

    def _create_entity_profiles(self):
        entities = []
        role_keys = list(ROLES.keys())
        loc_keys = list(GEO_LOCATIONS.keys())
        fp_keys = list(DEVICE_FINGERPRINTS.keys())

        for i in range(1, self.num_entities + 1):
            entity_id = f"USR_{i:03d}" if i <= 40 else f"DEV_{i:03d}"
            role = role_keys[(i - 1) % len(role_keys)]
            role_meta = ROLES[role]
            home_loc = loc_keys[(i - 1) % len(loc_keys)]
            fp_name = fp_keys[(i - 1) % len(fp_keys)]

            entities.append({
                "entity_id": entity_id,
                "entity_type": role_meta["entity_type"],
                "role": role,
                "domain": role_meta["domain"],
                "start_hour": role_meta["start_hour"],
                "end_hour": role_meta["end_hour"],
                "home_location": home_loc,
                "lat": GEO_LOCATIONS[home_loc]["lat"],
                "lon": GEO_LOCATIONS[home_loc]["lon"],
                "ip_prefix": GEO_LOCATIONS[home_loc]["ip_prefix"],
                "auth_method": role_meta["auth"],
                "device_fingerprint": DEVICE_FINGERPRINTS[fp_name],
                "fp_name": fp_name,
                "allowed_resources": OT_RESOURCES if role_meta["domain"] == "OT" else IT_RESOURCES
            })
        return entities

    def generate_dataset(self, total_sessions=2000):
        start_dt = datetime.now() - timedelta(days=self.num_days)
        events = []

        # Target anomaly counts based on anomaly_rate (0.5% - 3.0%)
        num_anomalies = max(10, int(total_sessions * self.anomaly_rate))
        num_normal = total_sessions - num_anomalies

        # 1. Generate Normal Sessions
        current_time = start_dt
        for _ in range(num_normal):
            entity = random.choice(self.entities)
            hour = int(np.random.normal(loc=(entity["start_hour"] + entity["end_hour"]) / 2, scale=2.0)) % 24
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            event_dt = current_time.replace(hour=hour, minute=minute, second=second)

            resource = random.choice(entity["allowed_resources"])
            ip = f"{entity['ip_prefix']}{random.randint(1, 254)}.{random.randint(1, 254)}"
            geo_str = f"{entity['home_location']} ({entity['lat']:.4f}, {entity['lon']:.4f})"
            duration = random.randint(60, 3600)
            cmd_seq = random.choice(NORMAL_COMMAND_SEQUENCES)

            events.append({
                "entity_id": entity["entity_id"],
                "entity_type": entity["entity_type"],
                "timestamp": event_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ip,
                "geo_location": geo_str,
                "resource_accessed": resource,
                "auth_method": entity["auth_method"],
                "session_duration": duration,
                "command_sequence": cmd_seq,
                "device_fingerprint": entity["device_fingerprint"],
                "label": "normal",
                "role": entity["role"],
                "domain": entity["domain"],
                "mb_transferred": round(random.uniform(10.0, 150.0), 2)
            })

            current_time += timedelta(minutes=random.randint(4, 20))

        # 2. Inject 6 Official Malicious Attack Categories
        cats = ["brute_force", "impossible_travel", "credential_stuffing", "lateral_movement", "device_spoofing", "low_and_slow_exfiltration"]
        per_cat = max(1, num_anomalies // (len(cats) + 2))

        # A. brute_force (rapid failed auth attempts)
        for _ in range(per_cat):
            ent = random.choice(self.entities)
            dt = start_dt + timedelta(days=random.randint(1, 10), hours=random.randint(8, 18))
            for f in range(8):
                events.append({
                    "entity_id": ent["entity_id"],
                    "entity_type": ent["entity_type"],
                    "timestamp": (dt + timedelta(seconds=f*4)).strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip": "185.190.140.22",
                    "geo_location": f"{ent['home_location']} ({ent['lat']:.4f}, {ent['lon']:.4f})",
                    "resource_accessed": random.choice(ent["allowed_resources"]),
                    "auth_method": "password",
                    "session_duration": 5,
                    "command_sequence": "auth_attempt -> auth_failed",
                    "device_fingerprint": ent["device_fingerprint"],
                    "label": "brute_force",
                    "role": ent["role"],
                    "domain": ent["domain"],
                    "mb_transferred": 0.0
                })

        # B. impossible_travel (geographically distant login in minutes)
        for _ in range(per_cat):
            ent = random.choice(self.entities)
            dt = start_dt + timedelta(days=random.randint(1, 10), hours=10)
            events.append({
                "entity_id": ent["entity_id"],
                "entity_type": ent["entity_type"],
                "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ent["ip_prefix"] + "12",
                "geo_location": f"Atlanta_HQ (33.7490, -84.3880)",
                "resource_accessed": "Corporate_VPN",
                "auth_method": ent["auth_method"],
                "session_duration": 300,
                "command_sequence": "login -> vpn_connect",
                "device_fingerprint": ent["device_fingerprint"],
                "label": "normal",
                "role": ent["role"],
                "domain": ent["domain"],
                "mb_transferred": 25.0
            })
            events.append({
                "entity_id": ent["entity_id"],
                "entity_type": ent["entity_type"],
                "timestamp": (dt + timedelta(minutes=12)).strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": "192.168.90.105",
                "geo_location": "Singapore_Facility (1.3521, 103.8198)",
                "resource_accessed": "Corporate_VPN",
                "auth_method": ent["auth_method"],
                "session_duration": 450,
                "command_sequence": "login -> vpn_connect -> abnormal_jump",
                "device_fingerprint": ent["device_fingerprint"],
                "label": "impossible_travel",
                "role": ent["role"],
                "domain": ent["domain"],
                "mb_transferred": 45.0
            })

        # C. credential_stuffing (many entity_ids, 1 source IP, high failure rate)
        spray_ip = "194.26.29.110"
        for i in range(per_cat):
            target_ent = self.entities[i % len(self.entities)]
            dt = start_dt + timedelta(days=5, hours=2, minutes=i*3)
            events.append({
                "entity_id": target_ent["entity_id"],
                "entity_type": target_ent["entity_type"],
                "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": spray_ip,
                "geo_location": "Unknown_External_Proxy (55.7558, 37.6173)",
                "resource_accessed": "Active_Directory",
                "auth_method": "password",
                "session_duration": 2,
                "command_sequence": "credential_stuffing_attempt -> auth_failure",
                "device_fingerprint": "Python-Requests/2.31.0 | MAC: 00:00:00:00:00:00",
                "label": "credential_stuffing",
                "role": target_ent["role"],
                "domain": target_ent["domain"],
                "mb_transferred": 0.1
            })

        # D. lateral_movement (IT entity accessing OT resources)
        it_users = [e for e in self.entities if e["domain"] == "IT" and e["role"] in ["Finance_Manager", "HR_Specialist"]]
        for i in range(per_cat):
            ent = random.choice(it_users)
            dt = start_dt + timedelta(days=random.randint(2, 12), hours=14)
            events.append({
                "entity_id": ent["entity_id"],
                "entity_type": ent["entity_type"],
                "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ent["ip_prefix"] + "199",
                "geo_location": f"{ent['home_location']} ({ent['lat']:.4f}, {ent['lon']:.4f})",
                "resource_accessed": "Honeywell_Forge_Gateway" if i % 2 == 0 else "BMS_Controller_HVAC_01",
                "auth_method": ent["auth_method"],
                "session_duration": 1800,
                "command_sequence": "ssh_connect -> modbus_read -> plc_override_attempt -> unauthorized_hop",
                "device_fingerprint": ent["device_fingerprint"],
                "label": "lateral_movement",
                "role": ent["role"],
                "domain": ent["domain"],
                "mb_transferred": 450.0
            })

        # E. device_spoofing (device_id reappearing with mismatched OS/MAC fingerprint)
        for _ in range(per_cat):
            ent = random.choice(self.entities)
            dt = start_dt + timedelta(days=random.randint(3, 11), hours=11)
            spoofed_fp = "Kali-Linux 2024.1 | MAC: de:ad:be:ef:00:01 | Protocol: Raw-Socket"
            events.append({
                "entity_id": ent["entity_id"],
                "entity_type": ent["entity_type"],
                "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": ent["ip_prefix"] + "77",
                "geo_location": f"{ent['home_location']} ({ent['lat']:.4f}, {ent['lon']:.4f})",
                "resource_accessed": "SCADA_HMI_Workstation_01",
                "auth_method": ent["auth_method"],
                "session_duration": 600,
                "command_sequence": "spoofed_device_handshake -> raw_socket_inject",
                "device_fingerprint": spoofed_fp,
                "label": "device_spoofing",
                "role": ent["role"],
                "domain": ent["domain"],
                "mb_transferred": 120.0
            })

        # F. low_and_slow_exfiltration (gradual small off-hours resource access over days/weeks)
        exfil_user = self.entities[2] # USR_003
        for i in range(per_cat):
            dt = start_dt + timedelta(days=i*2, hours=random.choice([1, 2, 3]))
            events.append({
                "entity_id": exfil_user["entity_id"],
                "entity_type": exfil_user["entity_type"],
                "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": exfil_user["ip_prefix"] + "55",
                "geo_location": f"{exfil_user['home_location']} ({exfil_user['lat']:.4f}, {exfil_user['lon']:.4f})",
                "resource_accessed": "AWS_Console",
                "auth_method": exfil_user["auth_method"],
                "session_duration": 420,
                "command_sequence": "quiet_connect -> s3_download_chunk -> background_exfil",
                "device_fingerprint": exfil_user["device_fingerprint"],
                "label": "low_and_slow_exfiltration",
                "role": exfil_user["role"],
                "domain": exfil_user["domain"],
                "mb_transferred": round(random.uniform(80.0, 180.0), 2)
            })

        # 3. Inject Non-Malicious Edge Case: insider_drift
        # Legitimate entity slowly expanding access footprint over time
        drift_user = self.entities[0] # USR_001
        for i in range(6):
            dt = start_dt + timedelta(days=i*2 + 1, hours=10 + (i % 3))
            events.append({
                "entity_id": drift_user["entity_id"],
                "entity_type": drift_user["entity_type"],
                "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": drift_user["ip_prefix"] + "10",
                "geo_location": f"{drift_user['home_location']} ({drift_user['lat']:.4f}, {drift_user['lon']:.4f})",
                "resource_accessed": "Jira_Cloud" if i < 3 else "GitHub_Enterprise",
                "auth_method": drift_user["auth_method"],
                "session_duration": 900,
                "command_sequence": "legitimate_work_shift -> new_project_access",
                "device_fingerprint": drift_user["device_fingerprint"],
                "label": "insider_drift",
                "role": drift_user["role"],
                "domain": drift_user["domain"],
                "mb_transferred": round(random.uniform(30.0, 70.0), 2)
            })

        df = pd.DataFrame(events)
        df.sort_values(by="timestamp", inplace=True)
        df.reset_index(drop=True, inplace=True)

        malicious_df = df[df["label"].isin(cats)]
        actual_anomaly_rate = len(malicious_df) / len(df) * 100

        print("\n=== Official Synthetic Data Generation Summary ===")
        print(f"Total Sessions: {len(df)}")
        print(f"Normal Sessions: {len(df[df['label'] == 'normal'])}")
        print(f"Insider Drift Sessions (Non-malicious edge case): {len(df[df['label'] == 'insider_drift'])}")
        print(f"Malicious Attack Sessions: {len(malicious_df)} ({actual_anomaly_rate:.2f}% anomaly rate)")
        print("Label Distribution:")
        print(df["label"].value_counts().to_dict())
        print("===================================================\n")

        return df

if __name__ == "__main__":
    gen = SyntheticLogGenerator(num_entities=50, num_days=14, anomaly_rate=0.015)
    df = gen.generate_dataset(total_sessions=1500)
    df.to_csv("synthetic_access_logs.csv", index=False)
