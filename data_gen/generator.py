"""
Synthetic Access Log Generator for Honeywell Mixed IT + OT Enterprise.
Generates realistic multi-day normal behavioral logs and injects explicit, labeled cyber attack scenarios.
"""

import random
import math
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

# Configuration constants
ROLES = {
    "IT_Analyst": {"domain": "IT", "start_hour": 9, "end_hour": 17, "base_mb": (10, 150)},
    "Software_Engineer": {"domain": "IT", "start_hour": 10, "end_hour": 18, "base_mb": (50, 400)},
    "HR_Specialist": {"domain": "IT", "start_hour": 8, "end_hour": 16, "base_mb": (5, 50)},
    "Finance_Manager": {"domain": "IT", "start_hour": 8, "end_hour": 17, "base_mb": (10, 80)},
    "BMS_Operator": {"domain": "OT", "start_hour": 7, "end_hour": 19, "base_mb": (20, 250)},
    "HVAC_Engineer": {"domain": "OT", "start_hour": 8, "end_hour": 17, "base_mb": (15, 200)},
    "SCADA_Specialist": {"domain": "OT", "start_hour": 6, "end_hour": 18, "base_mb": (30, 500)},
    "Facilities_Tech": {"domain": "OT", "start_hour": 7, "end_hour": 16, "base_mb": (10, 100)},
    "Domain_Admin": {"domain": "IT", "start_hour": 8, "end_hour": 18, "base_mb": (100, 800)},
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

DEVICES = [
    "Corporate-MacBook-Pro", "Windows-11-Enterprise-Workstation",
    "Honeywell-Toughbook-Field-Laptop", "Linux-Engineering-Workstation", "Mobile-iOS-Corporate"
]

def haversine_distance_miles(lat1, lon1, lat2, lon2):
    """Calculates geographical distance in miles between two lat/lon pairs."""
    R = 3958.8  # Earth radius in miles
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

class SyntheticLogGenerator:
    def __init__(self, num_users=50, num_days=14, seed=42):
        random.seed(seed)
        np.random.seed(seed)
        self.num_users = num_users
        self.num_days = num_days
        self.users = self._create_user_profiles()

    def _create_user_profiles(self):
        users = []
        role_keys = list(ROLES.keys())
        loc_keys = list(GEO_LOCATIONS.keys())
        
        for i in range(1, self.num_users + 1):
            user_id = f"USR_{i:03d}"
            role = role_keys[(i - 1) % len(role_keys)]
            role_meta = ROLES[role]
            home_loc = loc_keys[(i - 1) % len(loc_keys)]
            device = DEVICES[(i - 1) % len(DEVICES)]
            
            users.append({
                "user_id": user_id,
                "role": role,
                "domain": role_meta["domain"],
                "start_hour": role_meta["start_hour"],
                "end_hour": role_meta["end_hour"],
                "base_mb": role_meta["base_mb"],
                "home_location": home_loc,
                "lat": GEO_LOCATIONS[home_loc]["lat"],
                "lon": GEO_LOCATIONS[home_loc]["lon"],
                "ip_prefix": GEO_LOCATIONS[home_loc]["ip_prefix"],
                "primary_device": device,
                "dormant": False
            })
        
        # Mark 2 admin/engineering users as dormant (90+ days inactive baseline)
        users[3]["dormant"] = True
        users[7]["dormant"] = True
        return users

    def generate_logs(self, target_events=1200):
        """Generates raw normal access logs over the simulated timeframe."""
        start_time = datetime.now() - timedelta(days=self.num_days)
        events = []
        
        current_time = start_time
        events_created = 0
        
        while events_created < target_events:
            # Pick a random active user
            active_users = [u for u in self.users if not u["dormant"]]
            user = random.choice(active_users)
            
            # Timestamp with gaussian variation around working hours
            hour = int(np.random.normal(loc=(user["start_hour"] + user["end_hour"])/2, scale=2.5)) % 24
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            event_dt = current_time.replace(hour=hour, minute=minute, second=second)
            
            # Determine target resource based on user domain (mostly domain match)
            if user["domain"] == "OT":
                target_resource = random.choice(OT_RESOURCES if random.random() < 0.85 else IT_RESOURCES)
                asset_domain = "OT" if target_resource in OT_RESOURCES else "IT"
            else:
                target_resource = random.choice(IT_RESOURCES if random.random() < 0.95 else OT_RESOURCES)
                asset_domain = "IT" if target_resource in IT_RESOURCES else "OT"
                
            ip_addr = f"{user['ip_prefix']}{random.randint(1, 254)}.{random.randint(1, 254)}"
            mb_transferred = round(random.uniform(user["base_mb"][0], user["base_mb"][1]), 2)
            
            events.append({
                "timestamp": event_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": user["user_id"],
                "role": user["role"],
                "domain": user["domain"],
                "target_resource": target_resource,
                "asset_domain": asset_domain,
                "ip_address": ip_addr,
                "latitude": user["lat"] + random.uniform(-0.01, 0.01),
                "longitude": user["lon"] + random.uniform(-0.01, 0.01),
                "location_name": user["home_location"],
                "device_id": user["primary_device"],
                "mb_transferred": mb_transferred,
                "auth_result": "SUCCESS",
                "is_attack": False,
                "attack_type": "None",
                "taxonomy": "Normal"
            })
            
            events_created += 1
            current_time += timedelta(minutes=random.randint(5, 25))
            
        df = pd.DataFrame(events)
        df.sort_values(by="timestamp", inplace=True)
        df.reset_index(drop=True, inplace=True)
        return df

    def inject_attack_scenarios(self, df):
        """
        Injects explicit attack scenarios ensuring strong representation of Honeywell OT threats.
        Scenario Types:
        1. Impossible Travel (Collective)
        2. Off-Hours Exfiltration (Contextual)
        3. Dormant Account Reactivation (Collective)
        4. Device Mismatch on OT Controller (Contextual)
        5. Rapid Brute-Force (Point)
        6. IT-to-OT Crossover Misuse (Collective/Contextual - Honeywell Priority)
        """
        events = df.to_dict("records")
        num_events = len(events)
        
        injected_counts = {
            "Impossible Travel": 0,
            "Off-Hours Exfiltration": 0,
            "Dormant Account Reactivation": 0,
            "Device Mismatch OT": 0,
            "Brute Force": 0,
            "IT-OT Crossover": 0
        }

        # 1. Inject Impossible Travel (8 instances)
        # Select pairs of events spaced close in time for the same user, change location to Singapore/Tokyo
        for _ in range(8):
            idx = random.randint(50, num_events - 100)
            base_event = events[idx]
            target_user = base_event["user_id"]
            base_dt = datetime.strptime(base_event["timestamp"], "%Y-%m-%d %H:%M:%S")
            
            # Create rapid follow-up login 12 minutes later from Singapore
            attack_dt = base_dt + timedelta(minutes=12)
            events.append({
                "timestamp": attack_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": target_user,
                "role": base_event["role"],
                "domain": base_event["domain"],
                "target_resource": "Corporate_VPN",
                "asset_domain": "IT",
                "ip_address": "192.168.90.105",
                "latitude": GEO_LOCATIONS["Singapore_Facility"]["lat"],
                "longitude": GEO_LOCATIONS["Singapore_Facility"]["lon"],
                "location_name": "Singapore_Facility",
                "device_id": base_event["device_id"],
                "mb_transferred": 45.0,
                "auth_result": "SUCCESS",
                "is_attack": True,
                "attack_type": "Impossible Travel",
                "taxonomy": "Collective Anomaly"
            })
            injected_counts["Impossible Travel"] += 1

        # 2. Inject Off-Hours Exfiltration (8 instances)
        for _ in range(8):
            idx = random.randint(30, num_events - 50)
            base_event = events[idx]
            base_dt = datetime.strptime(base_event["timestamp"], "%Y-%m-%d %H:%M:%S")
            off_hours_dt = base_dt.replace(hour=random.choice([1, 2, 3]), minute=random.randint(10, 50))
            
            events.append({
                "timestamp": off_hours_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": base_event["user_id"],
                "role": base_event["role"],
                "domain": base_event["domain"],
                "target_resource": "AWS_Console",
                "asset_domain": "IT",
                "ip_address": "185.220.101.5", # Suspicious external IP
                "latitude": base_event["latitude"],
                "longitude": base_event["longitude"],
                "location_name": base_event["location_name"],
                "device_id": base_event["device_id"],
                "mb_transferred": round(random.uniform(4500.0, 9500.0), 2), # Massive exfil
                "auth_result": "SUCCESS",
                "is_attack": True,
                "attack_type": "Off-Hours Exfiltration",
                "taxonomy": "Contextual Anomaly"
            })
            injected_counts["Off-Hours Exfiltration"] += 1

        # 3. Inject Dormant Account Reactivation (6 instances)
        dormant_user = self.users[3] # USR_004 (Dormant Domain_Admin)
        start_dt = datetime.strptime(events[100]["timestamp"], "%Y-%m-%d %H:%M:%S")
        for i in range(6):
            reactivation_dt = start_dt + timedelta(days=7, hours=i*2)
            events.append({
                "timestamp": reactivation_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": dormant_user["user_id"],
                "role": dormant_user["role"],
                "domain": "IT",
                "target_resource": random.choice(["Active_Directory", "Honeywell_Forge_Gateway", "BMS_Controller_HVAC_01"]),
                "asset_domain": "OT" if i % 2 == 0 else "IT",
                "ip_address": "10.50.99.12",
                "latitude": dormant_user["lat"],
                "longitude": dormant_user["lon"],
                "location_name": dormant_user["home_location"],
                "device_id": "Unknown-Legacy-Console",
                "mb_transferred": 350.0,
                "auth_result": "SUCCESS",
                "is_attack": True,
                "attack_type": "Dormant Account Reactivation",
                "taxonomy": "Collective Anomaly"
            })
            injected_counts["Dormant Account Reactivation"] += 1

        # 4. Inject Device Mismatch on OT Controller (8 instances)
        for _ in range(8):
            idx = random.randint(40, num_events - 60)
            base_event = events[idx]
            base_dt = datetime.strptime(base_event["timestamp"], "%Y-%m-%d %H:%M:%S")
            
            events.append({
                "timestamp": base_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": base_event["user_id"],
                "role": base_event["role"],
                "domain": base_event["domain"],
                "target_resource": "BMS_Controller_HVAC_01",
                "asset_domain": "OT",
                "ip_address": base_event["ip_address"],
                "latitude": base_event["latitude"],
                "longitude": base_event["longitude"],
                "location_name": base_event["location_name"],
                "device_id": "Unrecognized-Kali-Linux-Box", # Suspicious device
                "mb_transferred": 120.0,
                "auth_result": "SUCCESS",
                "is_attack": True,
                "attack_type": "Device Mismatch OT",
                "taxonomy": "Contextual Anomaly"
            })
            injected_counts["Device Mismatch OT"] += 1

        # 5. Inject Brute Force (10 instances - burst of failures followed by success)
        for _ in range(10):
            idx = random.randint(20, num_events - 80)
            base_event = events[idx]
            base_dt = datetime.strptime(base_event["timestamp"], "%Y-%m-%d %H:%M:%S")
            
            # Generate 8 rapid failed attempts
            for f in range(8):
                fail_dt = base_dt + timedelta(seconds=f*5)
                events.append({
                    "timestamp": fail_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "user_id": base_event["user_id"],
                    "role": base_event["role"],
                    "domain": base_event["domain"],
                    "target_resource": base_event["target_resource"],
                    "asset_domain": base_event["asset_domain"],
                    "ip_address": "185.190.140.22",
                    "latitude": base_event["latitude"],
                    "longitude": base_event["longitude"],
                    "location_name": base_event["location_name"],
                    "device_id": base_event["device_id"],
                    "mb_transferred": 0.0,
                    "auth_result": "FAILURE",
                    "is_attack": True,
                    "attack_type": "Brute Force",
                    "taxonomy": "Point Anomaly"
                })
            injected_counts["Brute Force"] += 1

        # 6. Inject IT-to-OT Crossover Misuse (10 instances - Honeywell Highlight!)
        it_users = [u for u in self.users if u["domain"] == "IT" and u["role"] in ["Finance_Manager", "HR_Specialist"]]
        for i in range(10):
            target_user = random.choice(it_users)
            idx = random.randint(50, num_events - 50)
            base_dt = datetime.strptime(events[idx]["timestamp"], "%Y-%m-%d %H:%M:%S")
            
            ot_target = random.choice(["Honeywell_Forge_Gateway", "Industrial_PLC_Substation_01", "SCADA_HMI_Workstation_01"])
            events.append({
                "timestamp": base_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "user_id": target_user["user_id"],
                "role": target_user["role"],
                "domain": "IT",
                "target_resource": ot_target,
                "asset_domain": "OT",
                "ip_address": target_user["ip_prefix"] + "222",
                "latitude": target_user["lat"],
                "longitude": target_user["lon"],
                "location_name": target_user["home_location"],
                "device_id": target_user["primary_device"],
                "mb_transferred": round(random.uniform(200.0, 800.0), 2),
                "auth_result": "SUCCESS",
                "is_attack": True,
                "attack_type": "IT-OT Crossover",
                "taxonomy": "Collective Anomaly"
            })
            injected_counts["IT-OT Crossover"] += 1

        df_out = pd.DataFrame(events)
        df_out.sort_values(by="timestamp", inplace=True)
        df_out.reset_index(drop=True, inplace=True)
        
        print("\n=== Synthetic Data Generation Summary ===")
        print(f"Total Log Events: {len(df_out)}")
        print(f"Normal Events: {len(df_out[~df_out['is_attack']])}")
        print(f"Total Attack Events: {len(df_out[df_out['is_attack']])} ({(len(df_out[df_out['is_attack']])/len(df_out))*100:.2f}%)")
        print("Injected Attacks Breakdown:")
        for atype, cnt in injected_counts.items():
            print(f" - {atype}: {cnt} scenario bursts")
        print("==========================================\n")
        
        return df_out

if __name__ == "__main__":
    gen = SyntheticLogGenerator(num_users=50, num_days=14)
    raw_df = gen.generate_logs(target_events=1000)
    final_df = gen.inject_attack_scenarios(raw_df)
    final_df.to_csv("synthetic_access_logs.csv", index=False)
