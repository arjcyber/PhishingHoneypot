# engine.py - Python logic placeholder
# ndaill/engine.py

from datetime import datetime
import random

def generate_fake_admin_panel():
    return {
        "users": ["admin", "root", "pentest_bot", "shadow_user"],
        "alerts": ["Unauthorized SSH login", "Credential stuffing detected", "Phishing attempt from TOR exit node"]
    }

def get_flagged_logs():
    return [
        {"ip": "192.168.1.23", "behavior": "Rapid form submission", "timestamp": datetime.utcnow()},
        {"ip": "10.0.0.5", "behavior": "Fingerprint spoofing", "timestamp": datetime.utcnow()}
    ]

def audit_clearance():
    return [
        {"user": "decoy_user01", "role": "Fake HR Manager", "access_time": "2025-04-18 14:32", "location": "Ukraine"},
        {"user": "pentester_admin", "role": "Simulated Admin", "access_time": "2025-04-18 15:12", "location": "Unknown"}
    ]
