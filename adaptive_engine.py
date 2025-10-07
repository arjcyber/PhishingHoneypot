# adaptive_engine.py
import time
import random

def analyze_attacker(ip, user_agent, attempt_count, typing_speed):
    deception_level = 1
    profile = "Human"

    if typing_speed < 0.8:
        profile = "Bot"
        deception_level += 1

    if attempt_count > 3:
        deception_level += 1

    if "curl" in user_agent or "python" in user_agent:
        profile = "Scanner/Bot"
        deception_level += 1

    payload = "none"
    if deception_level >= 3:
        payload = "fake_admin_link"

    return {
        "profile": profile,
        "deception_level": deception_level,
        "payload": payload,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
