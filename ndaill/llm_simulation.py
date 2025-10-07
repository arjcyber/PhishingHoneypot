# llm_simulation.py - Python logic placeholder

# ndaill/llm_simulation.py

def simulate_chat(input_text):
    response_bank = {
        "password": "For security reasons, I can't share passwords. Please verify your identity first.",
        "admin": "This panel is monitored. Unauthorized access will be logged.",
        "token": "Temporary token generated: 3f98xY12eTz — valid for 1 min.",
    }
    for keyword, reply in response_bank.items():
        if keyword in input_text.lower():
            return reply
    return "I don't understand your request. Try rephrasing or use the internal help command."

