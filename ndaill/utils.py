# utils.py - Python logic placeholder

# ndaill/utils.py

import json
import os

def load_personas():
    path = os.path.join(os.path.dirname(__file__), 'personas.json')
    with open(path, 'r') as f:
        return json.load(f)

