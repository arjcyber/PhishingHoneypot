from flask import Flask, render_template, request, redirect, url_for
import os
from datetime import datetime
import random

app = Flask(__name__)

# Ensure the logs folder exists
if not os.path.exists("logs"):
    os.makedirs("logs")

ADAPTIVE_LOG_FILE = os.path.join("logs", "adaptive_honeypot_log.txt")

# Define available fake login templates
adaptive_templates = [
    "facebook_login.html",
    "instagram_login.html",
    "office365_login.html",
    "admin_panel.html",
    "leaked_file_page.html"
]

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/adaptive_honeypot", methods=["GET", "POST"])
def adaptive_honeypot():
    selected_template = random.choice(adaptive_templates)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        ip_address = request.remote_addr
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] IP: {ip_address} tried to log in on {selected_template}\nUsername: {username} | Password: {password}\n"
        with open(ADAPTIVE_LOG_FILE, "a") as log_file:
            log_file.write(log_entry)
        return redirect(url_for("adaptive_honeypot"))
    return render_template(selected_template)

@app.route("/adaptive_logs")
def adaptive_logs():
    try:
        with open(ADAPTIVE_LOG_FILE, "r") as f:
            logs = f.readlines()
    except FileNotFoundError:
        logs = []
    return render_template("adaptive_logs.html", logs=logs)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
