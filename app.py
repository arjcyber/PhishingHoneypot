from flask import Flask, render_template, request, redirect, send_file, session
import sqlite3
import pickle
import datetime
import warnings
import pandas as pd
import threading
import requests
import time
import os
import io
import csv
import random
from email_scanner import check_email

app = Flask(__name__)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "pass123"
app.secret_key = os.urandom(24)

TELEGRAM_BOT_TOKEN = "8014983608:AAFDpA5Kw4SLsJbveEej0TLMJa6lm62oFBI"
CHAT_ID = "974683585"

try:
    with open('phishing_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("✅ ML model loaded.")
except Exception as e:
    print(f"❌ ML model load error: {e}")
    model = None

adaptive_logins = [
    'adaptive_honeypot_instagram.html',
    'adaptive_honeypot_facebook.html',
    'adaptive_honeypot_microsoft.html'
]

def init_db():
    conn = sqlite3.connect('honeypot.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, password TEXT, ip_address TEXT, timestamp TEXT, is_phishing INTEGER)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS qr_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT, timestamp TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS email_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT, timestamp TEXT)''')
    conn.commit()
    conn.close()

def send_telegram_alert(message):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {"chat_id": CHAT_ID, "text": message}
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("✅ Telegram alert sent.")
        else:
            print(f"❌ Telegram error: {response.text}")
    except Exception as e:
        print(f"❌ Telegram exception: {e}")

def get_readable_page_name(filename):
    if "facebook" in filename.lower():
        return "Facebook"
    elif "instagram" in filename.lower():
        return "Instagram"
    elif "microsoft" in filename.lower():
        return "Microsoft"
    else:
        return "Unknown"

@app.route("/", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect("/home")
        else:
            return render_template("auth_login.html", error="❌ Wrong credentials.")
    return render_template("auth_login.html")

@app.route("/home")
def home():
    if not session.get('admin_logged_in'):
        return redirect("/")
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.pop('admin_logged_in', None)
    return redirect("/")

@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect('honeypot.db')
    login_logs = conn.execute("SELECT * FROM logs ORDER BY timestamp DESC").fetchall()
    qr_logs = conn.execute("SELECT * FROM qr_logs ORDER BY timestamp DESC").fetchall()
    email_logs = conn.execute("SELECT * FROM email_logs ORDER BY timestamp DESC").fetchall()
    conn.close()

    try:
        with open("adaptive_honeypot_log.txt", "r") as f:
            adaptive_logs = f.readlines()
    except FileNotFoundError:
        adaptive_logs = ["❌ No adaptive honeypot logs."]

    return render_template("dashboard.html", logs=login_logs, qr_logs=qr_logs,
                           email_logs=email_logs, adaptive_logs=adaptive_logs)

@app.route('/login_form')
def login_form():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    ip = request.remote_addr
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ✅ If admin credentials, redirect to admin page
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        return redirect("/adminpage")

    # ✅ Else phishing login
    input_data = pd.DataFrame([[0] * 5000])
    prediction = int(model.predict(input_data)[0]) if model else 0

    conn = sqlite3.connect('honeypot.db')
    conn.execute("INSERT INTO logs (username, password, ip_address, timestamp, is_phishing) VALUES (?, ?, ?, ?, ?)",
                 (username, password, ip, timestamp, prediction))
    conn.commit()
    conn.close()

    if prediction == 1:
        send_telegram_alert(f"🚨 Phishing Login Detected!\nUser: {username}\nIP: {ip}\nTime: {timestamp}")
        return "🚨 Phishing Attempt Detected!"
    return "✅ Login Successful!"

@app.route("/adminpage")
def admin_page():
    if not session.get('admin_logged_in'):
        return redirect("/")
    return "<h2>✅ Welcome to the Admin Page!</h2><p>You are successfully logged in as admin.</p>"

@app.route('/log_qr_download')
def log_qr_download():
    ip = request.remote_addr
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = sqlite3.connect('honeypot.db')
    conn.execute("INSERT INTO qr_logs (ip_address, timestamp) VALUES (?, ?)", (ip, timestamp))
    conn.commit()
    conn.close()

    send_telegram_alert(f"📲 QR Code Download Detected!\nIP: {ip}\nTime: {timestamp}")
    return redirect("http://10.0.2.15:9090/fake_malware.exe")

@app.route('/adaptive_honeypot')
def adaptive_honeypot():
    session['start_time'] = time.time()
    session['login_attempts'] = 0
    selected_template = random.choice(adaptive_logins)
    session['ui_used'] = selected_template
    return render_template(f'login_variants/{selected_template}')

@app.route('/adaptive_submit', methods=['POST'])
def adaptive_submit():
    session['login_attempts'] += 1
    end_time = time.time()
    duration = end_time - session.get('start_time', end_time)
    user_agent = request.headers.get('User-Agent')
    ip = request.remote_addr
    username = request.form.get('username')
    password = request.form.get('password')

    deception_level = 1
    deception_page = session.get('ui_used', 'adaptive_honeypot_instagram.html')

    if session['login_attempts'] > 2 or duration < 1 or 'sqlmap' in user_agent.lower():
        deception_level = 3
        deception_page = 'adaptive_honeypot_facebook.html'
    if 'curl' in user_agent.lower():
        deception_level = 4
        deception_page = 'adaptive_honeypot_microsoft.html'

    readable_page = get_readable_page_name(deception_page)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert_message = f"""🎯 Adaptive Honeypot Triggered!
🧑‍💻 Username: {username}
🔑 Password: {password}
🌐 IP: {ip}
🕵‍♂ Agent: {user_agent}
📄 Page: {readable_page}
⚠ Deception Level: {deception_level}
🕒 Time: {timestamp}"""

    send_telegram_alert(alert_message)

    with open("adaptive_honeypot_log.txt", "a") as log:
        log.write(alert_message + "\n")

    return render_template(f'login_variants/{deception_page}')

@app.route("/adaptive_facebook")
def adaptive_facebook():
    return render_template("adaptive_honeypot_facebook.html")

@app.route("/adaptive_instagram")
def adaptive_instagram():
    return render_template("adaptive_honeypot_instagram.html")

@app.route("/adaptive_microsoft")
def adaptive_microsoft():
    return render_template("adaptive_honeypot_microsoft.html")

@app.route("/adaptive_logs")
def adaptive_logs():
    return render_template("adaptive_logs.html")

def export_csv(table, headers, filename):
    conn = sqlite3.connect('honeypot.db')
    rows = conn.execute(f"SELECT * FROM {table}").fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    output.seek(0)

    return send_file(io.BytesIO(output.getvalue().encode()),
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name=filename)

@app.route('/export_login_logs')
def export_login_logs():
    return export_csv('logs', ['ID', 'Username', 'Password', 'IP Address', 'Timestamp', 'Phishing'], 'login_logs.csv')

@app.route('/export_qr_logs')
def export_qr_logs():
    return export_csv('qr_logs', ['ID', 'IP Address', 'Timestamp'], 'qr_logs.csv')

@app.route('/export_email_logs')
def export_email_logs():
    return export_csv('email_logs', ['ID', 'Phishing URL', 'Timestamp'], 'email_logs.csv')

def start_email_scanner():
    while True:
        try:
            phishing_url = check_email()
            if phishing_url:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                conn = sqlite3.connect('honeypot.db')
                conn.execute("INSERT INTO email_logs (url, timestamp) VALUES (?, ?)", (phishing_url, timestamp))
                conn.commit()
                conn.close()
                send_telegram_alert(f"📧 Email Phishing URL Detected:\n{phishing_url}")
        except Exception as e:
            print(f"❌ Email scanner error: {e}")
        time.sleep(10)

def run_adaptive_simulator():
    while True:
        try:
            with open("adaptive_honeypot_log.txt", "a") as f:
                f.write(f"[{datetime.datetime.now()}] Simulated adaptive attack.\n")
        except Exception as e:
            print(f"❌ Adaptive simulator error: {e}")
        time.sleep(20)

if __name__ == '__main__':
    init_db()
    threading.Thread(target=start_email_scanner, daemon=True).start()
    threading.Thread(target=run_adaptive_simulator, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=True)
