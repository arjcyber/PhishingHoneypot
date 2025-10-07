import imaplib
import email
import requests
from bs4 import BeautifulSoup
import json
import time
import sqlite3
import datetime  # ✅ For timestamping log entries

# ✉️ Gmail Configuration
EMAIL_ACCOUNT = "xxxxxxxx"  # Replace with your Gmail
EMAIL_PASSWORD = "yxxxxxxxxxx"  # Use Google App Password
IMAP_SERVER = "imap.gmail.com"

# 🔍 VirusTotal API Key
VIRUSTOTAL_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# 🚨 Blacklisted Phishing Domains
BLACKLISTED_DOMAINS = ["phishingsite.com", "malicious.com", "hacker-attacks.com"]

# 🛑 Shortened URL Services (To Expand)
SHORTENED_SERVICES = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]

# 📢 Telegram Alert Configuration
TELEGRAM_BOT_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
CHAT_ID = "xxxxxxxxxx"


def send_telegram_alert(message):
    """Send phishing alert to Telegram."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    
    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("✅ Telegram alert sent successfully!")
        else:
            print(f"❌ Failed to send alert: {response.text}")
    except requests.RequestException as e:
        print(f"⚠️ Telegram Alert Error: {e}")


def expand_shortened_url(url):
    """Expand shortened URLs before scanning."""
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url  # Get final destination URL
    except requests.RequestException:
        return url  # Return original if expansion fails


def check_url_virustotal(url):
    """Check URL reputation on VirusTotal."""
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {"url": url}

    try:
        # Submit URL to VirusTotal
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        if response.status_code != 200:
            return False, f"❌ VirusTotal scan failed: {response.status_code} - {response.text}"

        response_data = response.json()
        url_id = response_data.get("data", {}).get("id")

        if not url_id:
            return False, "❌ VirusTotal scan failed: No analysis ID."

        # Wait for analysis
        time.sleep(15)  # Allow VirusTotal time to process

        # Fetch scan results
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        response = requests.get(analysis_url, headers=headers)
        analysis = response.json()

        # Check scan results
        stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
        malicious_count = stats.get("malicious", 0)

        if malicious_count > 0:
            return True, f"🚨 VirusTotal flagged {url} as MALICIOUS!"
        return False, f"✅ Safe URL: {url}"

    except Exception as e:
        return False, f"⚠️ Error checking VirusTotal: {e}"


def extract_links(html_content):
    """Extract all URLs from an email body."""
    soup = BeautifulSoup(html_content, "html.parser")
    links = [a["href"] for a in soup.find_all("a", href=True)]
    return links


def log_to_database(phishing_url):
    """Insert phishing URL and timestamp into SQLite database."""
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO email_logs (url, timestamp) VALUES (?, ?)", (phishing_url, timestamp))
        conn.commit()
        conn.close()
        print("📥 Logged phishing URL to database.")
    except Exception as e:
        print(f"⚠️ DB Logging Error: {e}")


def check_email():
    """Connect to Gmail, fetch unread emails, and scan links for phishing."""
    try:
        # Connect to Gmail IMAP
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
        mail.select("inbox")

        # Fetch unread emails
        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()

        if not email_ids:
            print("✅ No new unread emails.")
            return None  # No phishing detected

        print(f"📩 Found {len(email_ids)} unread emails.")
        phishing_detected = None  # Store the first phishing link detected

        # Process each email
        for email_id in email_ids:
            _, msg_data = mail.fetch(email_id, "(RFC822)")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            email_body = ""
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    email_body = part.get_payload(decode=True).decode(errors="ignore")

            # Extract URLs
            urls = extract_links(email_body)
            for url in urls:
                print(f"🔍 Checking URL: {url}")

                # Expand shortened URLs
                domain = url.split("//")[-1].split("/")[0]  # Extract domain
                if any(service in domain for service in SHORTENED_SERVICES):
                    expanded_url = expand_shortened_url(url)
                    print(f"🔄 Expanded Shortened URL: {expanded_url}")
                    url = expanded_url  # Use expanded URL

                # Check against local phishing list
                if any(blacklisted in url for blacklisted in BLACKLISTED_DOMAINS):
                    print(f"🚨 ALERT: {url} is a known phishing site!")
                    send_telegram_alert(f"🚨 ALERT: Phishing Email Detected!\nURL: {url}")
                    log_to_database(url)  # ✅ Log to DB
                    phishing_detected = url
                    continue

                # Check with VirusTotal
                is_phishing, result = check_url_virustotal(url)
                print(result)

                if is_phishing:
                    send_telegram_alert(f"🚨 ALERT: VirusTotal detected PHISHING!\nURL: {url}")
                    log_to_database(url)  # ✅ Log to DB
                    phishing_detected = url

        # Close connection
        mail.logout()
        return phishing_detected  # Return first phishing URL detected (or None)

    except Exception as e:
        print(f"❌ Error: {e}")
        return None


if __name__ == "__main__":
    check_email()
