from flask import Flask, request, jsonify
import re
import requests
import sqlite3

app = Flask(__name__)

# Initialize the database
def init_db():
    conn = sqlite3.connect("phishnet.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """
    )
    conn.commit()
    conn.close()

init_db()

# Phishing detection function
def detect_phishing(url):
    try:
        # PhishTank API
        phishtank_url = "https://phishtank.org/phish_search.php?valid=y&active=All&Search=Search"
        phishtank_response = requests.get(phishtank_url, params={"url": url})
        if "phish" in phishtank_response.text:
            return True

        # OpenPhish API
        openphish_url = "https://mailer-sender.vercel.app/openphish"
        openphish_response = requests.get(openphish_url)
        if url in openphish_response.text:
            return True

        # Validin API
        validin_url = "https://raw.githubusercontent.com/MikhailKasimov/validin-phish-feed/refs/heads/main/validin-phish-feed.txt"
        validin_response = requests.get(validin_url)
        if url in validin_response.text:
            return True
    except Exception as e:
        print(f"Error during API request: {e}")
        return False

    return False

# Report submission function
def submit_report(url, reason):
    try:
        conn = sqlite3.connect("phishnet.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO reports (url, reason) VALUES (?, ?)", (url, reason))
        conn.commit()
        conn.close()
        return {"status": "success", "url": url, "reason": reason}
    except Exception as e:
        print(f"Error saving report: {e}")
        return {"status": "error", "message": "Failed to save report"}

# URL validation function
def is_valid_url(url):
    regex = re.compile(
        r'^(https?:\/\/)?'  # Optional scheme
        r'(([a-zA-Z0-9_\-]+\.)+[a-zA-Z]{2,})'  # Domain
        r'(\/.*)?$'  # Optional path
    )
    return re.match(regex, url) is not None

# API endpoint to check phishing
@app.route("/detect", methods=["POST"])
def api_detect_phishing():
    data = request.json
    url = data.get("url")

    if not url or not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    is_phishing = detect_phishing(url)
    return jsonify({"url": url, "is_phishing": is_phishing})

# API endpoint to submit a report
@app.route("/report", methods=["POST"])
def api_submit_report():
    data = request.json
    url = data.get("url")
    reason = data.get("reason")

    if not url or not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400
    if not reason or len(reason.strip()) == 0:
        return jsonify({"error": "Reason is required"}), 400

    report = submit_report(url, reason)
    return jsonify(report)

# Default route
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "PhishNet API is running!"})

if __name__ == "__main__":
    app.run(debug=True)