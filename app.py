from flask import Flask, request, jsonify, render_template
import sqlite3
from detector import PhishingDetector
from email_detector import EmailDetector
import datetime
import os

app = Flask(__name__)
detector = PhishingDetector()
email_detector = EmailDetector(url_detector=detector)

# Database setup
DB_PATH = 'scan_history.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  url TEXT, 
                  verdict TEXT, 
                  confidence REAL, 
                  timestamp TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    result = detector.analyze(url)
    
    # Save to history
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, verdict, confidence, timestamp) VALUES (?, ?, ?, ?)",
              (url, result['verdict'], result['confidence'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    
    return jsonify(result)

@app.route('/scan_email', methods=['POST'])
def scan_email():
    subject = request.form.get('subject', '')
    body = request.form.get('body', '')
    sender = request.form.get('sender', '')
    
    if not body and not subject:
        return jsonify({"error": "No content provided"}), 400
        
    result = email_detector.analyze_content(subject, body, sender)
    
    # Save to history (optional, or separate table)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, verdict, confidence, timestamp) VALUES (?, ?, ?, ?)",
              (f"Email: {subject[:30]}...", result['verdict'], result['confidence'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    
    return jsonify(result)

@app.route('/history')
def history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    
    scans = []
    for row in rows:
        scans.append({
            "id": row[0],
            "url": row[1],
            "verdict": row[2],
            "confidence": row[3],
            "timestamp": row[4]
        })
    return jsonify(scans)

if __name__ == '__main__':
    # Disable reloader if model isn't trained yet to avoid annoying errors
    app.run(debug=True, port=5000)
