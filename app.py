"""
PhishGuard — Flask Web Application for Phishing Detection
Uses ML model for URL scanning and heuristic analysis for email scanning.
"""

import os
import pickle
import re
import numpy as np
from flask import Flask, render_template, request

# ── App Setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)

# Load ML model
try:
    _base_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _base_dir = os.getcwd()
MODEL_PATH = os.path.join(_base_dir, 'model.pkl')
with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)


# ── Feature Extraction (URL) ────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'bank', 'confirm',
    'password', 'signin', 'credential', 'suspend', 'alert', 'expire',
    'unusual', 'restrict', 'wallet', 'paypal', 'ebay', 'apple', 'microsoft'
]

SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy'
]


def extract_features(url: str) -> list:
    """Extract numeric features from a URL string."""
    url_lower = url.lower()

    features = [
        len(url),                                                               # 0: length
        url_lower.count('.'),                                                   # 1: dot count
        url_lower.count('-'),                                                   # 2: dash count
        url_lower.count('@'),                                                   # 3: @ symbol
        url_lower.count('//'),                                                  # 4: double-slash count
        1 if 'https' in url_lower else 0,                                       # 5: has https
        1 if any(c.isdigit() for c in url_lower.split('/')[2]                   # 6: digits in domain
              if len(url_lower.split('/')) > 2) else 0,
        sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower),               # 7: suspicious keywords
        1 if any(sd in url_lower for sd in SHORTENER_DOMAINS) else 0,           # 8: shortener
        url_lower.count('/'),                                                   # 9: slash count
        url_lower.count('?'),                                                   # 10: query params
        url_lower.count('='),                                                   # 11: equals signs
        len(url_lower.split('/')[2]) if len(url_lower.split('/')) > 2           # 12: domain length
            else len(url_lower),
        1 if url_lower.count('.') > 4 else 0,                                  # 13: many subdomains
    ]
    return features


# ── Email Heuristic Analysis ────────────────────────────────────────────────

PHISHING_EMAIL_INDICATORS = {
    'urgency': [
        'immediately', 'urgent', 'right away', 'act now', 'expires today',
        'last warning', 'final notice', 'within 24 hours', 'limited time',
        'hurry', 'don\'t delay', 'time sensitive', 'deadline'
    ],
    'credential_request': [
        'verify your account', 'confirm your identity', 'update your password',
        'enter your credentials', 'verify your information', 'confirm your details',
        'reset your password', 'validate your account', 'update your information',
        'provide your details', 'verify your identity', 'login credentials'
    ],
    'threat': [
        'account will be suspended', 'account will be closed',
        'unauthorized access', 'suspicious activity', 'security alert',
        'account compromised', 'unusual sign-in', 'locked out',
        'account restricted', 'violation detected', 'permanently disabled'
    ],
    'reward': [
        'you have won', 'congratulations', 'prize', 'free gift',
        'claim your reward', 'lottery', 'selected as winner', 'cash prize',
        'million dollars', 'inheritance', 'unclaimed funds'
    ],
    'impersonation': [
        'dear customer', 'dear user', 'dear valued', 'dear account holder',
        'official notice', 'from the desk of', 'management team',
        'security department', 'technical support', 'helpdesk'
    ],
    'suspicious_links': [
        'click here', 'click below', 'click the link', 'click this',
        'follow the link', 'visit this link', 'open attachment',
        'download attachment', 'see attached', 'click to verify'
    ]
}

PHISHING_EMAIL_THRESHOLD = 3  # Minimum indicators to flag as phishing


def analyze_email(email_text: str) -> dict:
    """Analyze email content for phishing indicators."""
    text_lower = email_text.lower()
    found_indicators = {}
    total_score = 0

    for category, keywords in PHISHING_EMAIL_INDICATORS.items():
        matches = [kw for kw in keywords if kw in text_lower]
        if matches:
            found_indicators[category] = matches
            total_score += len(matches)

    # Check for suspicious patterns
    url_pattern = re.findall(r'https?://[^\s<>"\']+', text_lower)
    has_suspicious_urls = any(
        any(kw in url for kw in ['login', 'verify', 'secure', 'account', 'confirm'])
        for url in url_pattern
    )
    if has_suspicious_urls:
        total_score += 2

    # Check for excessive capitalization (shouting)
    words = email_text.split()
    caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
    if caps_words > 3:
        total_score += 1

    is_phishing = total_score >= PHISHING_EMAIL_THRESHOLD

    return {
        'is_phishing': is_phishing,
        'indicators': found_indicators,
    }


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    """Render the homepage."""
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    """Scan a URL for phishing indicators using ML model."""
    url = request.form.get('url', '').strip()

    if not url:
        return render_template('index.html', error='Please enter a URL to scan.')

    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        features = extract_features(url)
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        is_phishing = bool(prediction == 1)
    except Exception:
        is_phishing = False

    return render_template('result.html', url=url, is_phishing=is_phishing)


@app.route('/email_scan', methods=['POST'])
def email_scan():
    """Analyze email content for phishing indicators."""
    email_text = request.form.get('email_text', '').strip()

    if not email_text:
        return render_template('index.html', error='Please enter email content to analyze.')

    result = analyze_email(email_text)

    return render_template(
        'email_result.html',
        is_phishing=result['is_phishing'],
        indicators=result['indicators'],
    )


@app.route('/help')
def help_page():
    """Render the help page."""
    return render_template('help.html')


# ── Run ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
