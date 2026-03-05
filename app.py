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
def help_page():"""
PhishGuard — Flask Web Application for Phishing Detection
Uses ML model for URL scanning and heuristic analysis for email scanning.
Enhanced with URL validation, pattern analysis, risk levels, and robust error handling.
"""

import os
import pickle
import re
from urllib.parse import urlparse

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


# ── URL Validation ──────────────────────────────────────────────────────────

_URL_REGEX = re.compile(
    r'^https?://'                       # scheme
    r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*'  # subdomains
    r'(?:[A-Za-z]{2,}|'                 # TLD  OR
    r'\d{1,3}(?:\.\d{1,3}){3})'         # IPv4
    r'(?::\d+)?'                        # optional port
    r'(?:/[^\s]*)?$',                   # path
    re.IGNORECASE,
)


def validate_url(url: str) -> tuple[bool, str]:
    """Return (is_valid, error_message)."""
    if not url:
        return False, 'Please enter a URL to scan.'

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    if not _URL_REGEX.match(url):
        return False, 'Invalid URL format. Please enter a valid website URL (e.g. https://example.com).'

    return True, ''


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


# ── URL Pattern Analysis ────────────────────────────────────────────────────

_IP_DOMAIN_RE = re.compile(r'^https?://\d{1,3}(\.\d{1,3}){3}', re.IGNORECASE)


def analyze_url_patterns(url: str) -> dict:
    """Detect suspicious URL patterns and compute a heuristic risk score."""
    url_lower = url.lower()
    findings = []
    score = 0

    # 1. IP-based URL
    if _IP_DOMAIN_RE.match(url):
        findings.append('IP address used instead of domain name')
        score += 3

    # 2. Very long URL (>75 chars)
    if len(url) > 75:
        findings.append(f'Unusually long URL ({len(url)} characters)')
        score += 2

    # 3. @ symbol in URL (credential trick)
    if '@' in url:
        findings.append('"@" symbol detected — may redirect to a different site')
        score += 3

    # 4. Excessive dashes in domain
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    if hostname.count('-') >= 3:
        findings.append(f'Excessive dashes in domain ({hostname.count("-")} found)')
        score += 2

    # 5. Many subdomains (>3 dots in hostname)
    if hostname.count('.') > 3:
        findings.append(f'Excessive subdomains ({hostname.count(".") + 1} levels)')
        score += 2

    # 6. URL shortener
    if any(sd in url_lower for sd in SHORTENER_DOMAINS):
        findings.append('URL shortener detected — destination is hidden')
        score += 2

    # 7. Missing HTTPS
    if not url_lower.startswith('https://'):
        findings.append('No HTTPS encryption — connection is not secure')
        score += 1

    # 8. Suspicious keywords in URL
    matched_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_kw:
        findings.append(f'Suspicious keywords: {", ".join(matched_kw)}')
        score += min(len(matched_kw), 3)

    # 9. Suspicious characters
    special_chars = url_lower.count('%') + url_lower.count('~') + url_lower.count('^')
    if special_chars > 2:
        findings.append('Unusual encoded or special characters detected')
        score += 1

    return {'findings': findings, 'score': min(score, 10)}


def compute_url_risk(ml_phishing: bool, pattern_score: int) -> tuple[str, str]:
    """Combine ML prediction with pattern score to produce risk level and explanation."""
    if ml_phishing and pattern_score >= 4:
        return 'High', (
            'Both the ML model and pattern analysis flagged this URL as highly suspicious. '
            'Multiple phishing indicators were detected. Avoid visiting this site.'
        )
    if ml_phishing:
        return 'High', (
            'The ML model identified this URL as a phishing attempt. '
            'Exercise extreme caution and do not enter any personal information.'
        )
    if pattern_score >= 6:
        return 'High', (
            'Multiple suspicious patterns were detected in this URL. '
            'Although the ML model did not flag it, the URL exhibits high-risk characteristics.'
        )
    if pattern_score >= 3:
        return 'Medium', (
            'Some suspicious patterns were found in this URL. '
            'Proceed with caution and verify the site\'s legitimacy before entering any data.'
        )
    if pattern_score >= 1:
        return 'Low', (
            'Minor concerns were noted but the URL appears mostly safe. '
            'Always verify the source before sharing personal information.'
        )
    return 'Low', (
        'No significant threats were detected. '
        'This URL appears to be legitimate based on our analysis.'
    )


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
    ],
    'sensitive_info_request': [
        'social security', 'ssn', 'credit card number', 'bank account',
        'routing number', 'pin number', 'date of birth', 'mother\'s maiden',
        'tax return', 'financial information', 'billing address',
        'card verification', 'cvv', 'debit card'
    ],
    'spoofed_sender': [
        'noreply@', 'no-reply@', 'support@secure', 'admin@update',
        'service@account', 'alert@security', 'notification@verify'
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

    # Check for suspicious URLs in text
    url_pattern = re.findall(r'https?://[^\s<>"\']+', text_lower)
    suspicious_url_kws = ['login', 'verify', 'secure', 'account', 'confirm', 'update', 'password']
    has_suspicious_urls = any(
        any(kw in url for kw in suspicious_url_kws)
        for url in url_pattern
    )
    if has_suspicious_urls:
        found_indicators.setdefault('suspicious_links', []).append('embedded suspicious URL')
        total_score += 2

    # Check for IP-based URLs in email
    ip_urls = [u for u in url_pattern if _IP_DOMAIN_RE.match(u)]
    if ip_urls:
        found_indicators.setdefault('suspicious_links', []).append('IP-based URL found')
        total_score += 2

    # Check for excessive capitalization (shouting)
    words = email_text.split()
    caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
    if caps_words > 3:
        total_score += 1

    # Check for misspelled brand domains
    brand_misspellings = [
        'paypa1', 'paypai', 'amaz0n', 'amazom', 'g00gle', 'go0gle',
        'micros0ft', 'microsott', 'faceb00k', 'lnstagram', 'app1e'
    ]
    brand_hits = [b for b in brand_misspellings if b in text_lower]
    if brand_hits:
        found_indicators['spoofed_domains'] = brand_hits
        total_score += 3

    is_phishing = total_score >= PHISHING_EMAIL_THRESHOLD

    # Compute risk level
    risk_level, explanation = compute_email_risk(total_score, len(found_indicators), is_phishing)

    return {
        'is_phishing': is_phishing,
        'indicators': found_indicators,
        'risk_level': risk_level,
        'explanation': explanation,
    }


def compute_email_risk(total_score: int, category_count: int, is_phishing: bool) -> tuple[str, str]:
    """Determine email risk level and explanation."""
    if is_phishing and total_score >= 8:
        return 'High', (
            'Multiple strong phishing indicators detected across several categories. '
            'This email is very likely a phishing attempt. Do not click any links or provide information.'
        )
    if is_phishing and category_count >= 3:
        return 'High', (
            'Phishing indicators found in multiple categories — urgency, credential requests, and threats. '
            'This email has strong characteristics of a phishing attack.'
        )
    if is_phishing:
        return 'Medium', (
            'Some phishing indicators were detected. '
            'Treat this email with caution and verify the sender before taking any action.'
        )
    if total_score >= 2:
        return 'Low', (
            'A few minor indicators were noted but they may not be malicious. '
            'Stay cautious with unsolicited emails and verify the sender.'
        )
    return 'Low', (
        'No significant phishing indicators were found. '
        'This email appears to be safe based on our analysis.'
    )


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    """Render the homepage."""
    return render_template('index.html')


@app.route('/url-scanner')
def url_scanner():
    """Render the URL scanner page."""
    return render_template('url_scanner.html')


@app.route('/scan-url', methods=['POST'])
def scan_url():
    """Scan a URL for phishing indicators using ML model + pattern analysis."""
    url = request.form.get('url', '').strip()

    # ── Validation ──
    if not url:
        return render_template('url_scanner.html', error='Please enter a URL to scan.')

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    is_valid, error_msg = validate_url(url)
    if not is_valid:
        return render_template('url_scanner.html', error=error_msg)

    # ── Analysis ──
    try:
        # ML prediction
        features = extract_features(url)
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        ml_phishing = bool(prediction == 1)

        # Pattern analysis
        patterns = analyze_url_patterns(url)
        pattern_score = patterns['score']
        findings = patterns['findings']

        # Combined risk assessment
        is_phishing = ml_phishing or pattern_score >= 6
        risk_level, explanation = compute_url_risk(ml_phishing, pattern_score)

    except Exception as e:
        return render_template(
            'url_scanner.html',
            error=f'An error occurred while scanning the URL. Please try again.'
        )

    return render_template(
        'result.html',
        url=url,
        is_phishing=is_phishing,
        risk_level=risk_level,
        explanation=explanation,
        findings=findings,
    )


@app.route('/email-scanner')
def email_scanner():
    """Render the email scanner page."""
    return render_template('email_scanner.html')


@app.route('/scan-email', methods=['POST'])
def scan_email():
    """Analyze email content for phishing indicators."""
    email_text = request.form.get('email_text', '').strip()

    if not email_text:
        return render_template('email_scanner.html', error='Please enter email content to analyze.')

    try:
        result = analyze_email(email_text)
    except Exception as e:
        return render_template(
            'email_scanner.html',
            error='An error occurred while analyzing the email. Please try again.'
        )

    return render_template(
        'email_result.html',
        is_phishing=result['is_phishing'],
        indicators=result['indicators'],
        risk_level=result['risk_level'],
        explanation=result['explanation'],
    )


@app.route('/help')
def help_page():
    """Render the help page."""
    return render_template('help.html')


# ── Run ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

    """Render the help page."""
        return render_template('help.html')


# ── Run ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)


