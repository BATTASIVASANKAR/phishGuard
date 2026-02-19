# Phishing Detection System

A Machine Learning-powered tool to identify phishing URLs using feature analysis, blacklist verification, and Random Forest classification.

## Features
- **URL Feature Extraction**: Analyzes 12+ features including length, dots, @ symbols, IP addresses, and suspicious keywords.
- **Machine Learning**: Uses a Random Forest model trained on labeled datasets.
- **Blacklist Verification**: Quick lookup against a database of known phishing domains.
- **Modern Dashboard**: Flask-based web interface with a dark cybersecurity theme.
- **Scan History**: Stores and displays past scans using SQLite.

## Tech Stack
- **Backend**: Python, Flask, Pandas, Scikit-learn
- **Frontend**: HTML5, CSS3 (Vanilla), JavaScript
- **Database**: SQLite3
- **Tools**: Joblib, TLDextract

## Project Structure
```text
phishing_detection_system/
├── app.py              # Flask Web Application
├── detector.py         # Detection Engine (Blacklist + ML)
├── model.py            # ML Training & Feature Extraction
├── dataset.csv         # Training Dataset
├── blacklist.csv       # Known Phishing Domains
├── requirements.txt    # Dependencies
├── static/
│   └── style.css       # UI Styling
└── templates/
    └── index.html      # UI Dashboard
```

## Setup & Usage

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train the Model
Run this once to extract features and train the ML model:
```bash
python model.py
```
This will generate `phishing_model.pkl` and `feature_names.pkl`.

### 3. Launch the Dashboard
```bash
python app.py
```
Open `http://localhost:5000` in your browser.

## URL Features Analyzed
1. **Length**: Phishing URLs are often unnaturally long.
2. **Dots Count**: Multiple subdomains or long paths.
3. **Presence of @**: Often used to hide the real domain.
4. **IP instead of Domain**: Classic phishing technique.
5. **HTTPS**: Checks for secure connection (though many phishing sites now use it).
6. **Keywords**: Scans for "login", "verify", "secure", etc.
7. **Path/Query Length**: Complex obfuscated paths.

## Disclaimer
This tool is for educational purposes. Always use official and verified links when entering sensitive information.
