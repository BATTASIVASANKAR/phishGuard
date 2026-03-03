# 🛡️ PhishGuard — AI-Powered Phishing Detection

PhishGuard is a Flask-based web application that uses Machine Learning to detect phishing URLs and emails. Built with a professional cybersecurity dark theme, it provides real-time analysis to help users identify potential phishing threats.

---

## ✨ Features

- **URL Scanner** — Analyze any URL for phishing indicators using a trained Random Forest ML model
- **Email Scanner** — Paste email content to detect phishing attempts using heuristic analysis
- **Help Center** — Comprehensive guide on phishing awareness and safety tips
- **Dark Cybersecurity Theme** — Modern, responsive UI with glassmorphism and animations
- **Render-Ready Deployment** — Includes `Procfile`, `requirements.txt`, and dynamic port binding

---

## 📂 Project Structure

```
phishguard/
├── app.py                 # Flask backend with all routes
├── model.pkl              # Trained ML model (Random Forest)
├── train_model.py         # Script to retrain the model
├── requirements.txt       # Python dependencies
├── Procfile               # Gunicorn config for Render
├── README.md              # This file
├── templates/
│   ├── index.html         # Homepage with URL & Email scanners
│   ├── result.html        # URL scan result page
│   ├── email_result.html  # Email scan result page
│   └── help.html          # Help & education page
└── static/
    └── style.css          # Dark cybersecurity theme
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd phishguard
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Train the model** (if `model.pkl` doesn't exist):
   ```bash
   python train_model.py
   ```

4. **Run the application:**
   ```bash
   python app.py
   ```

5. **Open your browser:**
   Navigate to `http://localhost:5000`

---

## 🌐 Deployment on Render

1. Push the project to a GitHub repository.
2. Create a new **Web Service** on [Render](https://render.com).
3. Connect your GitHub repo.
4. Render will automatically detect the `Procfile` and `requirements.txt`.
5. The app will be deployed and accessible via a public URL.

> PhishGuard uses dynamic port binding (`PORT` environment variable) for seamless cloud deployment.

---

## 🛠️ Tech Stack

| Component     | Technology                    |
|---------------|-------------------------------|
| Backend       | Flask (Python)                |
| ML Model      | scikit-learn (Random Forest)  |
| Frontend      | HTML5, CSS3, Jinja2           |
| Deployment    | Gunicorn, Render              |

---

## ⚠️ Disclaimer

> This tool is for **educational and cybersecurity awareness purposes only**. PhishGuard is not a replacement for professional cybersecurity solutions. No automated tool is 100% accurate. Always exercise caution and use multiple layers of security to protect yourself online.

---

## 📄 License

This project is open source under the [MIT License](LICENSE).
