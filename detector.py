import joblib
import pandas as pd
from urllib.parse import urlparse
import tldextract
import os
from model import extract_features

class PhishingDetector:
    def __init__(self, model_path='phishing_model.pkl', blacklist_path='blacklist.csv'):
        self.model_path = model_path
        self.blacklist_path = blacklist_path
        self.model = None
        self.feature_names = None
        self.blacklist = set()
        
        self.load_resources()

    def load_resources(self):
        # Load Model
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                if os.path.exists('feature_names.pkl'):
                    self.feature_names = joblib.load('feature_names.pkl')
            except Exception as e:
                print(f"Error loading model: {e}")
        
        # Load Blacklist
        if os.path.exists(self.blacklist_path):
            try:
                df = pd.read_csv(self.blacklist_path)
                self.blacklist = set(df['domain'].str.lower().tolist())
            except Exception as e:
                print(f"Error loading blacklist: {e}")

    def check_blacklist(self, url):
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        return domain in self.blacklist

    def predict(self, url):
        if not self.model:
            return "Unknown (Model not trained)", 0.0, {}
        
        features = extract_features(url)
        # Reshape for prediction
        prediction = self.model.predict([features])[0]
        probabilities = self.model.predict_proba([features])[0]
        
        confidence = probabilities[prediction] * 100
        verdict = "PHISHING" if prediction == 1 else "SAFE"
        
        # Create a dictionary of features for display
        feature_data = {}
        if self.feature_names:
            feature_data = dict(zip(self.feature_names, features))
        
        return verdict, confidence, feature_data

    def analyze(self, url):
        # Result dictionary
        result = {
            "url": url,
            "verdict": "SAFE",
            "confidence": 100.0,
            "blacklist_match": False,
            "ml_prediction": "SAFE",
            "ml_confidence": 0.0,
            "features": {}
        }
        
        # 1. Blacklist Check
        if self.check_blacklist(url):
            result["verdict"] = "PHISHING"
            result["blacklist_match"] = True
            result["confidence"] = 100.0
            # Still run ML for features
            _, ml_conf, features = self.predict(url)
            result["features"] = features
            return result
        
        # 2. ML Prediction
        verdict, confidence, features = self.predict(url)
        result["verdict"] = verdict
        result["confidence"] = confidence
        result["ml_prediction"] = verdict
        result["ml_confidence"] = confidence
        result["features"] = features
        
        return result

if __name__ == "__main__":
    detector = PhishingDetector()
    urls = [
        "https://www.google.com",
        "http://free-gift-card.top/claim",
        "http://192.168.1.1/verify-account"
    ]
    
    for url in urls:
        print(f"\nAnalyzing: {url}")
        res = detector.analyze(url)
        print(f"Verdict: {res['verdict']} (Confidence: {res['confidence']:.2f}%)")
        if res['blacklist_match']:
            print("Detected via Blacklist!")
