import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
import tldextract
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

def extract_features(url):
    features = []
    
    # URL Length
    features.append(len(url))
    
    # Number of dots
    features.append(url.count('.'))
    
    # Presence of @ symbol
    features.append(1 if '@' in url else 0)
    
    # Presence of // (redirection)
    features.append(1 if url.rfind('//') > 7 else 0)
    
    # Number of hyphens
    features.append(url.count('-'))
    
    # Presence of IP address instead of domain
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    features.append(1 if re.search(ip_pattern, url) else 0)
    
    # Subdomain count
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    features.append(len(subdomain.split('.')) if subdomain else 0)
    
    # Path length
    parsed = urlparse(url)
    features.append(len(parsed.path))
    
    # Query length
    features.append(len(parsed.query))
    
    # HTTPS availability (1 if HTTPS, 0 if HTTP)
    features.append(1 if parsed.scheme == 'https' else 0)
    
    # Suspicious keywords
    keywords = ['login', 'verify', 'secure', 'update', 'account', 'bank', 'confirm', 'free', 'gift', 'prize', 'signin', 'webscr']
    found_keywords = sum([1 for kw in keywords if kw in url.lower()])
    features.append(found_keywords)
    
    return features

def train_model():
    print("Loading dataset...")
    df = pd.read_csv('dataset.csv')
    
    print("Extracting features...")
    X = []
    y = []
    
    for index, row in df.iterrows():
        X.append(extract_features(row['url']))
        y.append(row['label'])
        
    X = np.array(X)
    y = np.array(y)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    
    print("\nModel Evaluation:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    print("Saving model and features...")
    joblib.dump(model, 'phishing_model.pkl')
    
    # Also save the list of feature names for reference
    feature_names = [
        'url_length', 'num_dots', 'has_at', 'has_double_slash', 'num_hyphens', 
        'has_ip', 'subdomain_count', 'path_length', 'query_length', 'has_https', 'keyword_count'
    ]
    joblib.dump(feature_names, 'feature_names.pkl')
    
    print("Model saved to phishing_model.pkl")

if __name__ == "__main__":
    try:
        train_model()
    except Exception as e:
        print(f"Error during training: {e}")
