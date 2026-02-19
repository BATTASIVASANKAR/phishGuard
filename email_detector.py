import re
from detector import PhishingDetector

class EmailDetector:
    def __init__(self, url_detector=None):
        self.url_detector = url_detector or PhishingDetector()
        
        # Keywords commonly found in phishing emails
        self.urgency_keywords = ['urgent', 'important', 'action required', 'suspended', 'limited time', 'immediate']
        self.financial_keywords = ['bank', 'payment', 'invoice', 'transfer', 'account', 'verify', 'billing', 'refund', 'credit']
        self.spam_keywords = ['free', 'winner', 'gift', 'prize', 'claim', 'bonus', 'extra cash']

    def extract_urls(self, text):
        # A simple regex for URL extraction
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)

    def analyze_content(self, subject, body, sender=""):
        subject = subject.lower()
        body = body.lower()
        
        risk_score = 0
        reasons = []

        # 1. Subject Analysis
        urgency_found = [kw for kw in self.urgency_keywords if kw in subject]
        if urgency_found:
            risk_score += 20
            reasons.append(f"Urgency detected in subject: {', '.join(urgency_found)}")
            
        financial_found = [kw for kw in self.financial_keywords if kw in subject]
        if financial_found:
            risk_score += 15
            reasons.append(f"Financial keyword in subject: {', '.join(financial_found)}")

        # 2. Body Analysis
        spam_found = [kw for kw in self.spam_keywords if kw in body]
        if spam_found:
            risk_score += 25
            reasons.append(f"Promotional/Spam keywords in body: {', '.join(spam_found)}")

        # 3. URL Analysis
        urls = self.extract_urls(body)
        url_results = []
        highest_url_risk = 0
        
        for url in urls:
            res = self.url_detector.analyze(url)
            url_results.append(res)
            if res['verdict'] == 'PHISHING':
                highest_url_risk = max(highest_url_risk, res['confidence'])
        
        if highest_url_risk > 0:
            risk_score += highest_url_risk * 0.5  # Add weight from URL risk
            reasons.append(f"Malicious link detected ({int(highest_url_risk)}% confidence)")
        elif urls:
            reasons.append(f"Found {len(urls)} links in email body")

        # 4. Sender Analysis (Simple check)
        if sender:
            # Check if sender looks like a public domain but content is sensitive
            public_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
            sender_domain = sender.split('@')[-1] if '@' in sender else ""
            if sender_domain in public_domains and financial_found:
                risk_score += 15
                reasons.append("Sensitive request from a public email provider")

        # Final verdict
        confidence = min(100, risk_score)
        verdict = "PHISHING" if confidence > 50 else "SUSPICIOUS" if confidence > 30 else "SAFE"

        return {
            "verdict": verdict,
            "confidence": confidence,
            "reasons": reasons,
            "url_count": len(urls),
            "url_results": url_results
        }

if __name__ == "__main__":
    email_det = EmailDetector()
    sample_subject = "Action Required: Your Bank Account is Suspended"
    sample_body = "We noticed suspicious activity on your account. Please login here to verify: http://bank-secure-update.net/login"
    
    result = email_det.analyze_content(sample_subject, sample_body, "security@bank-no-reply.com")
    print(f"Verdict: {result['verdict']} (Confidence: {result['confidence']}%)")
    print("Reasons:", result['reasons'])
