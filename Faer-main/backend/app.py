import os
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
from ml_model import load_models

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for Vite Frontend

# Load machine learning models on start
email_model, email_vectorizer, url_model, url_vectorizer = load_models()

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.icu', '.cfd', '.work', '.click', '.info']
TRUSTED_DOMAINS = ['google.com', 'amazon.com', 'paypal.com', 'microsoft.com', 'apple.com', 'github.com', 'netflix.com', 'linkedin.com', 'zoom.us', 'wikipedia.org']

def extract_urls(text):
    if not text:
        return []
    return re.findall(r'https?://[^\s"\'<>]+', text)

def humanize(key):
    m = {
        'uses_http': 'Unencrypted HTTP connection',
        'is_ip_host': 'Numeric IP address instead of a branded domain',
        'suspicious_tld': 'High-risk domain extension',
        'brand_typosquat': 'Domain resembles a famous brand with alterations',
        'urgency_density': 'Heavy urgency or pressure wording',
        'sensitive_request': 'Requests for passwords or financial data',
        'spoofed_domain': 'Sender domain imitates a trusted organization',
        'live_blocklist_hit': 'Address appears on a live phishing blocklist'
    }
    return m.get(key, key.replace('_', ' '))

def score_to_verdict(score):
    if score >= 55: return 'Dangerous'
    if score >= 28: return 'Suspicious'
    return 'Safe'

# Vector 1: Email Gateway / API
@app.route('/api/analyze/email', methods=['POST'])
def analyze_email():
    data = request.get_json() or {}
    sender = data.get('sender', '')
    subject = data.get('subject', '')
    body = data.get('body', '')
    live_intel = data.get('liveIntel', {})

    # 1. Feature Extraction
    features = {}
    sender_lower = sender.lower()
    subject_lower = subject.lower()
    body_lower = body.lower()
    all_text = f"{subject_lower} {body_lower}"
    
    domain = ''
    m = re.search(r'@([a-z0-9.-]+)', sender_lower)
    if m:
        domain = m.group(1)

    features['spoofed_domain'] = 1 if re.search(r'paypa[l1]|amaz[o0]n|micros[o0]ft|g[o0]{2}gle', domain) else 0
    features['free_email_brand_claim'] = 1 if domain in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'] and re.search(r'paypal|amazon|microsoft|bank|irs|netflix', all_text) else 0
    features['suspicious_sender_tld'] = 1 if any(domain.endswith(t) for t in SUSPICIOUS_TLDS) else 0
    features['subject_urgency'] = 1 if re.search(r'urgent|immediately|frozen|final warning|act now', subject_lower) else 0
    features['body_urgency'] = 1 if sum(1 for w in ['urgent', 'verify', 'suspended', 'password', 'immediately'] if w in body_lower) >= 3 else 0
    features['sensitive_request'] = 1 if re.search(r'ssn|credit card|password|otp|routing|seed phrase|cvv', all_text) else 0
    features['trusted_sender'] = 1 if any(domain == d or domain.endswith('.' + d) for d in TRUSTED_DOMAINS) else 0

    # 2. Machine Learning Prediction on Email Content using Real Dataset Model
    full_email_content = f"Subject: {subject}\nSender: {sender}\n\n{body}"
    email_vec = email_vectorizer.transform([full_email_content])
    ml_prob = email_model.predict_proba(email_vec)[0][1] # Phishing probability
    ml_pred = int(email_model.predict(email_vec)[0])

    # 3. Correlation & Risk Scoring
    risk_factors = []
    for k, v in features.items():
        if v > 0 and k != 'trusted_sender':
            risk_factors.append(f"{humanize(k)} increases suspicion.")
    
    # Inject live intelligence feedback
    if live_intel.get('any_threat'):
        risk_factors.append("Address or content appears on a live phishing blocklist.")
        ml_prob = max(ml_prob, 0.85)

    base_score = ml_prob * 100
    if features['trusted_sender']:
        base_score = max(0, base_score - 35)
        risk_factors.append("Trusted domain verification reduces overall risk.")

    risk_score = min(100, round(base_score))
    verdict = score_to_verdict(risk_score)

    return jsonify({
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": min(98, 50 + int(risk_score / 2)),
        "risk_factors": list(set(risk_factors)),
        "why_suspicious": " ".join(list(set(risk_factors))) if risk_factors else "Message patterns resemble routine legitimate correspondence.",
        "feature_snapshot": features,
        "ml_probability": float(ml_prob)
    })

# Vector 2: Browser Extension / URL API
@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    data = request.get_json() or {}
    url = data.get('url', '')
    body_text = data.get('bodyText', '')
    live_intel = data.get('liveIntel', {})

    # 1. Feature Extraction
    features = {}
    hostname = url
    protocol = 'https'
    path = ''
    try:
        if not url.startswith('http'):
            parse_url = f"https://{url}"
        else:
            parse_url = url
        from urllib.parse import urlparse
        u = urlparse(parse_url)
        hostname = u.hostname or url
        protocol = u.scheme
        path = u.path + u.query
    except:
        pass

    subdomain_count = max(0, len(hostname.split('.')) - 2)
    domain_base = hostname.split('.')[0] if '.' in hostname else hostname
    content = f"{body_text} {path}".lower()

    features['uses_http'] = 1 if protocol == 'http' else 0
    features['is_ip_host'] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0
    features['suspicious_tld'] = 1 if any(hostname.endswith(t) for t in SUSPICIOUS_TLDS) else 0
    features['subdomain_heavy'] = 1 if subdomain_count >= 3 else 0
    features['digit_in_host'] = 1 if any(c.isdigit() for c in domain_base) else 0
    features['brand_typosquat'] = 1 if re.search(r'paypa[l1]|amaz[o0]n|g[o0]{2}gle|micros[o0]ft|app[l1]e|netf[l1]ix', hostname) else 0
    features['at_in_url'] = 1 if '@' in url else 0
    features['url_very_long'] = 1 if len(url) > 120 else 0
    features['trusted_domain'] = 1 if any(hostname == d or hostname.endswith('.' + d) for d in TRUSTED_DOMAINS) else 0

    # 2. Machine Learning Prediction on URL using Real Dataset Model
    url_vec = url_vectorizer.transform([url])
    ml_prob = url_model.predict_proba(url_vec)[0][1] # Phishing probability
    ml_pred = int(url_model.predict(url_vec)[0])

    # 3. Correlation & Risk Scoring
    risk_factors = []
    for k, v in features.items():
        if v > 0 and k != 'trusted_domain':
            risk_factors.append(f"{humanize(k)} increases suspicion.")

    if live_intel.get('any_threat'):
        risk_factors.append(live_intel.get('summary', "URL appears on a live blocklist."))
        ml_prob = max(ml_prob, 0.90)

    base_score = ml_prob * 100
    if features['trusted_domain']:
        base_score = max(0, base_score - 40)
        risk_factors.append("Trusted domain verification reduces overall risk.")

    risk_score = min(100, round(base_score))
    verdict = score_to_verdict(risk_score)

    return jsonify({
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": min(98, 50 + int(risk_score / 2)),
        "risk_factors": list(set(risk_factors)),
        "why_suspicious": " ".join(list(set(risk_factors))) if risk_factors else "Structural signals align with normal legitimate websites.",
        "feature_snapshot": features,
        "ml_probability": float(ml_prob)
    })

# Vector 3: Mobile Chat Connector API (SMS / WhatsApp / Chat messages)
@app.route('/api/analyze/chat', methods=['POST'])
def analyze_chat():
    data = request.get_json() or {}
    message = data.get('message', '')
    sender = data.get('sender', '') # Phone number or handle
    
    # Extract links in chat
    urls = extract_urls(message)
    url_threats = []
    highest_url_score = 0
    
    for url in urls:
        # Run ML URL Classifier
        url_vec = url_vectorizer.transform([url])
        prob = float(url_model.predict_proba(url_vec)[0][1])
        highest_url_score = max(highest_url_score, prob)
        url_threats.append({"url": url, "phishing_probability": prob})

    # Run ML Email/Text Classifier on Chat message text
    msg_vec = email_vectorizer.transform([message])
    chat_prob = float(email_model.predict_proba(msg_vec)[0][1])
    
    # Combined score
    combined_prob = max(chat_prob, highest_url_score)
    risk_score = min(100, round(combined_prob * 100))
    verdict = score_to_verdict(risk_score)
    
    risk_factors = []
    if chat_prob > 0.5:
        risk_factors.append("Chat content displays standard social engineering or urgency patterns.")
    if urls:
        risk_factors.append(f"Contains {len(urls)} embedded link(s).")
    if highest_url_score > 0.5:
        risk_factors.append("Contains a highly suspicious link with elevated phishing risks.")

    return jsonify({
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": min(98, 50 + int(risk_score / 2)),
        "risk_factors": risk_factors,
        "why_suspicious": " ".join(risk_factors) if risk_factors else "No malicious patterns detected in chat exchange.",
        "url_threats": url_threats,
        "chat_probability": chat_prob
    })

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "vectors": ["email_gateway", "browser_extension", "mobile_chat"]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
