import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from dataset_loader import load_or_download_email_dataset, load_or_download_url_dataset

# Models dir
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

EMAIL_MODEL_PATH = os.path.join(MODELS_DIR, 'email_classifier.joblib')
EMAIL_VECTORIZER_PATH = os.path.join(MODELS_DIR, 'email_vectorizer.joblib')

URL_MODEL_PATH = os.path.join(MODELS_DIR, 'url_classifier.joblib')
URL_VECTORIZER_PATH = os.path.join(MODELS_DIR, 'url_vectorizer.joblib')

def train_email_classifier():
    print("Loading Email Dataset (Enron Ham + Public Phishing)...")
    df = load_or_download_email_dataset()
    
    print(f"Loaded {len(df)} emails.")
    # Map labels to 0 (Safe) and 1 (Phishing)
    # The dataset typically labels them as 'Safe Email' / 'Phishing Email' or similar. Let's make sure it handles both.
    df['target'] = df['label'].apply(lambda x: 1 if 'phish' in str(x).lower() else 0)
    
    X = df['text'].astype(str)
    y = df['target']
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Vectorizing email text with TF-IDF...")
    vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    print("Training Random Forest Classifier on Enron/Phishing Email dataset...")
    classifier = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    classifier.fit(X_train_vec, y_train)
    
    accuracy = classifier.score(X_test_vec, y_test)
    print(f"Email Classifier Trained successfully. Accuracy: {accuracy:.4f}")
    
    # Save model and vectorizer
    joblib.dump(classifier, EMAIL_MODEL_PATH)
    joblib.dump(vectorizer, EMAIL_VECTORIZER_PATH)
    print(f"Saved Email Model to {EMAIL_MODEL_PATH}")
    return classifier, vectorizer

def train_url_classifier():
    print("Loading URL Dataset (Benign/Legitimate + PhishTank/Public Phishing)...")
    df = load_or_download_url_dataset()
    
    print(f"Loaded {len(df)} URLs.")
    # Map labels to 0 (Benign) and 1 (Phishing/Malicious)
    # In rlilojr/Detecting-Malicious-URL-Machine-Learning, 'label' is usually 'benign' / 'malicious' or 'phishing'
    df['target'] = df['label'].apply(lambda x: 1 if str(x).lower() in ['phishing', 'malicious', 'bad', 'spam'] else 0)
    
    X = df['url'].astype(str)
    y = df['target']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("Vectorizing URLs with TF-IDF (char n-grams)...")
    # For URLs, char-level analyzer is much better because it captures sub-parts, domains, and keywords
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=10000)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    print("Training Random Forest Classifier on Phishing URLs...")
    classifier = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    classifier.fit(X_train_vec, y_train)
    
    accuracy = classifier.score(X_test_vec, y_test)
    print(f"URL Classifier Trained successfully. Accuracy: {accuracy:.4f}")
    
    # Save model and vectorizer
    joblib.dump(classifier, URL_MODEL_PATH)
    joblib.dump(vectorizer, URL_VECTORIZER_PATH)
    print(f"Saved URL Model to {URL_MODEL_PATH}")
    return classifier, vectorizer

def load_models():
    try:
        email_model = joblib.load(EMAIL_MODEL_PATH)
        email_vectorizer = joblib.load(EMAIL_VECTORIZER_PATH)
        print("Loaded existing Email models.")
    except:
        print("Training Email Classifier...")
        email_model, email_vectorizer = train_email_classifier()
        
    try:
        url_model = joblib.load(URL_MODEL_PATH)
        url_vectorizer = joblib.load(URL_VECTORIZER_PATH)
        print("Loaded existing URL models.")
    except:
        print("Training URL Classifier...")
        url_model, url_vectorizer = train_url_classifier()
        
    return email_model, email_vectorizer, url_model, url_vectorizer

if __name__ == '__main__':
    train_email_classifier()
    train_url_classifier()