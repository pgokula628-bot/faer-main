import os
import requests
import pandas as pd

# Paths
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DATA_DIR, exist_ok=True)

ENRON_CSV_PATH = os.path.join(DATA_DIR, 'enron_phishing_emails.csv')
URL_CSV_PATH = os.path.join(DATA_DIR, 'phishing_urls.csv')

# Public dataset URLs (using trusted repositories containing cleaned real-world datasets)
# 1. Combined Phishing and Enron Ham email dataset
EMAIL_DATASET_URL = "https://raw.githubusercontent.com/uzmabb182/Data_622/refs/heads/main/final_project_data_622/Phishing_Email.csv"

# 2. Labeled Malicious & Safe URLs (contains real phishing URLs from PhishTank / open sources)
URL_DATASET_URL = "https://raw.githubusercontent.com/rlilojr/Detecting-Malicious-URL-Machine-Learning/master/dataset.csv"

def download_file(url, dest_path):
    print(f"Downloading dataset from {url}...")
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        with open(dest_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"Downloaded successfully to {dest_path}")
        return True
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        return False

def load_or_download_email_dataset():
    if not os.path.exists(ENRON_CSV_PATH):
        success = download_file(EMAIL_DATASET_URL, ENRON_CSV_PATH)
        if not success:
            print("Creating fallback mock Enron / Phishing Email dataset to ensure backend starts...")
            create_fallback_email_dataset()
    
    try:
        df = pd.read_csv(ENRON_CSV_PATH)
        # Drop unnamed columns or unnecessary ones
        df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
        df = df.dropna()
        # Rename columns to standard: text, label
        if 'Email Text' in df.columns and 'Email Type' in df.columns:
            df = df.rename(columns={'Email Text': 'text', 'Email Type': 'label'})
        return df
    except Exception as e:
        print(f"Error loading email dataset: {e}")
        return create_fallback_email_dataset()

def load_or_download_url_dataset():
    if not os.path.exists(URL_CSV_PATH):
        success = download_file(URL_DATASET_URL, URL_CSV_PATH)
        if not success:
            print("Creating fallback URL dataset to ensure backend starts...")
            create_fallback_url_dataset()
            
    try:
        df = pd.read_csv(URL_CSV_PATH)
        df = df.dropna()
        # Standardize columns: url, label
        # In rlilojr/Detecting-Malicious-URL-Machine-Learning/master/dataset.csv, columns are usually 'url' and 'label'
        return df
    except Exception as e:
        print(f"Error loading URL dataset: {e}")
        return create_fallback_url_dataset()

def create_fallback_email_dataset():
    # Standard security training samples compiled from Enron ham and common phishing targets
    data = {
        'text': [
            # Enron Ham (routine corporate emails)
            "Subject: Meeting on Monday. Please review the updated schedule for the pipeline negotiations.",
            "Subject: Presentation Slides. Here are the slides for the Enron energy trading review tomorrow.",
            "Subject: Lunch Plans. Let us meet at the cafeteria at 12:30 PM to discuss the new project details.",
            "Subject: Quarterly Reports. The latest financial logs are ready for the board meeting review.",
            "Subject: Feedback requested. Please let me know your thoughts on the proposed timeline.",
            # Phishing emails
            "Subject: URGENT: Confirm your PayPal account security details immediately to avoid permanent suspension.",
            "Subject: Netflix Update: Your subscription has been frozen due to a declined credit card payment. Reactivate now.",
            "Subject: IRS Refund: You have an unclaimed tax refund of $1,250. Click here to confirm your SSN and bank details.",
            "Subject: Security Warning: Unauthorized login attempt detected from IP 192.168.1.99. Change password now.",
            "Subject: Action Required: Your bank account is locked. Verify your credentials using the attached link immediately."
        ],
        'label': [
            'Safe Email', 'Safe Email', 'Safe Email', 'Safe Email', 'Safe Email',
            'Phishing Email', 'Phishing Email', 'Phishing Email', 'Phishing Email', 'Phishing Email'
        ]
    }
    df = pd.DataFrame(data)
    df.to_csv(ENRON_CSV_PATH, index=False)
    print(f"Created fallback email dataset at {ENRON_CSV_PATH}")
    return df

def create_fallback_url_dataset():
    data = {
        'url': [
            # Benign websites (Enron reference + crawlable targets)
            "google.com", "wikipedia.org", "github.com", "amazon.com", "microsoft.com",
            "enron.com", "linkedin.com", "apple.com", "netflix.com", "zoom.us",
            # Phishing URLs
            "secure-login-paypal.com", "netflix-reactivate-billing.xyz", "irs-tax-refund-portal.net",
            "update-your-bank-alert.click", "amaz0n-security-check.work", "gmail-verify-password.buzz",
            "facebook-recovery-login.ga", "chase-bank-verify.cfd", "walmart-free-giftcard.ml", "fedex-tracking-package.top"
        ],
        'label': [
            'benign', 'benign', 'benign', 'benign', 'benign',
            'benign', 'benign', 'benign', 'benign', 'benign',
            'phishing', 'phishing', 'phishing', 'phishing', 'phishing',
            'phishing', 'phishing', 'phishing', 'phishing', 'phishing'
        ]
    }
    df = pd.DataFrame(data)
    df.to_csv(URL_CSV_PATH, index=False)
    print(f"Created fallback URL dataset at {URL_CSV_PATH}")
    return df

if __name__ == '__main__':
    print("Pre-fetching datasets...")
    load_or_download_email_dataset()
    load_or_download_url_dataset()
    print("Pre-fetching complete.")
