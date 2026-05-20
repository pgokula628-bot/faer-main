# Threat Lens ML Datasets

Curated training samples inspired by public phishing research feeds (PhishTank, APWG, OpenPhish patterns). Used by `mlEngine.js` for baseline ensemble classification.

| File | Source style | Samples |
|------|----------------|---------|
| `phishing_urls.json` | PhishTank / APWG URL campaigns | Malicious website URLs + page text |
| `legitimate_urls.json` | Alexa / Tranco top sites | Safe controls |
| `phishing_emails.json` | APWG email campaigns | Phishing email bodies |
| `legitimate_emails.json` | Corporate / SaaS notifications | Safe controls |

Labels: `Dangerous`, `Suspicious`, `Safe`
