# Phishing Detection Tool

A Python/Streamlit portfolio project that analyses raw email text, headers, URLs, and message content to generate a phishing risk score.

## Features

- SPF/DKIM/DMARC result detection from headers
- From vs Reply-To mismatch detection
- Return-Path mismatch detection
- Suspicious URL detection
- Shortened URL detection
- IP-address URL detection
- Suspicious TLD detection
- Urgency and credential-harvesting phrase detection
- Suspicious attachment keyword detection
- Risk scoring and classification

## Setup

```bash
python -m venv venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows
pip install -r requirements.txt
streamlit run app.py
```

## Classification

- 0-34: Low Risk
- 35-69: Suspicious
- 70-100: Likely Phishing

## Disclaimer

This is a rule-based educational tool. It should support, not replace, professional security analysis.
