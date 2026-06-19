# PhishGuard

A Python-based phishing detection platform that analyses email headers, embedded URLs, and message content to identify phishing indicators and generate a phishing risk score.

Built as a cybersecurity portfolio project to demonstrate phishing analysis techniques, threat detection methodologies, and secure software development practices.

---

## Overview

Phishing remains one of the most common attack vectors used to compromise user accounts, steal credentials, distribute malware, and conduct Business Email Compromise (BEC) attacks.

PhishGuard aims to simulate a lightweight phishing analysis platform capable of identifying common indicators associated with malicious emails through a rule-based detection engine.

The platform evaluates:

* Email authentication results (SPF, DKIM, DMARC)
* Header inconsistencies
* Suspicious URLs
* Credential-harvesting language
* Urgency-based social engineering techniques
* Potentially malicious attachments

The results are aggregated into a phishing risk score and classification.

<img width="2527" height="835" alt="image" src="https://github.com/user-attachments/assets/fefd688c-c197-4fad-a71c-61fcf1ebc811" />

<img width="2483" height="1291" alt="image" src="https://github.com/user-attachments/assets/60e4af2c-8841-453b-884c-235799a89aff" />

---

## Features

### Header Analysis

* SPF failure detection
* DKIM failure detection
* DMARC failure detection
* From vs Reply-To mismatch detection
* Return-Path mismatch detection

### URL Analysis

* URL extraction
* HTTP vs HTTPS detection
* Shortened URL detection
* IP-address URL detection
* Suspicious TLD detection

### Content Analysis

* Urgency phrase detection
* Credential-harvesting language detection
* Social engineering indicators
* Suspicious attachment keyword detection

### Risk Scoring

* Rule-based scoring engine
* Risk classification
* Findings breakdown by category

---

## Documentation

* [Project Overview](docs/01_Project_Overview.md)
* [System Architecture](docs/02_System_Architecture.md)
* [Detection Methodology](docs/03_Detection_Methodology.md)
* [Risk Scoring Model](docs/04_Risk_Scoring_Model.md)
* [Threat Model](docs/05_Threat_Model.md)
* [Development Journal](docs/06_Development_Journal.md)
* [Future Enhancements](docs/07_Future_Enhancements.md)
* [Test Cases](docs/08_Test_Cases.md)

---

## Architecture

```text
User Input
    │
    ▼
Email Analysis Engine
    │
 ┌─────────────┬─────────────┬─────────────┐
 ▼             ▼             ▼
Header      URL          Content
Analysis    Analysis     Analysis
 │             │             │
 └─────────────┴─────────────┘
               │
               ▼
        Risk Scoring Engine
               │
               ▼
      Classification Result
```

---

## Project Structure

```text
phishguard/
│
├── app.py
├── requirements.txt
├── README.md
│
├── phishing_analyzer/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── header_analyzer.py
│   ├── url_analyzer.py
│   ├── content_analyzer.py
│   └── scoring.py
│
├── sample_emails/
│
└── docs/
```

---

## Technologies Used

| Technology                  | Purpose                               |
| --------------------------- | ------------------------------------- |
| Python                      | Core application logic                |
| Streamlit                   | User interface                        |
| Git                         | Version control                       |
| GitHub                      | Source control and project management |
| Regular Expressions (Regex) | Pattern matching                      |
| Email Header Analysis       | Phishing indicator detection          |

---

## Example Detection Indicators

| Indicator                      | Description                        |
| ------------------------------ | ---------------------------------- |
| SPF Failure                    | Email failed sender validation     |
| DKIM Failure                   | Email integrity validation failure |
| DMARC Failure                  | Domain authentication failure      |
| Reply-To Mismatch              | Different response destination     |
| Suspicious URL                 | Potential phishing destination     |
| Credential Harvesting Language | Password collection attempt        |
| Urgency Language               | Social engineering tactic          |

---

## Current Risk Classification

| Score  | Classification  |
| ------ | --------------- |
| 0–34   | Low Risk        |
| 35–69  | Suspicious      |
| 70–100 | Likely Phishing |

---

## Example Use Case

A security analyst receives a suspicious email claiming to be from Microsoft requesting immediate account verification.

PhishGuard analyses:

* Email authentication results
* Reply-To and Return-Path values
* Embedded URLs
* Credential harvesting language
* Social engineering indicators

The tool then generates:

* Risk score
* Classification
* Findings summary
* Indicator breakdown

---

## Roadmap

### Version 1 (Current)

* Rule-based phishing detection
* Streamlit interface
* Header analysis
* URL analysis
* Content analysis
* Risk scoring

### Version 2

* WHOIS integration
* Domain age analysis
* DNS intelligence
* Suspicious registrar detection

### Version 3

* VirusTotal integration
* URLHaus integration
* AbuseIPDB integration
* IOC enrichment

### Version 4

* PDF investigation reports
* Analyst dashboard
* Evidence export
* Historical analysis

---

## Security Disclaimer

This project is intended for educational and research purposes.

PhishGuard is not designed to replace enterprise-grade email security solutions and should not be relied upon as a sole phishing detection mechanism in production environments.

---

## Author

**Akib Sattik**

IT Support Specialist | Cybersecurity Enthusiast | Aspiring Security Engineer

GitHub: https://github.com/Sattik99
