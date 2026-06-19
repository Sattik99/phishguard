# Risk Scoring Model

## Scoring Philosophy

Each phishing indicator contributes to the overall risk score.

Indicators with stronger correlation to phishing activity receive higher scores.

---

## Current Scoring

| Indicator                      | Points |
| ------------------------------ | ------ |
| SPF Failure                    | 20     |
| DKIM Failure                   | 20     |
| DMARC Failure                  | 20     |
| Reply-To Mismatch              | 15     |
| Return-Path Mismatch           | 15     |
| Suspicious URL                 | 15     |
| Urgency Language               | 10     |
| Credential Harvesting Language | 10     |
| Suspicious Attachment          | 10     |

---

## Classification

| Score Range | Result          |
| ----------- | --------------- |
| 0–34        | Low Risk        |
| 35–69       | Suspicious      |
| 70–100      | Likely Phishing |
