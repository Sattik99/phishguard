# System Architecture

## High-Level Architecture

```text
User Input
    │
    ▼
Streamlit Interface
    │
    ▼
Email Analysis Engine
    │
 ┌──────────────┬──────────────┬──────────────┐
 ▼              ▼              ▼
Header       URL          Content
Analysis     Analysis     Analysis
 │              │              │
 └──────────────┴──────────────┘
                │
                ▼
         Risk Scoring Engine
                │
                ▼
          Classification
```

---

## Components

### app.py

Provides the Streamlit user interface and presents analysis results.

### analyzer.py

Acts as the orchestration layer.

Responsible for:

* Header analysis
* URL analysis
* Content analysis
* Risk score calculation

### header_analyzer.py

Performs email header inspection.

### url_analyzer.py

Performs URL extraction and URL risk assessment.

### content_analyzer.py

Performs phishing language detection.

### scoring.py

Calculates final risk score and classification.
