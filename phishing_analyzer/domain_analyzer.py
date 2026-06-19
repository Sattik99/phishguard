from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import tldextract
import whois


def extract_domain_from_url(url: str) -> str:
    """
    Extracts the registered domain from a URL.

    Example:
    https://login.microsoft-security.example.com/path
    -> example.com
    """
    extracted = tldextract.extract(url)

    if not extracted.domain or not extracted.suffix:
        return ""

    return f"{extracted.domain}.{extracted.suffix}"


def calculate_domain_age_days(creation_date: Any) -> Optional[int]:
    """
    Calculates domain age in days using WHOIS creation date.

    WHOIS libraries may return:
    - a datetime object
    - a list of datetime objects
    - None
    """
    if creation_date is None:
        return None

    if isinstance(creation_date, list):
        creation_date = creation_date[0] if creation_date else None

    if creation_date is None:
        return None

    if not isinstance(creation_date, datetime):
        return None

    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    return (now - creation_date).days


def analyze_domain(domain: str) -> Dict[str, Any]:
    """
    Performs WHOIS lookup and basic domain intelligence analysis.
    """
    result = {
        "domain": domain,
        "creation_date": None,
        "registrar": None,
        "age_days": None,
        "risk_score": 0,
        "findings": [],
    }

    if not domain:
        result["findings"].append("Could not extract a valid domain.")
        result["risk_score"] += 5
        return result

    try:
        whois_data = whois.whois(domain)

        result["creation_date"] = str(whois_data.creation_date)
        result["registrar"] = str(whois_data.registrar)
        result["age_days"] = calculate_domain_age_days(whois_data.creation_date)

        if result["age_days"] is None:
            result["findings"].append("Domain creation date could not be determined.")
            result["risk_score"] += 5

        elif result["age_days"] <= 30:
            result["findings"].append("Domain is newly registered within the last 30 days.")
            result["risk_score"] += 25

        elif result["age_days"] <= 90:
            result["findings"].append("Domain was registered within the last 90 days.")
            result["risk_score"] += 15

        else:
            result["findings"].append("Domain age does not appear suspicious.")

    except Exception as error:
        result["findings"].append(f"WHOIS lookup failed: {error}")
        result["risk_score"] += 5

    return result


def analyze_domains_from_urls(urls: List[str]) -> Dict[str, Any]:
    """
    Extracts unique domains from URLs and performs domain analysis.
    """
    unique_domains = sorted(
        {
            extract_domain_from_url(url)
            for url in urls
            if extract_domain_from_url(url)
        }
    )

    domain_results = [analyze_domain(domain) for domain in unique_domains]

    total_score = sum(item["risk_score"] for item in domain_results)

    findings = []
    for item in domain_results:
        for finding in item["findings"]:
            findings.append(f"{item['domain']}: {finding}")

    return {
        "score": min(total_score, 30),
        "domains": domain_results,
        "findings": findings,
    }