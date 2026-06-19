from .header_analyzer import analyze_headers
from .content_analyzer import analyze_content
from .url_analyzer import analyze_urls, extract_urls
from .domain_analyzer import analyze_domains_from_urls
from .reputation_analyzer import analyze_url_reputation
from .scoring import classify, cap_score


def analyze_email(raw_email: str) -> dict:
    header_score, header_findings, metadata = analyze_headers(raw_email)
    content_score, content_findings = analyze_content(raw_email)
    url_score, url_findings = analyze_urls(raw_email)

    urls = extract_urls(raw_email)

    domain_result = analyze_domains_from_urls(urls)
    reputation_result = analyze_url_reputation(urls)

    total = cap_score(
        header_score
        + content_score
        + url_score
        + domain_result["score"]
        + reputation_result["score"]
    )

    findings = (
        header_findings
        + content_findings
        + url_findings
        + domain_result["findings"]
        + reputation_result["findings"]
    )

    return {
        "score": total,
        "classification": classify(total),
        "metadata": metadata,
        "urls": urls,
        "domains": domain_result["domains"],
        "reputation": reputation_result["reputation"],
        "findings": findings
        or ["No major phishing indicators detected by current rules."],
        "breakdown": {
            "headers": header_score,
            "content": content_score,
            "urls": url_score,
            "domains": domain_result["score"],
            "reputation": reputation_result["score"],
        },
    }