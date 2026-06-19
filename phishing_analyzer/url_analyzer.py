import re
from urllib.parse import urlparse
import tldextract

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "lnkd.in", "shorturl.at", "s.id"
}

BRAND_KEYWORDS = {
    "microsoft", "office", "outlook", "onedrive", "sharepoint", "teams", "google",
    "apple", "paypal", "amazon", "netflix", "facebook", "instagram", "dhl", "auspost",
    "bank", "commbank", "nab", "westpac", "anz"
}

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "rest", "click"}

URL_RE = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.IGNORECASE)
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def extract_urls(text: str) -> list[str]:
    urls = URL_RE.findall(text or "")
    cleaned = []
    for url in urls:
        url = url.rstrip(".,);]\n\r")
        if url.startswith("www."):
            url = "http://" + url
        cleaned.append(url)
    return sorted(set(cleaned))

def _registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return urlparse(url).netloc.lower()

def analyze_urls(text: str) -> tuple[int, list[str]]:
    score = 0
    findings = []
    for url in extract_urls(text):
        parsed = urlparse(url)
        host = parsed.netloc.lower().split(":")[0]
        reg_domain = _registered_domain(url)
        ext = tldextract.extract(url)

        if parsed.scheme == "http":
            score += 10
            findings.append(f"URL uses HTTP, not HTTPS: {url}")

        if reg_domain in SHORTENER_DOMAINS:
            score += 15
            findings.append(f"Shortened URL detected: {url}")

        if IP_RE.match(host):
            score += 20
            findings.append(f"IP-address URL detected: {url}")

        if host.count(".") >= 4:
            score += 10
            findings.append(f"Excessive subdomains detected: {url}")

        if ext.suffix in SUSPICIOUS_TLDS:
            score += 10
            findings.append(f"Suspicious top-level domain '.{ext.suffix}' detected: {url}")

        # Simple typosquatting-style heuristic: brand keyword appears in subdomain/path but not real domain.
        url_lower = url.lower()
        for brand in BRAND_KEYWORDS:
            if brand in url_lower and brand not in ext.domain.lower():
                score += 12
                findings.append(f"Possible brand impersonation involving '{brand}': {url}")
                break

    return score, findings
