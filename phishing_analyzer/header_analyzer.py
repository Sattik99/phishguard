from email import policy
from email.parser import Parser
from email.utils import parseaddr
import re
import tldextract

AUTH_FAIL_RE = re.compile(r"(spf|dkim|dmarc)=(fail|softfail|permerror|temperror|none)", re.I)

def _domain_from_address(value: str) -> str:
    _, addr = parseaddr(value or "")
    if "@" not in addr:
        return ""
    domain = addr.split("@", 1)[1].lower()
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else domain

def analyze_headers(raw_email: str) -> tuple[int, list[str], dict]:
    msg = Parser(policy=policy.default).parsestr(raw_email or "")
    score = 0
    findings = []

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    auth_results = " ".join(msg.get_all("Authentication-Results", []))

    from_domain = _domain_from_address(from_header)
    reply_domain = _domain_from_address(reply_to)
    return_path_domain = _domain_from_address(return_path)

    if reply_to and from_domain and reply_domain and from_domain != reply_domain:
        score += 20
        findings.append(f"From domain and Reply-To domain differ: {from_domain} vs {reply_domain}")

    if return_path and from_domain and return_path_domain and from_domain != return_path_domain:
        score += 10
        findings.append(f"From domain and Return-Path domain differ: {from_domain} vs {return_path_domain}")

    for mechanism, result in AUTH_FAIL_RE.findall(auth_results):
        mechanism = mechanism.upper()
        result = result.lower()
        points = 20 if mechanism in {"SPF", "DMARC"} and result == "fail" else 10
        score += points
        findings.append(f"Authentication issue: {mechanism}={result}")

    metadata = {
        "subject": msg.get("Subject", ""),
        "from": from_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_path_domain,
    }
    return score, findings, metadata
