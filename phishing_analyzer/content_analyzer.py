import re

URGENCY_PHRASES = [
    "urgent", "immediately", "action required", "account suspended", "account locked",
    "verify your account", "password expired", "payment failed", "final notice",
    "unusual sign-in", "security alert", "confirm your identity", "click here",
    "limited time", "within 24 hours", "invoice attached", "reset your password"
]

CREDENTIAL_PHRASES = [
    "enter your password", "login to continue", "sign in to verify", "update your payment",
    "validate your mailbox", "confirm your credentials", "recover your account"
]

SUSPICIOUS_ATTACHMENTS = [".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso", ".img", ".hta", ".jar", ".ps1", ".lnk", ".zip", ".rar", ".7z"]

def analyze_content(text: str) -> tuple[int, list[str]]:
    score = 0
    findings = []
    lower = (text or "").lower()

    for phrase in URGENCY_PHRASES:
        if phrase in lower:
            score += 6
            findings.append(f"Urgency/social-engineering phrase found: '{phrase}'")

    for phrase in CREDENTIAL_PHRASES:
        if phrase in lower:
            score += 10
            findings.append(f"Credential-harvesting phrase found: '{phrase}'")

    attachment_pattern = re.compile(r"[\w\-. ]+(" + "|".join(re.escape(x) for x in SUSPICIOUS_ATTACHMENTS) + r")\b", re.I)
    for match in attachment_pattern.findall(text or ""):
        score += 15
        findings.append(f"Suspicious attachment type referenced: '{match}'")

    if lower.count("!") >= 3:
        score += 5
        findings.append("Excessive exclamation marks detected")

    return score, findings
