def classify(score: int) -> str:
    if score >= 70:
        return "Likely Phishing"
    if score >= 35:
        return "Suspicious"
    return "Low Risk"

def cap_score(score: int) -> int:
    return max(0, min(100, score))
