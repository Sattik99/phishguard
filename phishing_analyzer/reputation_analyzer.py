from typing import Any, Dict, List

import requests


URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def check_urlhaus(url: str) -> Dict[str, Any]:
    """
    Checks a URL against the URLhaus threat intelligence database.
    """
    result = {
        "url": url,
        "source": "URLhaus",
        "query_status": None,
        "threat": None,
        "url_status": None,
        "risk_score": 0,
        "findings": [],
    }

    try:
        response = requests.post(
            URLHAUS_API_URL,
            data={"url": url},
            timeout=10,
        )

        data = response.json()
        result["query_status"] = data.get("query_status")

        if data.get("query_status") == "ok":
            result["threat"] = data.get("threat")
            result["url_status"] = data.get("url_status")
            result["risk_score"] += 35
            result["findings"].append("URL found in URLhaus threat intelligence database.")

            if data.get("threat"):
                result["findings"].append(f"Threat classification: {data.get('threat')}")

            if data.get("url_status"):
                result["findings"].append(f"URL status: {data.get('url_status')}")

        elif data.get("query_status") == "no_results":
            result["findings"].append("URL was not found in URLhaus database.")

        else:
            result["findings"].append(f"URLhaus returned status: {data.get('query_status')}")

    except Exception as error:
        result["findings"].append(f"URLhaus lookup failed: {error}")
        result["risk_score"] += 0

    return result


def analyze_url_reputation(urls: List[str]) -> Dict[str, Any]:
    """
    Checks detected URLs against URLhaus.
    """
    reputation_results = [check_urlhaus(url) for url in urls]

    total_score = sum(item["risk_score"] for item in reputation_results)

    findings = []
    for item in reputation_results:
        for finding in item["findings"]:
            findings.append(f"{item['url']}: {finding}")

    return {
        "score": min(total_score, 35),
        "reputation": reputation_results,
        "findings": findings,
    }