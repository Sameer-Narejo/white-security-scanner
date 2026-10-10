# app/core/explainer.py

FINDING_DETAILS = {
    "missing-x-frame-options": {
        "title": "Missing X-Frame-Options Header",
        "category": "Headers",
        "severity": "Medium",
        "confidence": "High",
        "plain_explanation": "The website can be invisibly loaded inside another malicious website, tricking users into clicking unintended buttons.",
        "technical_explanation": "The HTTP response does not include the X-Frame-Options header, leaving it vulnerable to Clickjacking attacks.",
        "business_impact": "Loss of user trust and potential unauthorized actions performed on behalf of authenticated users via UI redressing.",
        "remediation": "Configure your web server to return the 'X-Frame-Options: SAMEORIGIN' header.",
        "references": ["https://owasp.org/www-community/attacks/Clickjacking"]
    },
    "missing-hsts": {
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "category": "TLS",
        "severity": "High",
        "confidence": "High",
        "plain_explanation": "Users could initially connect over an unencrypted connection, making their data vulnerable to interception.",
        "technical_explanation": "The HTTP response is missing the Strict-Transport-Security header, allowing protocol downgrade attacks.",
        "business_impact": "Data interception, credential theft, and man-in-the-middle attacks on initial page loads.",
        "remediation": "Configure your web server to include 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        "references": ["https://owasp.org/www-project-top-ten/"]
    },
    "http-not-redirecting": {
        "title": "HTTP Not Redirecting to HTTPS",
        "category": "TLS",
        "severity": "High",
        "confidence": "High",
        "plain_explanation": "Users who type your web address without 'https://' can be vulnerable to interception or traffic modification.",
        "technical_explanation": "The server responds over plain HTTP without enforcing a permanent (301) redirect to the secure HTTPS scheme.",
        "business_impact": "Exposure of sensitive user data transmitted before encryption is established.",
        "remediation": "Configure your web server to permanently redirect all incoming HTTP traffic to HTTPS using a 301 redirect.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"]
    }
}

def enrich_finding(finding_key: str, target: str, custom_evidence: str = "") -> dict:
    """
    Enriches a basic scanner alert with full dual-explanation metadata
    matching SecuLens specifications.
    """
    base = FINDING_DETAILS.get(finding_key, {
        "title": "Unknown Finding",
        "category": "General",
        "severity": "Low",
        "confidence": "Medium",
        "plain_explanation": "An unspecified security observation was noted.",
        "technical_explanation": "No specific technical details available.",
        "business_impact": "Minor security hygiene observation.",
        "remediation": "Review system configuration.",
        "references": []
    })
    
    return {
        "finding_id": finding_key,
        "title": base["title"],
        "category": base["category"],
        "severity": base["severity"],
        "confidence": base["confidence"],
        "target": target,
        "evidence": custom_evidence or "Observed during automated security checks.",
        "technical_explanation": base["technical_explanation"],
        "plain_explanation": base["plain_explanation"],
        "business_impact": base["business_impact"],
        "remediation": base["remediation"],
        "references": base["references"]
    }