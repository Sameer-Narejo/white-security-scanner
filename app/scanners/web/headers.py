# app/scanners/web/headers.py

import requests
from typing import List
from app.core.models import Finding
from app.core.explainer import enrich_finding

def scan_headers(target_url: str) -> List[Finding]:
    """
    Performs security header checks against the target URL
    and returns fully enriched Finding objects.
    """
    findings = []
    
    try:
        response = requests.get(target_url, timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # 1. Check for X-Frame-Options (Clickjacking protection)
        if "x-frame-options" not in headers:
            enriched_data = enrich_finding(
                finding_key="missing-x-frame-options",
                target=target_url,
                custom_evidence=f"Checked headers. Response headers received: {list(response.headers.keys())}"
            )
            findings.append(Finding(**enriched_data))
            
        # 2. Check for Strict-Transport-Security (HSTS)
        if "strict-transport-security" not in headers:
            enriched_data = enrich_finding(
                finding_key="missing-hsts",
                target=target_url,
                custom_evidence="Strict-Transport-Security (HSTS) header is absent from the response."
            )
            findings.append(Finding(**enriched_data))

    except Exception as e:
        # Handle connection or request errors gracefully
        pass
        
    return findings