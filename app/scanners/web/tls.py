# app/scanners/web/tls.py

import requests
from typing import List
from app.core.models import Finding
from app.core.explainer import enrich_finding

def scan_tls(target_url: str) -> List[Finding]:
    """
    Performs TLS and redirect checks against the target URL
    and returns fully enriched Finding objects.
    """
    findings = []
    
    try:
        response = requests.get(target_url, timeout=10, allow_redirects=True)
        
        # If the final landing page after redirects is still HTTP, it's a security flaw
        if not response.url.startswith("https://"):
            enriched_data = enrich_finding(
                finding_key="http-not-redirecting",
                target=target_url,
                custom_evidence=f"Request to {target_url} ended up on unencrypted URL: {response.url}"
            )
            findings.append(Finding(**enriched_data))
            
    except Exception as e:
        # Handle connection or request errors gracefully
        pass
        
    return findings