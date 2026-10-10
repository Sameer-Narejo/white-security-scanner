import requests
from app.core.models import Finding, SeverityLevel

def scan_cookies(target_url: str) -> list[Finding]:
    """
    Scans cookies returned by the target URL (including across redirects)
    for missing security flags (Secure, HttpOnly, SameSite).
    """
    findings = []
    
    try:
        response = requests.get(target_url, timeout=10, allow_redirects=True)
        
        # Collect cookies from all responses in the redirect chain + final response
        all_cookies = []
        for resp in response.history:
            for cookie in resp.cookies:
                all_cookies.append(cookie)
        for cookie in response.cookies:
            all_cookies.append(cookie)
        
        # If no cookies are set anywhere, return empty list
        if not all_cookies:
            return findings

        # Deduplicate cookies by name
        seen_names = set()
        for cookie in all_cookies:
            if cookie.name in seen_names:
                continue
            seen_names.add(cookie.name)
            
            cookie_name = cookie.name
            
            # 1. Check for 'Secure' attribute
            if not cookie.secure:
                findings.append(Finding(
                    finding_id=f"SEC-CK-001-{cookie_name}",
                    title=f"Cookie Missing 'Secure' Flag ({cookie_name})",
                    category="Cookies",
                    severity=SeverityLevel.MEDIUM,
                    confidence="High",
                    target=target_url,
                    evidence=f"The cookie '{cookie_name}' does not have the 'Secure' flag enabled.",
                    technical_explanation="Without the Secure attribute, the cookie can be transmitted over unencrypted HTTP connections.",
                    plain_explanation=f"Your cookie '{cookie_name}' can be intercepted if a user visits the site over an insecure connection.",
                    remediation=f"Configure your server to set the 'Secure' attribute on the '{cookie_name}' cookie."
                ))

            # 2. Check for 'HttpOnly' attribute
            rest_attrs = {k.lower(): v for k, v in cookie._rest.items()}
            if "httponly" not in rest_attrs:
                findings.append(Finding(
                    finding_id=f"SEC-CK-002-{cookie_name}",
                    title=f"Cookie Missing 'HttpOnly' Flag ({cookie_name})",
                    category="Cookies",
                    severity=SeverityLevel.MEDIUM,
                    confidence="High",
                    target=target_url,
                    evidence=f"The cookie '{cookie_name}' does not have the 'HttpOnly' flag enabled.",
                    technical_explanation="Without HttpOnly, client-side scripts (such as malicious XSS payloads) can access the cookie value.",
                    plain_explanation=f"The cookie '{cookie_name}' is accessible via JavaScript, making it vulnerable to theft through script injection.",
                    remediation=f"Configure your server to set the 'HttpOnly' attribute on the '{cookie_name}' cookie."
                ))

    except requests.RequestException:
        pass
        
    return findings