from app.scanners.web.headers import scan_headers

print("\n--- Running Header Security Scan ---")
target = "https://example.com"
issues = scan_headers(target)

print(f"Scanned Target: {target}")
print(f"Total Findings Found: {len(issues)}\n")

for finding in issues:
    print(f"[{finding.severity.value}] {finding.title}")
    print(f"   -> Explanation: {finding.plain_explanation}")
    print(f"   -> Remediation: {finding.remediation}\n")

print("====================================\n")