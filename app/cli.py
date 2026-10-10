# app/cli.py
# app/cli.py

import typer
from typing import Optional
from app.core.target import parse_target
from app.core.models import ScanSummary
from app.core.reporting import generate_html_report, export_json_report
from app.scanners.web.headers import scan_headers
from app.scanners.web.cookies import scan_cookies
from app.scanners.web.tls import scan_tls

app = typer.Typer(help="SecuLens - AI-Assisted Pentesting & Security Assessment Platform")

@app.command()
def main(
    target: str = typer.Option(..., "--target", "-t", help="Authorized website URL or IP address to scan."),
    profile: str = typer.Option("full", "--profile", "-p", help="Scan profile: quick, full, or custom."),
    confirm: bool = typer.Option(False, "--confirm", help="Confirm that you own or have permission to test the target."),
    html: Optional[str] = typer.Option(None, "--html", help="Export stylized HTML report to specified filename."),
    json: Optional[str] = typer.Option(None, "--json", help="Export structured JSON report to specified filename.")
):
    """
    Run a safe security assessment against an authorized target.
    """
    typer.echo("[+] Initializing SecuLens scanner...")

    # 1. Parse and normalize target
    try:
        parsed_target = parse_target(target)
        typer.echo(f"[+] Target identified: {parsed_target.normalized_value} ({parsed_target.target_type})")
    except Exception as e:
        typer.echo(f"[!] Error parsing target: {e}")
        raise typer.Exit(code=1)

    # 2. Authorization and scope check
    if not confirm:
        typer.echo("\n[!] SAFETY & SCOPE CHECK:")
        typer.echo("SecuLens is designed for authorized defensive testing only.")
        is_confirmed = typer.confirm("Do you own this target or have explicit permission to test it?")
        if not is_confirmed:
            typer.echo("[!] Scan aborted. Authorization required.")
            raise typer.Exit(code=1)
    else:
        typer.echo("[+] Permission verified via command flag.")

    typer.echo(f"[+] Running profile: [{profile.upper()}]...")

    all_findings = []

    # 3. Execute Scanners based on profile
    try:
        typer.echo("[*] Running Header Security Check...")
        all_findings.extend(scan_headers(parsed_target.normalized_value))

        if profile.lower() in ["full", "standard"]:
            typer.echo("[*] Running Cookie Security Check...")
            all_findings.extend(scan_cookies(parsed_target.normalized_value))

            typer.echo("[*] Running TLS & Redirect Security Check...")
            all_findings.extend(scan_tls(parsed_target.normalized_value))

    except Exception as e:
        typer.echo(f"[!] An error occurred during scan execution: {e}")

    # 4. Print findings summary to terminal
    if not all_findings:
        typer.echo("\n[+] No security issues found! Excellent security posture.")
    else:
        typer.echo(f"\n==========================================")
        typer.echo(f"  SCAN RESULTS: {len(all_findings)} Finding(s) Discovered")
        typer.echo(f"==========================================")
        for finding in all_findings:
            severity_str = str(finding.severity).upper()
            typer.echo(f"[{severity_str}] {finding.title}")
            typer.echo(f"    -> Explanation: {finding.plain_explanation}")
            typer.echo(f"    -> Remediation: {finding.remediation}\n")

    # 5. Package into ScanSummary and export reports if requested
    if html or json:
        summary = ScanSummary(
            target=parsed_target.normalized_value,
            profile=profile,
            total_findings=len(all_findings),
            findings=all_findings
        )

        if html:
            try:
                generate_html_report(summary, output_path=html)
                typer.echo(f"[+] HTML Dashboard successfully exported to: {html}")
            except Exception as e:
                typer.echo(f"[!] Failed to export HTML report: {e}")

        if json:
            try:
                export_json_report(summary, output_path=json)
                typer.echo(f"[+] JSON report successfully exported to: {json}")
            except Exception as e:
                typer.echo(f"[!] Failed to export JSON report: {e}")

if __name__ == "__main__":
    app()