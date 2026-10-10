# app/core/reporting.py

import json
from pathlib import Path
from typing import List
from app.core.models import Finding, ScanSummary

def generate_html_report(summary: ScanSummary, output_path: str = "report.html") -> str:
    """
    Generates a professional styled HTML dashboard implementing the SecuLens
    dual-explanation requirement (Manager View vs. Developer View).
    """
    
    # Calculate counts by severity
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in summary.findings:
        sev = f.severity.capitalize()
        if sev in counts:
            counts[sev] += 1

    # Determine overall risk label based on findings
    overall_risk = "Low"
    if counts["Critical"] > 0 or counts["High"] > 0:
        overall_risk = "High"
    elif counts["Medium"] > 0:
        overall_risk = "Moderate"

    # Build HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuLens Security Assessment Report</title>
    <style>
        :root {{
            --primary: #0f172a;
            --accent: #2563eb;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #334155;
            --border: #e2e8f0;
            --high: #dc2626;
            --medium: #d97706;
            --low: #16a34a;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 40px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        header {{
            background: var(--primary);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }}
        header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
        }}
        header p {{
            margin: 5px 0;
            color: #94a3b8;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            border: 1px solid var(--border);
            text-align: center;
        }}
        .metric-card h3 {{
            margin: 0;
            font-size: 14px;
            color: #64748b;
            text-transform: uppercase;
        }}
        .metric-card .value {{
            font-size: 24px;
            font-weight: bold;
            margin-top: 10px;
            color: var(--primary);
        }}
        .finding-card {{
            background: var(--card-bg);
            border-radius: 8px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            overflow: hidden;
        }}
        .finding-header {{
            padding: 15px 20px;
            background: #f1f5f9;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }}
        .badge.High {{ background-color: var(--high); }}
        .badge.Medium {{ background-color: var(--medium); }}
        .badge.Low {{ background-color: var(--low); }}
        .finding-body {{
            padding: 20px;
        }}
        .view-section {{
            margin-bottom: 15px;
        }}
        .view-section h4 {{
            margin: 0 0 5px 0;
            font-size: 13px;
            text-transform: uppercase;
            color: #64748b;
            letter-spacing: 0.5px;
        }}
        .manager-view {{
            background: #eff6ff;
            border-left: 4px solid var(--accent);
            padding: 12px 15px;
            border-radius: 0 6px 6px 0;
            margin-bottom: 15px;
        }}
        .technical-view {{
            background: #f8fafc;
            border-left: 4px solid #64748b;
            padding: 12px 15px;
            border-radius: 0 6px 6px 0;
        }}
        .code-box {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 10px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 13px;
            margin-top: 5px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SecuLens Security Dashboard</h1>
            <p><strong>Target:</strong> {summary.target}</p>
            <p><strong>Profile:</strong> {summary.profile.upper()}</p>
            <p><strong>Overall Risk Rating:</strong> <span style="color: #facc15; font-weight: bold;">{overall_risk}</span></p>
        </header>

        <div class="metrics-grid">
            <div class="metric-card">
                <h3>Total Findings</h3>
                <div class="value">{summary.total_findings}</div>
            </div>
            <div class="metric-card">
                <h3>Critical / High</h3>
                <div class="value" style="color: var(--high);">{counts['Critical'] + counts['High']}</div>
            </div>
            <div class="metric-card">
                <h3>Medium</h3>
                <div class="value" style="color: var(--medium);">{counts['Medium']}</div>
            </div>
            <div class="metric-card">
                <h3>Low / Info</h3>
                <div class="value" style="color: var(--low);">{counts['Low'] + counts['Info']}</div>
            </div>
        </div>

        <h2>Detailed Security Findings</h2>
"""

    if not summary.findings:
        html_content += "<p>No security findings discovered. Excellent posture!</p>"
    else:
        for f in summary.findings:
            html_content += f"""
        <div class="finding-card">
            <div class="finding-header">
                <strong>{f.title}</strong>
                <span class="badge {f.severity}">{f.severity.upper()}</span>
            </div>
            <div class="finding-body">
                <div class="manager-view">
                    <h4>👔 Manager & Executive Summary</h4>
                    <p><strong>Impact:</strong> {f.business_impact}</p>
                    <p style="margin-bottom:0;"><strong>What it means:</strong> {f.plain_explanation}</p>
                </div>
                
                <div class="technical-view">
                    <h4>💻 Developer & Technical Details</h4>
                    <p><strong>Technical Reason:</strong> {f.technical_explanation}</p>
                    <p><strong>Observed Evidence:</strong></p>
                    <div class="code-box">{f.evidence}</div>
                    <p style="margin-top: 10px;"><strong>Recommended Fix:</strong> {f.remediation}</p>
                </div>
            </div>
        </div>
            """

    html_content += """
    </div>
</body>
</html>
    """

    Path(output_path).write_text(html_content, encoding="utf-8")
    return output_path


def export_json_report(summary: ScanSummary, output_path: str = "report.json") -> str:
    """Exports structured findings to JSON for automated tools and CI/CD."""
    Path(output_path).write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    return output_path