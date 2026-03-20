import json
import requests
import os

# ── GitHub Config ─────────────────────────────
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO         = "George-97-web/vuln-management-lab"
API_URL      = f"https://api.github.com/repos/{REPO}/issues"

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

def create_issue(finding):
    sev   = finding["severity_label"]
    name  = finding["name"]
    asset = finding["asset"]
    ip    = finding["ip"]

    title = f"[{sev}] {name} — {asset} ({ip})"

    body = f"""## Vulnerability Details
| Field | Value |
|---|---|
| **Asset** | {asset} |
| **IP Address** | {ip} |
| **Plugin ID** | {finding['plugin_id']} |
| **CVE(s)** | {finding['cve']} |
| **CVSS Score** | {finding['cvss_base']} |
| **Risk Score** | {finding['risk_score']} (weighted) |
| **Severity** | {sev} |
| **Priority** | {finding['priority']} |
| **Tenable Link** | {finding['tenable_url']} |

## SLA
| Field | Value |
|---|---|
| **Scan Date** | {finding['scan_date']} |
| **Remediation Due** | {finding['remediation_due']} |
| **SLA Days** | {finding['sla_days']} days |
| **Status** | {finding['sla_status']} |

## Solution
{finding['solution']}

## Remediation Checklist
- [ ] Triaged and confirmed
- [ ] Remediation applied
- [ ] Re-scan completed
- [ ] Vulnerability verified fixed
- [ ] Issue closed with evidence
"""

    labels = [
        sev.lower(),
        asset.lower().replace(" ", "-"),
        "vulnerability"
    ]

    payload = {
        "title":  title,
        "body":   body,
        "labels": labels
    }

    response = requests.post(API_URL, headers=HEADERS, json=payload)

    if response.status_code == 201:
        print(f"  ✓ Created: {title[:70]}")
    else:
        print(f"  ✗ Failed ({response.status_code}): {title[:50]}")
        print(f"    {response.json().get('message', '')}")

# ── Load findings ─────────────────────────────
with open("cve_findings.json", "r") as f:
    findings = json.load(f)

# ── Only create issues for Critical and High ──
priority_findings = [
    f for f in findings
    if f["severity_label"] in ["CRITICAL", "HIGH"]
]

print(f"Creating GitHub Issues for {len(priority_findings)} Critical/High findings...\n")

for finding in priority_findings:
    create_issue(finding)

print(f"\n✓ Done — check your GitHub repository Issues tab")
