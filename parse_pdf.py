import pdfplumber
import json
import re
from datetime import datetime, timedelta

# ── Asset IP to Name mapping ──────────────────
IP_TO_ASSET = {
    "192.168.91.10":  "WinServer-2012",
    "192.168.91.128": "Kali-Linux",
    "192.168.91.129": "Windows-10",
    "192.168.234.128":"Metasploitable",
}

ASSET_WEIGHT = {
    "WinServer-2012": 1.5,
    "Metasploitable":  1.3,
    "Windows-10":      1.0,
    "Kali-Linux":      0.8,
}

SLA_DAYS = {
    "CRITICAL": 1,
    "HIGH":     7,
    "MEDIUM":   30,
    "LOW":      90,
}

PRIORITY = {
    "CRITICAL": "P1 - Immediate",
    "HIGH":     "P2 - Urgent",
    "MEDIUM":   "P3 - Scheduled",
    "LOW":      "P4 - Backlog",
}

def get_severity(risk_text):
    r = risk_text.strip().upper()
    if "CRITICAL" in r: return "CRITICAL"
    if "HIGH"     in r: return "HIGH"
    if "MEDIUM"   in r: return "MEDIUM"
    if "LOW"      in r: return "LOW"
    return None

def add_sla(finding):
    sev   = finding["severity_label"]
    days  = SLA_DAYS.get(sev, 90)
    today = datetime.today()
    due   = today + timedelta(days=days)
    finding["scan_date"]       = today.strftime("%Y-%m-%d")
    finding["sla_days"]        = days
    finding["remediation_due"] = due.strftime("%Y-%m-%d")
    finding["priority"]        = PRIORITY.get(sev, "P4 - Backlog")
    finding["sla_status"]      = "OPEN - Within SLA"
    return finding

def parse_pdf(pdf_path):
    findings = []
    current_asset = None

    with pdfplumber.open(pdf_path) as pdf:
        full_text = ""
        for page in pdf.pages:
            full_text += page.extract_text() + "\n"

    # Split by IP address headers
    ip_pattern = re.compile(
        r'(192\.168\.\d+\.\d+)\s*\n',
        re.MULTILINE
    )

    # Split text into host sections
    sections = ip_pattern.split(full_text)

    # sections = [pre_text, ip1, block1, ip2, block2, ...]
    i = 1
    while i < len(sections) - 1:
        ip = sections[i].strip()
        block = sections[i + 1]
        asset_name = IP_TO_ASSET.get(ip, ip)
        i += 2

        # Split block into individual plugin sections by plugin ID pattern
        plugin_pattern = re.compile(
            r'(\d{4,6})\s+-\s+(.+?)\n',
            re.MULTILINE
        )

        plugin_matches = list(plugin_pattern.finditer(block))

        for j, match in enumerate(plugin_matches):
            plugin_id   = match.group(1).strip()
            plugin_name = match.group(2).strip()

            # Get text for this plugin until next plugin
            start = match.end()
            end   = plugin_matches[j + 1].start() if j + 1 < len(plugin_matches) else len(block)
            plugin_block = block[start:end]

            # Extract CVEs
            cves = re.findall(r'CVE\s+(CVE-\d{4}-\d+)', plugin_block)
            cve_string = ", ".join(sorted(set(cves))) if cves else "No CVE"

            # Skip findings with no CVE
            if not cves:
                continue

            # Extract Risk Factor / Severity
            risk_match = re.search(r'Risk Factor\s*\n\s*(\w+)', plugin_block)
            if not risk_match:
                continue
            severity = get_severity(risk_match.group(1))
            if not severity:
                continue

            # Extract CVSS v3 score (prefer v3, fallback v2)
            cvss3 = re.search(r'CVSS v3\.0 Base Score\s+([\d.]+)', plugin_block)
            cvss2 = re.search(r'CVSS v2\.0 Base Score\s+([\d.]+)', plugin_block)
            cvss = float(cvss3.group(1)) if cvss3 else (float(cvss2.group(1)) if cvss2 else 0.0)

            # Extract Solution
            sol_match = re.search(r'Solution\s*\n(.+?)(?:Risk Factor|See Also|References)', plugin_block, re.DOTALL)
            solution = sol_match.group(1).strip()[:300] if sol_match else "See Tenable plugin"

            weight = ASSET_WEIGHT.get(asset_name, 1.0)

            entry = {
                "asset":          asset_name,
                "ip":             ip,
                "plugin_id":      plugin_id,
                "name":           plugin_name,
                "severity_label": severity,
                "cvss_base":      cvss,
                "cve":            cve_string,
                "solution":       solution,
                "asset_weight":   weight,
                "risk_score":     round(cvss * weight, 2),
                "tenable_url":    f"https://www.tenable.com/plugins/nessus/{plugin_id}",
            }

            entry = add_sla(entry)
            findings.append(entry)

    return findings

# ── Run ───────────────────────────────────────
# WinServer-2012 rescan
findings_win = parse_pdf("rescan_winserver2012_01.pdf")

# Metasploitable rescan
findings_meta = parse_pdf("rescan_metasploitable_01.pdf")

# Original scan for Kali and Windows-10 only
findings_original = parse_pdf("nessus_report.pdf")

# Filter original to Kali and Windows-10 only
findings_others = [
    f for f in findings_original
    if f["asset"]  not in ["WinServer-2012", "Metasploitable"]
]

# Combine
all_findings = findings_win + findings_meta + findings_others
all_findings.sort(key=lambda x: x["risk_score"], reverse=True)

# Save
with open("cve_findings.json", "w", encoding="utf-8") as f:
    json.dump(all_findings, f, indent=2)

# Summary
from collections import Counter
sev_counts = Counter(f["severity_label"] for f in all_findings)

print(f"\n✓ Total CVE findings: {len(all_findings)} → cve_findings.json")
print(f"  🔴 Critical : {sev_counts.get('CRITICAL', 0)}")
print(f"  🟠 High     : {sev_counts.get('HIGH', 0)}")
print(f"  🟡 Medium   : {sev_counts.get('MEDIUM', 0)}")
print(f"  🟢 Low      : {sev_counts.get('LOW', 0)}")
print(f"\nTop 5 by Risk Score:")
for f in all_findings[:5]:
    print(f"  [{f['severity_label']}] {f['name'][:50]} | CVE: {f['cve'][:40]} | Score: {f['risk_score']}")



