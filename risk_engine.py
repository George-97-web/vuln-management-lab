from bs4 import BeautifulSoup
import json

REPORTS = [
    ("kalilinuxreport.html",              "Kali-Linux"),
    ("metasploitable.html",               "Metasploitable"),
    ("windows10scanreport_5rbsm5.html",   "Windows-10"),
    ("winserver2012.html",                "WinServer-2012"),
]

ASSET_WEIGHT = {
    "WinServer-2012": 1.5,
    "Metasploitable":  1.3,
    "Windows-10":      1.0,
    "Kali-Linux":      0.8,
}

SEV_CVSS = {
    "critical": 9.5,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
    "info":     0.0,
}

from datetime import datetime, timedelta

# ── SLA Definitions (days to remediate) ──────
SLA_DAYS = {
    "CRITICAL": 1,    # 24 hours
    "HIGH":     7,    # 7 days
    "MEDIUM":   30,   # 30 days
    "LOW":      90,   # 90 days
    "INFO":     None  # No SLA
}

PRIORITY = {
    "CRITICAL": "P1 - Immediate",
    "HIGH":     "P2 - Urgent",
    "MEDIUM":   "P3 - Scheduled",
    "LOW":      "P4 - Backlog",
    "INFO":     "P5 - Informational"
}

def add_sla(finding):
    sev = finding["severity_label"]
    days = SLA_DAYS.get(sev)
    scan_date = datetime.today()

    if days is not None:
        due_date = scan_date + timedelta(days=days)
        finding["scan_date"]        = scan_date.strftime("%Y-%m-%d")
        finding["sla_days"]         = days
        finding["remediation_due"]  = due_date.strftime("%Y-%m-%d")
        finding["priority"]         = PRIORITY.get(sev, "P5")
        finding["sla_status"]       = "OPEN - Within SLA"
    else:
        finding["scan_date"]        = scan_date.strftime("%Y-%m-%d")
        finding["sla_days"]         = "N/A"
        finding["remediation_due"]  = "N/A"
        finding["priority"]         = "P5 - Informational"
        finding["sla_status"]       = "NO SLA"

    return finding

def parse_html(filepath, asset_name):
    findings = []
    with open(filepath, "r", encoding="utf-8") as f:
        soup = BeautifulSoup(f, "html.parser")

    tables = soup.find_all("table")

    # Table 1 is the findings table (11 cells per row)
    # Row 1 = headers, Row 2+ = data
    for table in tables:
        rows = table.find_all("tr")
        for row in rows:
            cells = [c.get_text(strip=True) for c in row.find_all(["td","th"])]

            # Findings rows have 11 cells, severity at index 1
            if len(cells) == 11:
                severity_raw = cells[1].strip().lower()

                # Skip header rows
                if severity_raw == "severity" or severity_raw == "":
                    continue

                # Only process known severity values
                if severity_raw not in SEV_CVSS:
                    continue

                cvss_raw = cells[3].strip()
                try:
                    cvss = float(cvss_raw)
                except ValueError:
                    cvss = SEV_CVSS.get(severity_raw, 0.0)

                weight  = ASSET_WEIGHT.get(asset_name, 1.0)

                entry = {
                    "asset":          asset_name,
                    "source":         filepath,
                    "plugin_id":      cells[9],
                    "name":           cells[10],
                    "severity_label": severity_raw.upper(),
                    "cvss_base":      cvss,
                    "vpr_score":      cells[5],
                    "epss_score":     cells[7],
                    "asset_weight":   weight,
                    "risk_score":     round(cvss * weight, 2),
                }

                entry =add_sla(entry) 
                findings.append(entry) 
    return findings

# ── Run all reports ───────────────────────────
all_findings = []
for filepath, asset_name in REPORTS:
    try:
        results = parse_html(filepath, asset_name)
        all_findings.extend(results)
        print(f"✓ {asset_name}: {len(results)} findings")
    except FileNotFoundError:
        print(f"✗ Not found: {filepath}")

all_findings.sort(key=lambda x: x["risk_score"], reverse=True)

with open("all_findings.json", "w", encoding="utf-8") as f:
    json.dump(all_findings, f, indent=2)

crit  = sum(1 for f in all_findings if f["severity_label"] == "CRITICAL")
high  = sum(1 for f in all_findings if f["severity_label"] == "HIGH")
med   = sum(1 for f in all_findings if f["severity_label"] == "MEDIUM")
low   = sum(1 for f in all_findings if f["severity_label"] == "LOW")
info  = sum(1 for f in all_findings if f["severity_label"] == "INFO")

print(f"\n✓ Total: {len(all_findings)} findings → all_findings.json")
print(f"  🔴 Critical : {crit}")
print(f"  🟠 High     : {high}")
print(f"  🟡 Medium   : {med}")
print(f"  🟢 Low      : {low}")
print(f"  ⚪ Info     : {info}")

