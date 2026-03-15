# Vulnerability Management Home Lab

![Status](https://img.shields.io/badge/Status-Active-green)
![Tools](https://img.shields.io/badge/Tools-Nessus%20%7C%20Python%20%7C%20PowerBI-blue)

## Overview
A complete Vulnerability Management program built in a home lab 
environment simulating enterprise-grade security operations.

## Environment
| Asset | IP | OS | Role |
|---|---|---|---|
| WIN-SRV-2012 | 192.168.91.10 | Windows Server 2012 R2 | File Server |
| Windows-10 | 192.168.91.129 | Windows 10 | Workstation |
| Metasploitable | 192.168.234.128 | Ubuntu 8.04 | Vuln Target |
| Kali-Linux | 192.168.91.128 | Kali Linux | Scanner |

## Toolchain
- 🔍 **Nessus** — Vulnerability scanning and discovery
- 🐍 **Python** — ETL pipeline, CVE extraction, GitHub automation
- 🐙 **GitHub** — Remediation tracking and issue management  
- 📊 **Power BI** — Executive KPI dashboard and reporting
- 🖥️ **VMware** — Hypervisor for all lab VMs

## Project Phases
- [x] Phase 1 — Lab Setup & Asset Deployment
- [x] Phase 2 — Nessus Scanning & Discovery
- [x] Phase 3 — Python ETL Pipeline & CVE Extraction
- [x] Phase 4 — GitHub Issue Automation
- [ ] Phase 5 — Power BI Dashboard & Reporting

## Results
| Severity | Count | SLA |
|---|---|---|
| 🔴 Critical | 2 | 24 hours |
| 🟠 High | 6 | 7 days |
| 🟡 Medium | 20 | 30 days |
| 🟢 Low | 4 | 90 days |

## Key Findings
- **MS17-010 EternalBlue** (CVE-2017-0144) — WinServer-2012
- **Apache Tomcat Ghostcat** (CVE-2020-1938) — Metasploitable  
- **Debian OpenSSH Weak RNG** (CVE-2008-0166) — Metasploitable
- **SMBv1 Multiple Vulnerabilities** — WinServer-2012

## Repository Structure
\`\`\`
vuln-management-lab/
├── scripts/        ← Python ETL and parsing scripts
├── scans/          ← Nessus scan reports
├── data/           ← Parsed JSON findings
├── reports/        ← Power BI dashboard
└── README.md
\`\`\`
