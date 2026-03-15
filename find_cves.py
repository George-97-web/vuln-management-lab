from bs4 import BeautifulSoup

with open("kalilinuxreport.html", "r", encoding="utf-8") as f:
    soup = BeautifulSoup(f, "html.parser")

# Search for CVE patterns anywhere in the page
import re
cve_pattern = re.compile(r'CVE-\d{4}-\d+')
all_cves = cve_pattern.findall(str(soup))
print(f"CVEs found in page: {len(all_cves)}")
print("Sample:", all_cves[:10])
