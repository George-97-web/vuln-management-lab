from bs4 import BeautifulSoup

with open("kalilinuxreport.html", "r", encoding="utf-8") as f:
    content = f.read()

# Check 1: Are CVEs in JavaScript?
import re
js_cves = re.findall(r'CVE.{0,5}\d{4}.{0,5}\d{4,7}', content, re.IGNORECASE)
print(f"CVE pattern in JS/raw: {len(js_cves)}")
print("Sample:", js_cves[:5])

# Check 2: Look for plugin detail blocks
soup = BeautifulSoup(content, "html.parser")

# Check scripts for CVE data
scripts = soup.find_all("script")
print(f"\nScript tags found: {len(scripts)}")
for i, s in enumerate(scripts[:3]):
    text = s.get_text()[:300]
    if text.strip():
        print(f"\nScript {i}:", text[:200])

# Check 3: Look for any anchor tag linking to CVE databases
cve_links = soup.find_all("a", href=re.compile(r'cve|CVE', re.I))
print(f"\nCVE links found: {len(cve_links)}")
for link in cve_links[:5]:
    print(" →", link.get("href"), "|", link.get_text(strip=True))




