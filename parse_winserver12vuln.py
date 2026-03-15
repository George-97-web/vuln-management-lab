from bs4 import BeautifulSoup
import json

with open("winserver2012.html", "r", encoding="utf-8") as f:
    soup = BeautifulSoup(f, "html.parser")

findings = []

for table in soup.find_all("table"):
    rows = table.find_all("tr")
    if not rows:
        continue
    headers = [th.get_text(strip=True) for th in rows[0].find_all(["th","td"])]
    for row in rows[1:]:
        cols = [td.get_text(strip=True) for td in row.find_all("td")]
        if cols and headers:
            findings.append(dict(zip(headers, cols)))

with open("output.json", "w", encoding="utf-8") as f:
    json.dump(findings, f, indent=2)

print(f"Done - {len(findings)} findings saved to output.json")
