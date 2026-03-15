from bs4 import BeautifulSoup

with open("kalilinuxreport.html", "r", encoding="utf-8") as f:
    soup = BeautifulSoup(f, "html.parser")

# Find all tables and show raw cell counts per row
for i, table in enumerate(soup.find_all("table")[:5]):
    rows = table.find_all("tr")
    print(f"\n=== TABLE {i} — {len(rows)} rows ===")
    for j, row in enumerate(rows[:4]):  # first 4 rows of each table
        cells = row.find_all(["td","th"])
        print(f"  Row {j}: {len(cells)} cells →", [c.get_text(strip=True)[:40] for c in cells])


