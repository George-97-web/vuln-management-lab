import json

with open("all_findings.json", "r") as f:
    data = json.load(f)

# Show ALL keys and ALL values for first 10 entries
print("=== ALL KEYS ACROSS ALL ENTRIES ===")
all_keys = set()
for entry in data:
    all_keys.update(entry.keys())
print(all_keys)

print("\n=== FULL ENTRY SAMPLE (first 5) ===")
for entry in data[:5]:
    # Only show non-empty values
    clean = {k: v for k, v in entry.items() if v and v not in ["Kali-Linux","kalilinuxreport.html","INFO","0.0","0.8"]}
    print(json.dumps(clean, indent=2))
    print("---")
