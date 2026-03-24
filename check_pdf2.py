import pdfplumber

with pdfplumber.open("rescan_winserver2012_01.pdf") as pdf:
    print(f"Total pages: {len(pdf.pages)}")
    for i, page in enumerate(pdf.pages):
        text = page.extract_text()
        print(f"\n=== PAGE {i+1} ===")
        print(text[:800])
        print("---")
        