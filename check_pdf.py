import pdfplumber

with pdfplumber.open("rescan_winserver2012_01.pdf") as pdf:
    for i, page in enumerate(pdf.pages[:3]):
        print(f"\n=== PAGE {i+1} ===")
        print(page.extract_text()[:500])

