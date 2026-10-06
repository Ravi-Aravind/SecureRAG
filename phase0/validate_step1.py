# save as validate_step1.py and run: python validate_step1.py

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from cve_loader import iter_cve_records

CVELISTV5_ROOT = "data/raw/cvelistV5"
YEARS = [2022, 2023, 2024]

total = 0
by_state = {}
by_year = {}
missing_vendor = 0

print("Counting records (this may take 1-2 minutes)...")

for record in iter_cve_records(CVELISTV5_ROOT, years=YEARS):
    total += 1
    state = record["state"]
    year = record["year"]
    by_state[state] = by_state.get(state, 0) + 1
    by_year[year] = by_year.get(year, 0) + 1
    if record["vendor"] == "UNKNOWN":
        missing_vendor += 1

print(f"\nTotal parsed records : {total}")
print(f"\nBy state:")
for state, count in sorted(by_state.items()):
    print(f"  {state:30s} : {count}")
print(f"\nBy year:")
for year, count in sorted(by_year.items()):
    print(f"  {year} : {count}")
print(f"\nRecords with UNKNOWN vendor : {missing_vendor}")