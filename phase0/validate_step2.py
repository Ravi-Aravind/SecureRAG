# save as validate_step2.py

import json

with open("data/candidate_cves.json", "r", encoding="utf-8") as f:
    candidates = json.load(f)

print(f"Total candidates: {len(candidates)}")
print()

# Check year distribution
from collections import Counter
years = Counter(c["year"] for c in candidates)
print("By year:")
for y, count in sorted(years.items()):
    print(f"  {y}: {count}")

# Check all have boundary_matches
missing_matches = [c for c in candidates if not c.get("boundary_matches")]
print(f"\nCandidates missing boundary_matches: {len(missing_matches)}")

# Print 5 examples with their matched boundaries
print("\n5 example candidates:")
print("-" * 60)
for c in candidates[:5]:
    print(f"CVE     : {c['cve_id']}")
    print(f"Vendor  : {c['vendor']}")
    print(f"Product : {c['product']}")
    print(f"Matches : {c['boundary_matches']}")
    print(f"Desc    : {c['description'][:200]}")
    print("-" * 60)