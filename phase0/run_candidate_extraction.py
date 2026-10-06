"""
run_candidate_extraction.py

Scans all CVE records, applies exclusion filters, and saves
candidate_cves.json.

Usage:
    python run_candidate_extraction.py
"""

import sys
import os
import json
import logging
from pathlib import Path
from tqdm import tqdm

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from cve_loader import iter_cve_records
from candidate_extractor import check_exclusions, extract_boundary_matches

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

CVELISTV5_ROOT = "data/raw/cvelistV5"
OUTPUT_PATH = "data/candidate_cves.json"
YEARS = [2022, 2023, 2024]


def main():
    print("Starting candidate extraction...")
    print(f"Source : {CVELISTV5_ROOT}")
    print(f"Years  : {YEARS}")
    print()

    # Counters
    total_parsed = 0
    exclusion_counts = {}
    candidates = []

    for record in tqdm(
        iter_cve_records(CVELISTV5_ROOT, years=YEARS),
        desc="Scanning CVEs",
        unit="rec",
    ):
        total_parsed += 1

        reason = check_exclusions(record)

        if reason is not None:
            exclusion_counts[reason] = exclusion_counts.get(reason, 0) + 1
            continue

        # Record passed — add boundary match info before saving
        matches = extract_boundary_matches(record["description"])
        record["boundary_matches"] = matches
        candidates.append(record)

    # ------------------------------------------------------------------
    # Save candidates
    # ------------------------------------------------------------------
    Path(OUTPUT_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(candidates, f, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Print report
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("CANDIDATE EXTRACTION REPORT")
    print("=" * 60)
    print(f"Total records parsed         : {total_parsed}")
    print(f"Candidates passing all checks: {len(candidates)}")
    print()
    print("Exclusion breakdown:")
    for reason, count in sorted(exclusion_counts.items(),
                                key=lambda x: -x[1]):
        print(f"  {reason:45s} : {count}")
    print()
    print(f"Output saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()