"""
inspect_cve.py

Loads a small sample of CVE records and prints them for manual inspection.
Run this to verify the parser is working correctly.

Usage:
    python inspect_cve.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from cve_loader import iter_cve_records

CVELISTV5_ROOT = "data/raw/cvelistV5"
YEARS = [2022, 2023, 2024]
SAMPLE_SIZE = 10  # number of records to print


def main():
    print(f"Reading CVE records from: {CVELISTV5_ROOT}")
    print(f"Years: {YEARS}")
    print(f"Printing first {SAMPLE_SIZE} successfully parsed records.\n")
    print("=" * 70)

    count = 0
    for record in iter_cve_records(CVELISTV5_ROOT, years=YEARS):
        print(f"CVE ID       : {record['cve_id']}")
        print(f"State        : {record['state']}")
        print(f"Date         : {record['date_published']}")
        print(f"Year         : {record['year']}")
        print(f"Vendor       : {record['vendor']}")
        print(f"Product      : {record['product']}")
        print(f"Description  : {record['description'][:300]}")
        print(f"Raw path     : {record['raw_path']}")
        print("-" * 70)

        count += 1
        if count >= SAMPLE_SIZE:
            break

    print(f"\nDone. Printed {count} records.")


if __name__ == "__main__":
    main()