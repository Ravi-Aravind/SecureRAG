"""
run_feasibility_scan.py

Randomly samples ~50 CVEs from candidate_cves.json and applies
the full Step-3-decided filter set to measure feasibility.

Produces feasibility_scan.json and a printed report.

Usage:
    python run_feasibility_scan.py
"""

import json
import re
import sys
import os
import random
from pathlib import Path
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

CANDIDATES_PATH = "data/candidate_cves.json"
OUTPUT_PATH = "data/feasibility_scan.json"
RANDOM_SEED = 42
SCAN_SIZE = 50

# ---------------------------------------------------------------------------
# Version extraction — fixed to handle "X and earlier" left-side patterns
# ---------------------------------------------------------------------------

# Right-side: "before 2.4.52", "prior to 1.7.16.1"
RIGHT_SIDE_RE = re.compile(
    r"(?:before|prior\s+to|earlier\s+than|up\s+to(?:\s+and\s+including)?|"
    r"through|fixed\s+in)\s+(?:version\s+)?(\d+(?:\.\d+)+)",
    re.IGNORECASE
)

# Left-side: "2.4.52 and earlier", "2.4.52 or earlier"
LEFT_SIDE_RE = re.compile(
    r"(\d+(?:\.\d+)+)\s+(?:and|or)\s+earlier",
    re.IGNORECASE
)


def extract_all_versions(description: str) -> list[str]:
    """
    Extract all version strings from a description using both
    right-side and left-side boundary patterns.
    Returns a list of raw version strings (may contain duplicates).
    """
    versions = []
    for m in RIGHT_SIDE_RE.finditer(description):
        versions.append(m.group(1))
    for m in LEFT_SIDE_RE.finditer(description):
        versions.append(m.group(1))
    return versions


# ---------------------------------------------------------------------------
# Component count helpers
# ---------------------------------------------------------------------------

def component_count(version_str: str) -> int:
    return len(version_str.split("."))


def is_calendar_version(version_str: str) -> bool:
    try:
        return int(version_str.split(".")[0]) >= 2000
    except ValueError:
        return False


def is_allowed_component_count(version_str: str) -> bool:
    return component_count(version_str) in (3, 4)


# ---------------------------------------------------------------------------
# Mutation logic — increment last component by 1
# ---------------------------------------------------------------------------

def increment_version(version_str: str) -> str:
    """
    Increment the last component of a version string by 1.
    e.g. '2.4.52' -> '2.4.53'
         '1.7.16.1' -> '1.7.16.2'
    """
    parts = version_str.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def mutation_is_safe(original_desc: str, original_ver: str) -> tuple[bool, str]:
    """
    Verify that the version string appears exactly once in the description
    and that it can be safely replaced by the incremented version.

    Returns (is_safe, reason).
    """
    count = original_desc.count(original_ver)
    if count == 0:
        return False, "version_not_found_in_description"
    if count > 1:
        return False, f"version_appears_{count}_times_ambiguous"

    mutated_ver = increment_version(original_ver)

    # Verify incremented version does not already appear in description
    if mutated_ver in original_desc:
        return False, "mutated_version_already_in_description"

    return True, "ok"


# ---------------------------------------------------------------------------
# High-profile / parametric contamination heuristic
# ---------------------------------------------------------------------------

# CVE IDs known to be very high-profile (famous vulnerabilities).
# We keep this list short — the parametric sensitivity test in Step 10
# is the real control. This is just a coarse pre-filter.
HIGH_PROFILE_CVE_IDS = {
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-45046",
    "CVE-2021-45105",
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2022-0847",   # Dirty Pipe
    "CVE-2022-30190",  # Follina
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2023-23397",  # Outlook NTLM
    "CVE-2023-34048",  # VMware vCenter
}

# If description contains these product strings, likely high-profile
HIGH_PROFILE_PRODUCTS = {
    "log4j", "log4shell", "spring framework",
}


def is_high_profile(record: dict) -> bool:
    if record["cve_id"] in HIGH_PROFILE_CVE_IDS:
        return True
    desc_lower = record["description"].lower()
    for term in HIGH_PROFILE_PRODUCTS:
        if term in desc_lower:
            return True
    return False


# ---------------------------------------------------------------------------
# Multi-product heuristic
# ---------------------------------------------------------------------------

def has_multiple_distinct_products(record: dict) -> bool:
    """
    Heuristic: if a description contains many version boundaries
    (>3 distinct version strings), it likely covers multiple products
    and is ambiguous for single-field mutation.
    """
    versions = extract_all_versions(record["description"])
    unique = set(versions)
    return len(unique) > 3


# ---------------------------------------------------------------------------
# Full feasibility filter
# ---------------------------------------------------------------------------

def assess_candidate(record: dict) -> dict:
    """
    Apply all feasibility filters to a single candidate record.

    Returns a dict with:
        cve_id, vendor, product, passed (bool),
        failure_reason (str or None),
        usable_versions (list),
        chosen_version (str or None),
        mutated_version (str or None),
        notes (list)
    """
    result = {
        "cve_id": record["cve_id"],
        "vendor": record["vendor"],
        "product": record["product"],
        "date_published": record["date_published"],
        "passed": False,
        "failure_reason": None,
        "usable_versions": [],
        "chosen_version": None,
        "mutated_version": None,
        "description_snippet": record["description"][:200],
        "notes": [],
    }

    desc = record["description"]

    # --- High-profile check ---
    if is_high_profile(record):
        result["failure_reason"] = "excluded_high_profile"
        return result

    # --- Multi-product heuristic ---
    if has_multiple_distinct_products(record):
        result["failure_reason"] = "excluded_multi_product"
        return result

    # --- Extract versions ---
    all_versions = extract_all_versions(desc)
    if not all_versions:
        result["failure_reason"] = "excluded_no_version_extracted"
        return result

    # --- Apply component and calendar filters ---
    usable = []
    for v in all_versions:
        if is_calendar_version(v):
            result["notes"].append(f"skipped_calendar:{v}")
            continue
        if not is_allowed_component_count(v):
            result["notes"].append(
                f"skipped_component_count_{component_count(v)}:{v}"
            )
            continue
        usable.append(v)

    if not usable:
        result["failure_reason"] = "excluded_no_usable_version_after_filters"
        return result

    result["usable_versions"] = usable

    # --- Choose the first usable version and test mutation safety ---
    # We prefer 3-component over 4-component (simpler, less ambiguous)
    three_comp = [v for v in usable if component_count(v) == 3]
    four_comp  = [v for v in usable if component_count(v) == 4]
    chosen = three_comp[0] if three_comp else four_comp[0]

    safe, reason = mutation_is_safe(desc, chosen)
    if not safe:
        result["failure_reason"] = f"excluded_mutation_unsafe:{reason}"
        return result

    result["chosen_version"] = chosen
    result["mutated_version"] = increment_version(chosen)
    result["passed"] = True
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"Loading candidates from {CANDIDATES_PATH}...")
    with open(CANDIDATES_PATH, "r", encoding="utf-8") as f:
        candidates = json.load(f)
    print(f"Loaded {len(candidates)} candidates.")

    # Deterministic random sample
    rng = random.Random(RANDOM_SEED)
    sample = rng.sample(candidates, min(SCAN_SIZE, len(candidates)))
    print(f"Sampled {len(sample)} candidates "
          f"(seed={RANDOM_SEED}).\n")

    # Assess each
    results = [assess_candidate(r) for r in sample]

    # Save
    Path(OUTPUT_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"]]
    failure_counts = Counter(r["failure_reason"] for r in failed)

    print("=" * 60)
    print("FEASIBILITY SCAN REPORT")
    print("=" * 60)
    print(f"Scanned         : {len(results)}")
    print(f"Passed          : {len(passed)}")
    print(f"Failed          : {len(failed)}")
    print(f"Pass rate       : {len(passed)/len(results)*100:.1f}%")
    print()
    print("Failure breakdown:")
    for reason, count in sorted(failure_counts.items(), key=lambda x: -x[1]):
        print(f"  {reason:50s} : {count}")

    print()
    print("=" * 60)
    print("PASSING EXAMPLES (first 5)")
    print("=" * 60)
    for r in passed[:5]:
        print(f"CVE     : {r['cve_id']}")
        print(f"Vendor  : {r['vendor']}")
        print(f"Product : {r['product']}")
        print(f"Chosen  : {r['chosen_version']}  ->  {r['mutated_version']}")
        print(f"Snippet : {r['description_snippet'][:180]}")
        print("-" * 60)

    print()
    print("=" * 60)
    print("FAILING EXAMPLES (first 5)")
    print("=" * 60)
    for r in failed[:5]:
        print(f"CVE     : {r['cve_id']}")
        print(f"Reason  : {r['failure_reason']}")
        print(f"Snippet : {r['description_snippet'][:180]}")
        print("-" * 60)

    print(f"\nFull results saved to: {OUTPUT_PATH}")
    print("\nAUDIT COMPLETE — send this output before proceeding to Step 5.")


if __name__ == "__main__":
    main()