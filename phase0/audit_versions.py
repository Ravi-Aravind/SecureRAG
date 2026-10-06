"""
audit_versions.py

Extracts all version strings from candidate_cves.json boundary matches,
analyzes their formats, and tests packaging.version compatibility.

This is an audit script — it produces no output files.
Run it, read the results, and discuss before proceeding.

Usage:
    python audit_versions.py
"""

import json
import re
import sys
from collections import Counter
from packaging.version import Version, InvalidVersion

CANDIDATES_PATH = "data/candidate_cves.json"

# Regex to extract the version number from a boundary match string.
# Captures the last contiguous version-like token in the match.
# We strip trailing punctuation (periods, commas) before parsing.
VERSION_EXTRACT_RE = re.compile(r"(\d+(?:\.\d+)+)[.,;]?\s*$")


def extract_version_string(match: str) -> str | None:
    """
    Given a boundary match string like 'before 2.4.52' or 'through 1.5.12.',
    extract just the version number, stripping trailing punctuation.
    Returns None if no version number can be extracted.
    """
    m = VERSION_EXTRACT_RE.search(match.strip())
    if m:
        return m.group(1)
    return None


def component_count(version_str: str) -> int:
    """Returns number of dot-separated components e.g. '2.4.52' -> 3"""
    return len(version_str.split("."))


def looks_like_calendar_version(version_str: str) -> bool:
    """
    Heuristic: if the first component is >= 2000, treat as calendar version.
    e.g. 2022.1.0, 2024.03.15
    """
    parts = version_str.split(".")
    try:
        return int(parts[0]) >= 2000
    except ValueError:
        return False


def has_prerelease_suffix(match_str: str) -> bool:
    """
    Check if the original match string contains prerelease indicators
    immediately after the version number.
    e.g. '2.4.52-beta', '3.1.0.alpha', '1.0rc1'
    """
    return bool(re.search(
        r"\d+(?:\.\d+)+[-.]?(?:alpha|beta|rc|pre|dev|a|b)\d*",
        match_str,
        re.IGNORECASE
    ))


def main():
    print(f"Loading candidates from {CANDIDATES_PATH}...")
    with open(CANDIDATES_PATH, "r", encoding="utf-8") as f:
        candidates = json.load(f)
    print(f"Loaded {len(candidates)} candidates.\n")

    # ------------------------------------------------------------------
    # Extract all version strings from all boundary matches
    # ------------------------------------------------------------------
    all_versions = []          # (cve_id, match_str, version_str)
    extraction_failures = []   # matches where we could not extract a version

    for cand in candidates:
        for match in cand.get("boundary_matches", []):
            vstr = extract_version_string(match)
            if vstr:
                all_versions.append((cand["cve_id"], match, vstr))
            else:
                extraction_failures.append((cand["cve_id"], match))

    print("=" * 60)
    print("VERSION EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Total boundary matches     : "
          f"{sum(len(c['boundary_matches']) for c in candidates)}")
    print(f"Successfully extracted     : {len(all_versions)}")
    print(f"Extraction failures        : {len(extraction_failures)}")

    if extraction_failures:
        print("\nSample extraction failures (first 10):")
        for cve_id, match in extraction_failures[:10]:
            print(f"  [{cve_id}] '{match}'")

    # ------------------------------------------------------------------
    # Component count distribution
    # ------------------------------------------------------------------
    comp_counts = Counter(component_count(v) for _, _, v in all_versions)
    print("\n" + "=" * 60)
    print("VERSION COMPONENT COUNT DISTRIBUTION")
    print("=" * 60)
    print("(e.g. '2.4.52' has 3 components, '6.1' has 2)")
    for count, freq in sorted(comp_counts.items()):
        bar = "#" * (freq // 50)
        print(f"  {count} components : {freq:6d}  {bar}")

    # ------------------------------------------------------------------
    # Calendar version detection
    # ------------------------------------------------------------------
    calendar_versions = [
        (cve_id, match, v)
        for cve_id, match, v in all_versions
        if looks_like_calendar_version(v)
    ]
    print("\n" + "=" * 60)
    print("CALENDAR VERSIONS (first component >= 2000)")
    print("=" * 60)
    print(f"Count: {len(calendar_versions)}")
    for cve_id, match, v in calendar_versions[:10]:
        print(f"  [{cve_id}] '{match}' -> '{v}'")

    # ------------------------------------------------------------------
    # Prerelease suffix detection
    # ------------------------------------------------------------------
    prerelease = [
        (cve_id, match, v)
        for cve_id, match, v in all_versions
        if has_prerelease_suffix(match)
    ]
    print("\n" + "=" * 60)
    print("PRERELEASE VERSIONS (alpha/beta/rc/dev etc.)")
    print("=" * 60)
    print(f"Count: {len(prerelease)}")
    for cve_id, match, v in prerelease[:10]:
        print(f"  [{cve_id}] '{match}' -> '{v}'")

    # ------------------------------------------------------------------
    # packaging.version compatibility test
    # ------------------------------------------------------------------
    parse_ok = []
    parse_fail = []

    for cve_id, match, v in all_versions:
        try:
            parsed = Version(v)
            parse_ok.append((cve_id, match, v, parsed))
        except InvalidVersion:
            parse_fail.append((cve_id, match, v))

    print("\n" + "=" * 60)
    print("packaging.version COMPATIBILITY")
    print("=" * 60)
    print(f"Parse OK    : {len(parse_ok)}")
    print(f"Parse FAIL  : {len(parse_fail)}")

    if parse_fail:
        print("\nSample parse failures (first 20):")
        for cve_id, match, v in parse_fail[:20]:
            print(f"  [{cve_id}] '{match}' -> '{v}'")

    # ------------------------------------------------------------------
    # Four-component version sample
    # ------------------------------------------------------------------
    four_comp = [
        (cve_id, match, v)
        for cve_id, match, v in all_versions
        if component_count(v) == 4
    ]
    print("\n" + "=" * 60)
    print("FOUR-COMPONENT VERSION SAMPLE (first 15)")
    print("=" * 60)
    print(f"Total four-component versions: {len(four_comp)}")
    for cve_id, match, v in four_comp[:15]:
        print(f"  [{cve_id}] '{match}' -> '{v}'")

    # ------------------------------------------------------------------
    # Two-component version sample
    # ------------------------------------------------------------------
    two_comp = [
        (cve_id, match, v)
        for cve_id, match, v in all_versions
        if component_count(v) == 2
    ]
    print("\n" + "=" * 60)
    print("TWO-COMPONENT VERSION SAMPLE (first 15)")
    print("=" * 60)
    print(f"Total two-component versions: {len(two_comp)}")
    for cve_id, match, v in two_comp[:15]:
        print(f"  [{cve_id}] '{match}' -> '{v}'")

    # ------------------------------------------------------------------
    # High-component versions (5+)
    # ------------------------------------------------------------------
    high_comp = [
        (cve_id, match, v)
        for cve_id, match, v in all_versions
        if component_count(v) >= 5
    ]
    print("\n" + "=" * 60)
    print("HIGH-COMPONENT VERSIONS (5+ components, first 15)")
    print("=" * 60)
    print(f"Count: {len(high_comp)}")
    for cve_id, match, v in high_comp[:15]:
        print(f"  [{cve_id}] '{match}' -> '{v}'")

    print("\n" + "=" * 60)
    print("AUDIT COMPLETE — Do not proceed until this is reviewed.")
    print("=" * 60)


if __name__ == "__main__":
    main()