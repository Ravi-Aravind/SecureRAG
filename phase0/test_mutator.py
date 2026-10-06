"""
test_mutator.py

Tests the mutation engine on the feasibility scan passing examples
and on synthetic edge cases.

Usage:
    python test_mutator.py
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from mutator import mutate_cve, increment_version, verify_probe_semantics

FEASIBILITY_PATH = "data/feasibility_scan.json"


def print_result(r):
    status = "PASS" if r.mutation_valid else "FAIL"
    print(f"[{status}] {r.cve_id}")
    print(f"  Vendor/Product   : {r.vendor} / {r.product}")
    print(f"  Original boundary: {r.original_boundary}")
    print(f"  Mutated boundary : {r.mutated_boundary}")
    print(f"  Probe version    : {r.probe_version}")
    print(f"  Diff changes     : {r.diff_changes}")
    print(f"  Probe semantic   : {r.probe_semantic_explanation}")
    if not r.mutation_valid:
        print(f"  FAILURE REASON   : {r.failure_reason}")
    print()


def test_synthetic():
    """Test on hand-crafted examples to verify logic."""
    print("=" * 60)
    print("SYNTHETIC TESTS")
    print("=" * 60)

    cases = [
        {
            "cve_id": "CVE-TEST-0001",
            "vendor": "Apache",
            "product": "HTTP Server",
            "description": (
                "A vulnerability in Apache HTTP Server versions "
                "before 2.4.52 allows remote attackers to execute "
                "arbitrary code."
            ),
        },
        {
            "cve_id": "CVE-TEST-0002",
            "vendor": "Example",
            "product": "Widget",
            "description": (
                "Widget versions 1.7.16.1 and earlier are affected."
            ),
        },
        {
            "cve_id": "CVE-TEST-0003",
            "vendor": "Fake",
            "product": "Product",
            "description": (
                # Version appears twice — should fail
                "Versions before 3.1.0. Fixed in 3.1.0."
            ),
        },
        {
            "cve_id": "CVE-TEST-0004",
            "vendor": "Calendar",
            "product": "App",
            "description": (
                # Calendar version — should fail
                "Versions prior to 2023.04.01 are affected."
            ),
        },
    ]

    for case in cases:
        result = mutate_cve(case)
        print_result(result)


def test_on_feasibility_passing():
    """Test on the CVEs that passed the feasibility scan."""
    print("=" * 60)
    print("FEASIBILITY PASSING CVEs")
    print("=" * 60)

    with open(FEASIBILITY_PATH, "r", encoding="utf-8") as f:
        scan_results = json.load(f)

    passing = [r for r in scan_results if r["passed"]]
    print(f"Testing {len(passing)} passing CVEs from feasibility scan.\n")

    valid_count = 0
    fail_count  = 0
    fail_reasons = {}

    for scan_r in passing:
        # Reconstruct a minimal record for mutate_cve
        record = {
            "cve_id":      scan_r["cve_id"],
            "vendor":      scan_r["vendor"],
            "product":     scan_r["product"],
            "description": scan_r["description_snippet"],
            # NOTE: description_snippet is truncated to 200 chars.
            # Some mutations may fail here that would pass on full text.
            # This is expected — we note it, not treat it as a bug.
        }
        result = mutate_cve(record)

        if result.mutation_valid:
            valid_count += 1
            print_result(result)
        else:
            fail_count += 1
            r = result.failure_reason or "unknown"
            fail_reasons[r] = fail_reasons.get(r, 0) + 1

    print(f"Valid mutations  : {valid_count}")
    print(f"Failed mutations : {fail_count}")
    if fail_reasons:
        print("Failure reasons (on truncated snippets — expected):")
        for r, c in sorted(fail_reasons.items(), key=lambda x: -x[1]):
            print(f"  {r}: {c}")


def test_probe_semantics_directly():
    """Directly verify the semantic logic for our increment-only attack."""
    print()
    print("=" * 60)
    print("PROBE SEMANTIC LOGIC VERIFICATION")
    print("=" * 60)

    cases = [
        # (original, mutated, probe, expected_ok)
        ("2.4.52", "2.4.53", "2.4.52", True),
        ("1.7.16.1", "1.7.16.2", "1.7.16.1", True),
        ("9.5.12", "9.5.13", "9.5.12", True),
        # Wrong probe — should fail
        ("2.4.52", "2.4.53", "2.4.51", False),
        # Probe already vulnerable in original — should fail
        ("2.4.52", "2.4.53", "2.4.50", False),
    ]

    all_ok = True
    for orig, mut, probe, expected in cases:
        ok, explanation = verify_probe_semantics(orig, mut, probe)
        status = "PASS" if ok == expected else "FAIL"
        if ok != expected:
            all_ok = False
        print(f"[{status}] original={orig} mutated={mut} probe={probe}")
        print(f"        expected={expected} got={ok}")
        print(f"        {explanation}")
        print()

    if all_ok:
        print("All probe semantic tests passed.")
    else:
        print("PROBE SEMANTIC TEST FAILURES DETECTED. Do not proceed.")


if __name__ == "__main__":
    test_synthetic()
    test_on_feasibility_passing()
    test_probe_semantics_directly()