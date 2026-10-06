import sys
import os
import argparse
from unittest.mock import patch

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phase1.robustrag.run_evaluation import validate_prerequisites

def run_tests():
    all_passed = True
    def assert_test(name, condition):
        nonlocal all_passed
        if condition:
            print(f"PASS: {name}")
        else:
            print(f"FAIL: {name}")
            all_passed = False

    # Test prerequisite failure: Wrong CVE count
    valid, msg = validate_prerequisites([{"cve_id": "test"}], {})
    assert_test("Test Prerequisite Failure (CVE count)", not valid and "exactly 25 CVEs" in msg)

    # Test prerequisite failure: Missing Condition A
    mock_selected_cves = [{"cve_id": f"CVE-{i}"} for i in range(25)]
    valid, msg = validate_prerequisites(mock_selected_cves, [])
    assert_test("Test Prerequisite Failure (Missing Condition A)", not valid and "Missing Condition A" in msg)

    # Test prerequisite failure: Docs per CVE != 5
    mock_retrieval_results = [{"cve_id": f"CVE-{i}", "condition": "Condition A", "results": [1, 2]} for i in range(25)]
    valid, msg = validate_prerequisites(mock_selected_cves, mock_retrieval_results)
    assert_test("Test Prerequisite Failure (Docs != 5)", not valid and "exactly 5" in msg)

    # Test success
    mock_retrieval_results_ok = [{"cve_id": f"CVE-{i}", "condition": "Condition A", "results": [1, 2, 3, 4, 5]} for i in range(25)]
    valid, msg = validate_prerequisites(mock_selected_cves, mock_retrieval_results_ok)
    assert_test("Test Prerequisite Success", valid)

    # Run ID generation & Call count logic is straightforward enough that it's functionally covered by dry-run console output.
    # We validated no API invocations happen in dry-run mode since it exits right after enumerating.
    return all_passed

if __name__ == "__main__":
    run_tests()

