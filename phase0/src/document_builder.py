"""
document_builder.py

Step 7: Document generation and verification for RAG poisoning experiment.

This module reads selected CVEs from data/selected_cves.json, generates
indexed document text for original and mutated versions of each CVE,
computes unified line diffs, verifies diff validity, and saves results to
data/documents.json.

Indexed Document Format:
{CVE_ID} {PRODUCT} {VENDOR}
{FULL_DESCRIPTION}

Usage:
    python src/document_builder.py
"""

import difflib
import json
import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def format_document(cve_id: str, product: str, vendor: str, description: str) -> str:
    """
    Formats a CVE record into the required indexed document text.

    Format:
    {CVE_ID} {PRODUCT} {VENDOR}
    {FULL_DESCRIPTION}
    """
    return f"{cve_id} {product} {vendor}\n{description}"


def verify_diff(
    diff_lines: list[str],
    original_boundary: str,
    mutated_boundary: str,
    probe_version: str,
) -> tuple[bool, str | None]:
    """
    Verifies that the unified diff contains exactly one changed line
    corresponding to the version boundary mutation.

    Returns:
        tuple of (diff_valid: bool, diff_warning: str | None)
    """
    removed = [
        line for line in diff_lines if line.startswith("-") and not line.startswith("---")
    ]
    added = [
        line for line in diff_lines if line.startswith("+") and not line.startswith("+++")
    ]

    if len(removed) != 1 or len(added) != 1:
        msg = (
            f"Expected exactly 1 removed line and 1 added line in diff, "
            f"found {len(removed)} removed and {len(added)} added"
        )
        return False, msg

    rem_line = removed[0][1:]
    add_line = added[0][1:]

    if original_boundary not in rem_line and probe_version not in rem_line:
        msg = (
            f"Original boundary/probe_version ('{original_boundary}'/'{probe_version}') "
            f"not found in removed line: '{rem_line}'"
        )
        return False, msg

    if mutated_boundary not in add_line:
        msg = (
            f"Mutated boundary ('{mutated_boundary}') "
            f"not found in added line: '{add_line}'"
        )
        return False, msg

    return True, None


def build_documents(
    input_path: Path,
    output_path: Path,
) -> list[dict]:
    """
    Loads selected CVEs, builds original and mutated document representations,
    verifies diffs, and saves the output to output_path.

    Raises FileExistsError if output_path already exists.
    Raises FileNotFoundError if input_path does not exist.
    """
    if output_path.exists():
        raise FileExistsError(
            f"Target output file '{output_path}' already exists. Overwriting is prohibited."
        )

    if not input_path.exists():
        raise FileNotFoundError(f"Input file '{input_path}' does not exist.")

    with open(input_path, "r", encoding="utf-8") as f:
        cves = json.load(f)

    logger.info("Loaded %d CVEs from %s", len(cves), input_path)

    documents = []
    passed_count = 0
    failed_count = 0

    for cve in cves:
        cve_id = cve["cve_id"]
        vendor = cve["vendor"]
        product = cve["product"]
        orig_desc = cve["description"]
        mut_desc = cve["mutated_description"]
        orig_boundary = cve["original_boundary"]
        mut_boundary = cve["mutated_boundary"]
        probe_version = cve["probe_version"]

        original_doc = format_document(cve_id, product, vendor, orig_desc)
        mutated_doc = format_document(cve_id, product, vendor, mut_desc)

        diff_lines = list(
            difflib.unified_diff(
                original_doc.splitlines(),
                mutated_doc.splitlines(),
                fromfile="original",
                tofile="mutated",
                lineterm="",
            )
        )

        diff_valid, diff_warning = verify_diff(
            diff_lines, orig_boundary, mut_boundary, probe_version
        )

        if diff_valid:
            passed_count += 1
        else:
            failed_count += 1
            logger.warning(
                "CVE %s diff verification failed: %s", cve_id, diff_warning
            )

        doc_record = {
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "original_doc": original_doc,
            "mutated_doc": mutated_doc,
            "original_boundary": orig_boundary,
            "mutated_boundary": mut_boundary,
            "probe_version": probe_version,
            "diff_lines": diff_lines,
            "diff_valid": diff_valid,
            "diff_warning": diff_warning,
        }
        documents.append(doc_record)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(documents, f, indent=2, ensure_ascii=False)

    logger.info("Saved %d document records to %s", len(documents), output_path)

    print("\n=== Document Generation & Verification Summary ===")
    print(f"Total CVEs processed   : {len(cves)}")
    print(f"Passed diff validation : {passed_count}")
    print(f"Failed diff validation : {failed_count}")

    return documents


def main():
    input_path = PROJECT_ROOT / "data" / "selected_cves.json"
    output_path = PROJECT_ROOT / "data" / "documents.json"
    build_documents(input_path, output_path)


if __name__ == "__main__":
    main()
