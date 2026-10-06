"""
cve_selector.py

Performs final reproducible CVE sample selection for Phase 0.

Steps:
1. Load data/candidate_cves.json
2. For every candidate, run mutate_cve() from src.mutator
3. Keep only records where mutation_valid is True
4. Seed random generator (seed 42) and sample 25 records (or all if < 25)
5. Save selected records to data/selected_cves.json (fail if file exists)
6. Print summary of candidates, valid mutations, selected count, and CVE IDs

Usage:
    python src/cve_selector.py
"""

import json
import logging
import random
import sys
from pathlib import Path

# Ensure project root is in sys.path so src.mutator can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.mutator import mutate_cve

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def select_cve_sample(
    candidate_path: Path,
    output_path: Path,
    sample_size: int = 25,
    seed: int = 42,
) -> list[dict]:
    """
    Selects a deterministic sample of mutation-valid CVE records.

    Raises FileExistsError if output_path already exists.
    Raises FileNotFoundError if candidate_path does not exist.
    """
    if output_path.exists():
        raise FileExistsError(
            f"Target file '{output_path}' already exists. Overwriting is prohibited."
        )

    if not candidate_path.exists():
        raise FileNotFoundError(
            f"Candidate file '{candidate_path}' does not exist."
        )

    with open(candidate_path, "r", encoding="utf-8") as f:
        candidates = json.load(f)

    total_candidates = len(candidates)
    logger.info("Loaded %d candidates from %s", total_candidates, candidate_path)

    valid_records = []
    inclusive_excluded = 0
    for candidate in candidates:
        result = mutate_cve(candidate)
        if result.mutation_valid:
            valid_records.append(
                {
                    "cve_id": result.cve_id,
                    "vendor": result.vendor,
                    "product": result.product,
                    "description": result.original_description,
                    "mutated_description": result.mutated_description,
                    "original_boundary": result.original_boundary,
                    "mutated_boundary": result.mutated_boundary,
                    "probe_version": result.probe_version,
                    "boundary_type": result.boundary_type,
                    "diff_changes": result.diff_changes,
                }
            )
        elif result.failure_reason == "inclusive_boundary_excluded":
            inclusive_excluded += 1

    total_valid = len(valid_records)
    logger.info("Mutation valid candidates: %d / %d", total_valid, total_candidates)
    logger.info("Inclusive-boundary excluded: %d", inclusive_excluded)

    target_count = min(sample_size, total_valid)
    random.seed(seed)
    selected_records = random.sample(valid_records, target_count)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(selected_records, f, indent=2, ensure_ascii=False)

    logger.info("Saved %d selected records to %s", len(selected_records), output_path)

    selected_cve_ids = [r["cve_id"] for r in selected_records]

    print("\n=== Final CVE Sample Selection Summary ===")
    print(f"Total candidates          : {total_candidates}")
    print(f"Inclusive-boundary excluded: {inclusive_excluded}")
    print(f"Total mutation-valid      : {total_valid}")
    print(f"Total selected            : {len(selected_records)}")
    print(f"Selected CVE IDs ({len(selected_cve_ids)}):")
    for cve_id in selected_cve_ids:
        print(f"  - {cve_id}")

    return selected_records


def main():
    candidate_path = PROJECT_ROOT / "data" / "candidate_cves.json"
    output_path = PROJECT_ROOT / "data" / "selected_cves.json"
    select_cve_sample(candidate_path, output_path, sample_size=25, seed=42)


if __name__ == "__main__":
    main()
