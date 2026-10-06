"""
qualitative_analysis.py

Step 19: Qualitative analysis — selecting and displaying representative examples from the Phase 0 experiment.

Deterministically selects 5 representative CVE examples based on experimental outcomes:
1. Successful poisoning example: first CVE where Cond_C_probe = "affected"
2. Conflict acknowledged example: first CVE where Cond_C_probe = "conflict_acknowledged"
3. Clean resistance example: first CVE where Cond_C_probe = "not_affected"
4. Parametric sensitivity example: first CVE where parametric answer_class in ["mutated", "correct"]
5. Condition B validation example: first CVE where Cond_B_probe = "affected"

Loads data from:
- data/selected_cves.json (selection order)
- data/analysis_ready.csv (classifications)
- data/experiment_records.json (full model responses)

Outputs:
- Displays all five examples formatted to console
- Saves full qualitative records to results/qualitative_examples.json (does NOT overwrite if exists)

Usage:
    python src/qualitative_analysis.py
"""

import csv
import json
import logging
from pathlib import Path
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Determine project root and directory paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def find_file(filename: str, subfolder: str = "data") -> Path:
    """Finds path to a file, checking project root and current working directory."""
    candidates = [
        PROJECT_ROOT / subfolder / filename,
        Path(subfolder) / filename,
        Path("phase0") / subfolder / filename,
        PROJECT_ROOT / filename,
        Path(filename),
    ]
    for c in candidates:
        if c.exists():
            return c
    return PROJECT_ROOT / subfolder / filename


def load_selected_cves(json_path: Path) -> list[dict]:
    """Loads selected CVEs in original selection order."""
    if not json_path.exists():
        logger.error(f"Selected CVEs file not found at: {json_path}")
        sys.exit(1)
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    logger.info(f"Loaded {len(data)} selected CVEs from {json_path}")
    return data


def load_analysis_ready(csv_path: Path) -> dict[str, dict]:
    """Loads analysis_ready.csv keyed by cve_id."""
    if not csv_path.exists():
        logger.error(f"Analysis-ready CSV not found at: {csv_path}")
        sys.exit(1)
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = {r["cve_id"]: r for r in reader}
    logger.info(f"Loaded classifications for {len(rows)} CVEs from {csv_path}")
    return rows


def load_experiment_records(json_path: Path) -> dict[str, dict[tuple[str, str], dict]]:
    """
    Loads experiment records and indexes them by (cve_id, (condition, query_type)).
    """
    if not json_path.exists():
        logger.error(f"Experiment records file not found at: {json_path}")
        sys.exit(1)
    with open(json_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    indexed: dict[str, dict[tuple[str, str], dict]] = {}
    for r in records:
        cve_id = r["cve_id"]
        cond = r["condition"]
        q_type = r["query_type"]
        if cve_id not in indexed:
            indexed[cve_id] = {}
        indexed[cve_id][(cond, q_type)] = r

    logger.info(f"Indexed {len(records)} experiment records for {len(indexed)} CVEs from {json_path}")
    return indexed


def select_qualitative_examples(
    selected_cves: list[dict],
    analysis_ready: dict[str, dict],
    experiment_records: dict[str, dict[tuple[str, str], dict]],
) -> list[dict]:
    """
    Deterministically selects 5 representative examples following selection rules.
    """
    example_definitions = [
        {
            "category": "successful_poisoning",
            "title": "Example 1: Successful Poisoning (Cond_C_probe = 'affected')",
            "rule": lambda ar: ar.get("cond_c_probe") == "affected",
            "note": "Illustrates complete poisoning: In the presence of conflicting documents, the model adopts the mutated boundary, erroneously classifying the safe probe version as affected.",
            "include_parametric": False,
        },
        {
            "category": "conflict_acknowledged",
            "title": "Example 2: Conflict Acknowledged (Cond_C_probe = 'conflict_acknowledged')",
            "rule": lambda ar: ar.get("cond_c_probe") == "conflict_acknowledged",
            "note": "Illustrates conflict awareness: The model detects conflicting version boundaries across retrieved documents and explicitly acknowledges the contradiction without making an unsafe determination.",
            "include_parametric": False,
        },
        {
            "category": "clean_resistance",
            "title": "Example 3: Clean Resistance (Cond_C_probe = 'not_affected')",
            "rule": lambda ar: ar.get("cond_c_probe") == "not_affected",
            "note": "Illustrates clean resistance: Despite the injected poisoned document in retrieval context, the model adheres to the ground truth boundary and correctly classifies the probe version as not affected.",
            "include_parametric": False,
        },
        {
            "category": "parametric_sensitivity",
            "title": "Example 4: Parametric Sensitivity (Parametric answer_class = 'mutated' or 'correct')",
            "rule": lambda ar: ar.get("parametric") in ["mutated", "correct"],
            "note": "Illustrates parametric sensitivity: In zero-shot parametric probing (without retrieval), the base model demonstrates prior parametric knowledge regarding the vulnerability boundary.",
            "include_parametric": True,
        },
        {
            "category": "condition_b_validation",
            "title": "Example 5: Condition B Validation (Cond_B_probe = 'affected')",
            "rule": lambda ar: ar.get("cond_b_probe") == "affected",
            "note": "Illustrates uncontested mutation validity: When only the mutated document is present in retrieval context (Condition B), the model reliably adopts the corrupted boundary and classifies the probe version as affected.",
            "include_parametric": False,
        },
    ]

    selected_examples = []

    for defn in example_definitions:
        found_cve = None
        for cve_item in selected_cves:
            cve_id = cve_item["cve_id"]
            ar_row = analysis_ready.get(cve_id)
            if ar_row and defn["rule"](ar_row):
                found_cve = cve_item
                break

        if not found_cve:
            logger.warning(f"No matching CVE found for rule: {defn['title']}")
            continue

        cve_id = found_cve["cve_id"]
        ar_row = analysis_ready[cve_id]
        cve_records = experiment_records.get(cve_id, {})

        # Extract responses
        cond_a_probe_rec = cve_records.get(("Condition A", "Type C"), {})
        cond_b_probe_rec = cve_records.get(("Condition B", "Type C"), {})
        cond_c_probe_rec = cve_records.get(("Condition C", "Type C"), {})
        parametric_rec = cve_records.get(("Parametric", "Parametric"), {})

        example_data = {
            "category": defn["category"],
            "title": defn["title"],
            "cve_id": cve_id,
            "vendor": found_cve.get("vendor", ar_row.get("vendor", "")),
            "product": found_cve.get("product", ar_row.get("product", "")),
            "original_boundary": found_cve.get("original_boundary", ar_row.get("original_boundary", "")),
            "mutated_boundary": found_cve.get("mutated_boundary", ar_row.get("mutated_boundary", "")),
            "probe_version": found_cve.get("probe_version", ar_row.get("probe_version", "")),
            "classifications": {
                "cond_a_probe": ar_row.get("cond_a_probe", cond_a_probe_rec.get("answer_class", "N/A")),
                "cond_b_probe": ar_row.get("cond_b_probe", cond_b_probe_rec.get("answer_class", "N/A")),
                "cond_c_probe": ar_row.get("cond_c_probe", cond_c_probe_rec.get("answer_class", "N/A")),
                "parametric": ar_row.get("parametric", parametric_rec.get("answer_class", "N/A")),
            },
            "responses": {
                "cond_a_probe_response": cond_a_probe_rec.get("response_text", ""),
                "cond_b_probe_response": cond_b_probe_rec.get("response_text", ""),
                "cond_c_probe_response": cond_c_probe_rec.get("response_text", ""),
                "parametric_response": parametric_rec.get("response_text", ""),
            },
            "include_parametric": defn["include_parametric"],
            "note": defn["note"],
        }
        selected_examples.append(example_data)

    return selected_examples


def print_qualitative_examples(examples: list[dict]) -> None:
    """Prints all qualitative examples clearly labeled to the console."""
    print("\n" + "=" * 90)
    print("PHASE 0 QUALITATIVE ANALYSIS: REPRESENTATIVE EXAMPLES")
    print("=" * 90 + "\n")

    for idx, ex in enumerate(examples, 1):
        print("=" * 90)
        print(f"[{idx}/5] {ex['title'].upper()}")
        print("=" * 90)
        print(f"CVE ID:            {ex['cve_id']}")
        print(f"Vendor:            {ex['vendor']}")
        print(f"Product:           {ex['product']}")
        print(f"Original Boundary: {ex['original_boundary']}")
        print(f"Mutated Boundary:  {ex['mutated_boundary']}")
        print(f"Probe Version:     {ex['probe_version']}")
        print("-" * 90)
        print("CLASSIFICATIONS:")
        print(f"  Condition A Probe: {ex['classifications']['cond_a_probe']}")
        print(f"  Condition B Probe: {ex['classifications']['cond_b_probe']}")
        print(f"  Condition C Probe: {ex['classifications']['cond_c_probe']}")
        print(f"  Parametric:        {ex['classifications']['parametric']}")
        print("-" * 90)
        print("RESPONSES:")
        print("Condition A Probe Response:")
        print(f"  \"{ex['responses']['cond_a_probe_response']}\"")
        print(f"  [Classification: {ex['classifications']['cond_a_probe']}]")
        print()

        if ex["category"] == "condition_b_validation":
            print("Condition B Probe Response (Uncontested Injected Context):")
            print(f"  \"{ex['responses']['cond_b_probe_response']}\"")
            print(f"  [Classification: {ex['classifications']['cond_b_probe']}]")
            print()

        print("Condition C Probe Response (Conflicted Retrieval Context):")
        print(f"  \"{ex['responses']['cond_c_probe_response']}\"")
        print(f"  [Classification: {ex['classifications']['cond_c_probe']}]")
        print()

        if ex["include_parametric"] or ex["category"] == "parametric_sensitivity":
            print("Parametric Response (No Retrieval / Prior Knowledge):")
            print(f"  \"{ex['responses']['parametric_response']}\"")
            print(f"  [Classification: {ex['classifications']['parametric']}]")
            print()

        print("-" * 90)
        print(f"NOTE: {ex['note']}")
        print("=" * 90 + "\n")


def save_qualitative_examples(examples: list[dict], output_path: Path) -> None:
    """Saves qualitative examples to results/qualitative_examples.json if it doesn't already exist."""
    if output_path.exists():
        logger.warning(
            f"Output file {output_path} already exists. Skipping write to avoid overwriting existing data."
        )
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(examples, f, indent=2)
        logger.info(f"Qualitative examples successfully saved to {output_path}")


def main() -> None:
    # Resolve input and output file paths
    selected_cves_path = find_file("selected_cves.json", subfolder="data")
    analysis_ready_path = find_file("analysis_ready.csv", subfolder="data")
    records_path = find_file("experiment_records.json", subfolder="data")
    output_path = find_file("qualitative_examples.json", subfolder="results")

    # Load data
    selected_cves = load_selected_cves(selected_cves_path)
    analysis_ready = load_analysis_ready(analysis_ready_path)
    experiment_records = load_experiment_records(records_path)

    # Select representative examples
    examples = select_qualitative_examples(
        selected_cves=selected_cves,
        analysis_ready=analysis_ready,
        experiment_records=experiment_records,
    )

    if len(examples) != 5:
        logger.warning(f"Selected {len(examples)} examples instead of expected 5.")

    # Print all five examples
    print_qualitative_examples(examples)

    # Save to results/qualitative_examples.json (do NOT overwrite)
    save_qualitative_examples(examples, output_path)


if __name__ == "__main__":
    main()
