"""
run_condition_a.py

Step 11: Condition A clean baseline pilot for RAG poisoning experiment.

This script runs a pilot of Condition A (clean baseline) for the first 3 CVEs
from data/selected_cves.json using the saved retrieval results from
data/retrieval_results.json and documents from data/documents.json.

For each CVE:
- Retrieves top-5 original documents from retrieval_results.json
- Passes top-5 docs as context to LLM for Type A query
- Runs parametric query (no context, no system prompt)
- Prints results for manual inspection

Usage:
    python src/run_condition_a.py
"""

import json
import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.llm_caller import (
    SYSTEM_PROMPT,
    build_parametric_prompt,
    build_type_a_prompt,
    call_llm,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def main():
    logger.info("Starting Step 11: Condition A Clean Baseline Pilot (First 3 CVEs)...")

    selected_cves_path = PROJECT_ROOT / "data" / "selected_cves.json"
    documents_path = PROJECT_ROOT / "data" / "documents.json"
    retrieval_results_path = PROJECT_ROOT / "data" / "retrieval_results.json"

    # Validate file existence
    for path in [selected_cves_path, documents_path, retrieval_results_path]:
        if not path.exists():
            logger.error(f"Required data file missing: {path}")
            sys.exit(1)

    # Load data
    with open(selected_cves_path, "r", encoding="utf-8") as f:
        selected_cves = json.load(f)

    with open(documents_path, "r", encoding="utf-8") as f:
        documents_data = json.load(f)

    with open(retrieval_results_path, "r", encoding="utf-8") as f:
        retrieval_results = json.load(f)

    # Build document text lookup map: cve_id -> original_doc
    doc_lookup = {doc["cve_id"]: doc["original_doc"] for doc in documents_data}

    # Build retrieval lookup map: (cve_id, condition) -> retrieval result entry
    retrieval_map = {
        (res["cve_id"], res["condition"]): res for res in retrieval_results
    }

    # Pilot run on first 3 CVEs only (indices 0, 1, 2)
    pilot_cves = selected_cves[:3]
    logger.info(f"Loaded {len(pilot_cves)} CVEs for pilot inspection.")

    for idx, cve_item in enumerate(pilot_cves, 1):
        cve_id = cve_item["cve_id"]
        product = cve_item["product"]
        original_boundary = cve_item["original_boundary"]

        logger.info(f"Processing CVE {idx}/3: {cve_id} ({product})...")

        # Get Condition A retrieval results
        key = (cve_id, "Condition A")
        if key not in retrieval_map:
            logger.error(f"No Condition A retrieval results found for {cve_id}")
            continue

        ret_entry = retrieval_map[key]
        top5_doc_ids = [res["doc_id"] for res in ret_entry["results"]]

        # Retrieve full text for top-5 docs
        top5_docs = []
        for doc_id in top5_doc_ids:
            # Strip "_orig" suffix (e.g. "CVE-2024-9953_orig" -> "CVE-2024-9953")
            doc_cve_id = doc_id.removesuffix("_orig")
            if doc_cve_id in doc_lookup:
                top5_docs.append(doc_lookup[doc_cve_id])
            else:
                logger.warning(f"Document ID {doc_cve_id} not found in doc_lookup.")

        # --- 1. Type A Query (RAG with Context) ---
        prompt_a = build_type_a_prompt(
            documents=top5_docs, product=product, cve_id=cve_id
        )
        res_a = call_llm(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=prompt_a,
            model="openai/gpt-4o-mini",
            temperature=0.0,
        )
        type_a_response = (
            res_a["response_text"] if not res_a["error"] else f"ERROR: {res_a['error']}"
        )

        # --- 2. Parametric Query (No Context, No System Prompt) ---
        prompt_p = build_parametric_prompt(product=product, cve_id=cve_id)
        res_p = call_llm(
            system_prompt=None,
            user_prompt=prompt_p,
            model="openai/gpt-4o-mini",
            temperature=0.0,
        )
        parametric_response = (
            res_p["response_text"] if not res_p["error"] else f"ERROR: {res_p['error']}"
        )

        # --- Print Output Clearly Labeled ---
        print("\n" + "=" * 80)
        print(f"PILOT RESULT FOR CVE {idx}/3")
        print("=" * 80)
        print(f"CVE ID:            {cve_id}")
        print(f"Product:           {product}")
        print(f"Original Boundary: {original_boundary}")
        print("-" * 80)
        print("TYPE A RESPONSE (RAG Context):")
        print(type_a_response)
        print("-" * 80)
        print("PARAMETRIC RESPONSE (No Context):")
        print(parametric_response)
        print("=" * 80 + "\n")

    logger.info("Step 11 Pilot completed successfully.")


if __name__ == "__main__":
    main()
