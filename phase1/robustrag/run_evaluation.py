import os
import sys
import json
import argparse
import time
import uuid

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phase1.robustrag.config import SYSTEM_PROMPT, LLM_MODEL, TEMPERATURE, MAX_TOKENS
from phase1.robustrag.runner import run_robustrag_for_cve
from phase1.validation.check_phase0_integrity import check_integrity

PHASE0_DATA_DIR = os.path.join(ROOT_DIR, 'phase0', 'data')
PHASE1_RESULTS_DIR = os.path.join(ROOT_DIR, 'phase1', 'results')

def load_json(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def validate_prerequisites(selected_cves, retrieval_results):
    """
    Validates exactly 25 selected CVEs, retrieval data for all 25 (Condition A),
    and exact top-k=5 docs.
    """
    if len(selected_cves) != 25:
        return False, f"Expected exactly 25 CVEs, found {len(selected_cves)}"
        
    retrieval_map = {(res["cve_id"], res["condition"]): res for res in retrieval_results}
    
    for cve in selected_cves:
        cve_id = cve["cve_id"]
        key = (cve_id, "Condition A")
        if key not in retrieval_map:
            return False, f"Missing Condition A retrieval results for {cve_id}"
        
        docs = retrieval_map[key].get("results", [])
        if len(docs) != 5:
            return False, f"Expected exactly 5 retrieved documents for {cve_id} in Condition A, found {len(docs)}"
            
    return True, "All prerequisites validated successfully."

def execute_evaluation(dry_run=False, target_cve=None, run_id=None):
    print("="*60)
    print("RobustRAG Phase 1 Evaluation Runner")
    print("="*60)
    
    # 1. Validation & Hash Manifest
    print("Validating Phase 0 hash manifest...")
    if not check_integrity():
        print("ABORT: Phase 0 integrity check failed.")
        sys.exit(1)
        
    os.makedirs(PHASE1_RESULTS_DIR, exist_ok=True)
    
    # 2. Load Frozen Data
    print("Loading frozen Phase 0 data...")
    selected_cves = load_json(os.path.join(PHASE0_DATA_DIR, "selected_cves.json"))
    retrieval_results = load_json(os.path.join(PHASE0_DATA_DIR, "retrieval_results.json"))
    documents_data = load_json(os.path.join(PHASE0_DATA_DIR, "documents.json"))
    
    # 3. Prerequisites
    valid, msg = validate_prerequisites(selected_cves, retrieval_results)
    if not valid:
        print(f"ABORT: {msg}")
        sys.exit(1)
        
    print("Validation passed. 25 CVEs and exact k=5 Condition A retrieval verified.")
    
    # Setup state
    if not run_id:
        run_id = str(uuid.uuid4())
        
    results_path = os.path.join(PHASE1_RESULTS_DIR, f"robustrag_raw_results_{run_id}.json")
    
    doc_lookup = {doc["cve_id"]: doc for doc in documents_data}
    retrieval_map = {(res["cve_id"], res["condition"]): res for res in retrieval_results}
    
    cves_to_process = selected_cves
    if target_cve:
        cves_to_process = [c for c in selected_cves if c["cve_id"] == target_cve]
        if not cves_to_process:
            print(f"ABORT: Target CVE {target_cve} not found in selected CVEs.")
            sys.exit(1)
            
    total_cves = len(cves_to_process)
    expected_calls = total_cves * 5
    
    print("\n--- Execution Plan ---")
    print(f"Run ID:            {run_id}")
    print(f"Number of CVEs:    {total_cves}")
    print(f"Docs per CVE:      5")
    print(f"Expected isolated LLM calls: {expected_calls}")
    print(f"Condition:         Condition A")
    print(f"Defense Name:      RobustRAG-style categorical aggregation adaptation")
    print(f"Model Identifier:  {LLM_MODEL}")
    print(f"Provider:          OpenRouter")
    print(f"Temperature:       {TEMPERATURE}")
    print(f"Max Tokens:        {MAX_TOKENS}")
    print(f"System Prompt:     {SYSTEM_PROMPT}")
    print(f"Output Path:       {results_path}")
    print(f"Dry Run Mode:      {dry_run}")
    
    if dry_run:
        print("\n--- Dry Run CVE Enumeration ---")
        for cve in cves_to_process:
            cve_id = cve["cve_id"]
            ret_entry = retrieval_map[(cve_id, "Condition A")]
            doc_ids = [d["doc_id"] for d in ret_entry.get("results", [])]
            print(f"CVE: {cve_id} | Docs: {doc_ids}")
        print("\nDRY RUN COMPLETE. ZERO API CALLS MADE.")
        return

    # 4. Resumability
    existing_results = {}
    if os.path.exists(results_path):
        existing_results = load_json(results_path)
        print(f"Resuming from existing run ID {run_id}. {len(existing_results.get('results', []))} CVEs already completed.")
        
    completed_cves = {r["cve_id"] for r in existing_results.get("results", [])}
    final_results = existing_results.get("results", [])
    
    print("\n--- Beginning Evaluation ---")
    start_time = time.time()
    
    for idx, cve in enumerate(cves_to_process, 1):
        cve_id = cve["cve_id"]
        if cve_id in completed_cves:
            print(f"Skipping {cve_id} (already completed in this run).")
            continue
            
        print(f"Processing {idx}/{total_cves}: {cve_id} ...")
        ret_entry = retrieval_map[(cve_id, "Condition A")]
        retrieved_docs = ret_entry.get("results", [])
        product = cve["product"]
        probe_version = doc_lookup[cve_id]["probe_version"]
        
        # Real execution uses the default llm_caller_fn from phase0.src.llm_caller
        result = run_robustrag_for_cve(
            cve_id=cve_id,
            probe_question=f"Is {product} version {probe_version} affected by {cve_id}?",
            condition="Condition A",
            probe_version=probe_version,
            product=product,
            retrieved_docs=retrieved_docs,
            doc_lookup=doc_lookup
        )
        
        final_results.append(result.to_dict())
        
        # Incremental save
        output_payload = {
            "run_id": run_id,
            "timestamp": time.time(),
            "defense_name": "RobustRAG-style categorical aggregation adaptation",
            "configuration": {
                "model": LLM_MODEL,
                "temperature": TEMPERATURE,
                "max_tokens": MAX_TOKENS
            },
            "results": final_results
        }
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump(output_payload, f, indent=2)
            
    print(f"\nEvaluation Complete! Saved to {results_path}")
    print(f"Elapsed Time: {time.time() - start_time:.2f}s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RobustRAG Phase 1 Runner")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without API calls")
    parser.add_argument("--cve", type=str, help="Execute exactly one selected CVE")
    parser.add_argument("--run-id", type=str, help="Resume a specific run ID")
    
    args = parser.parse_args()
    execute_evaluation(dry_run=args.dry_run, target_cve=args.cve, run_id=args.run_id)

