import json
import os
import sys
import uuid
import time
import hashlib
from pathlib import Path
from dataclasses import asdict

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase1.nli.nli_model import load_nli_model
from phase1.nli.pairwise import execute_pairwise_nli
from phase1.nli.filtering import compute_c_min_retention
from phase1.nli.runner import format_isolated_prompt
from phase1.validation.check_phase0_integrity import check_integrity

from phase0.src.llm_caller import call_llm, SYSTEM_PROMPT, DEFAULT_MODEL
from phase0.src.run_probe import classify_probe_response

PHASE0_DATA_DIR = os.path.join(PROJECT_ROOT, "phase0", "data")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "phase1", "results")

def get_file_hash(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    print("Starting NLI Full 25-CVE Evaluation...")
    run_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Pre-execution checks
    print("Pre-execution integrity check...")
    check_integrity()
    
    api_key_present = "OPENROUTER_API_KEY" in os.environ
    print(f"API Key available: {api_key_present}")
    if not api_key_present:
        print("EXECUTION BLOCKER: OPENROUTER_API_KEY is not set.")
        sys.exit(1)
        
    # Load data
    with open(os.path.join(PHASE0_DATA_DIR, 'selected_cves.json'), 'r') as f:
        selected_cves = json.load(f)
        
    with open(os.path.join(PHASE0_DATA_DIR, 'retrieval_results.json'), 'r') as f:
        retrieval_results = json.load(f)
        
    with open(os.path.join(PHASE0_DATA_DIR, 'documents.json'), 'r') as f:
        docs_list = json.load(f)
        docs_by_cve = {d["cve_id"]: d for d in docs_list}
        
    print(f"Loaded {len(selected_cves)} selected CVEs.")
    
    # Load Model
    print("Loading NLI model (cross-encoder/nli-deberta-v3-large)...")
    pipe, metadata, error = load_nli_model()
    if error:
        print(f"EXECUTION BLOCKER: NLI model load failed: {error}")
        sys.exit(1)
        
    # Run loop
    all_results = []
    total_nli_pairs = 0
    successful_llm_calls = 0
    error_count = 0
    
    for cve_record in selected_cves:
        cve_id = cve_record["cve_id"]
        print(f"\nProcessing {cve_id}...")
        
        probe_version = docs_by_cve[cve_id]["probe_version"]
        product = docs_by_cve[cve_id]["product"]
        
        # Get Condition A documents
        cond_a_docs = None
        for res in retrieval_results:
            if res["cve_id"] == cve_id and res["condition"] == "Condition A":
                cond_a_docs = res["results"]
                break
                
        if not cond_a_docs or len(cond_a_docs) != 5:
            print(f"EXECUTION BLOCKER: Could not find exactly 5 Condition A documents for {cve_id}.")
            sys.exit(1)
            
        # Merge full text for retrieval
        retrieval_records = []
        for d in cond_a_docs:
            doc_id = d["doc_id"]
            if doc_id.endswith("_orig"):
                cve_key = doc_id.replace("_orig", "")
                full_text = docs_by_cve[cve_key]["original_doc"]
            elif doc_id.endswith("_mut"):
                cve_key = doc_id.replace("_mut", "")
                full_text = docs_by_cve[cve_key]["mutated_doc"]
            else:
                full_text = ""
            
            d["text"] = full_text
            retrieval_records.append({
                "doc_id": doc_id,
                "rank": d["rank"],
                "score": d.get("score"),
                "text": full_text
            })
            
        # Execute NLI
        pairs_pass = execute_pairwise_nli(cond_a_docs, pipe)
        total_nli_pairs += len(pairs_pass)
        
        # Compute scores and filter
        scores, c_min, retained_doc_ids, filtered_doc_ids, rule = compute_c_min_retention(cond_a_docs, pairs_pass)
        retained_docs = [d for d in cond_a_docs if d["doc_id"] in retained_doc_ids]
        
        # Format NLI pair records
        nli_records = []
        for pair in pairs_pass:
            pair_dict = asdict(pair)
            pair_dict["conflict_status"] = pair.argmax_label == "Contradiction"
            nli_records.append(pair_dict)
            
        # Build prompt
        prompt = format_isolated_prompt(retained_docs, product, cve_id, probe_version)
        
        # Call LLM
        call_start_t = time.time()
        try:
            llm_res = call_llm(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=prompt,
                model=DEFAULT_MODEL,
                temperature=0,
                max_tokens=512
            )
        except Exception as e:
            llm_res = {"error": f"Exception: {str(e)}", "model": DEFAULT_MODEL, "response_text": ""}
            
        latency = time.time() - call_start_t
        
        if llm_res.get("error"):
            print(f"Error calling LLM for {cve_id}: {llm_res['error']}")
            response_text = ""
            classification = "error"
            consequence = "error"
            exec_status = "error"
            error_count += 1
        else:
            successful_llm_calls += 1
            response_text = llm_res["response_text"]
            classification, consequence = classify_probe_response(response_text)
            exec_status = "success"
            
        # Combine everything into CVE result record
        cve_result = {
            "cve_id": cve_id,
            "probe_version": probe_version,
            "retrieval": retrieval_records,
            "nli_pairs": nli_records,
            "filtering": {
                "scores": [asdict(s) for s in scores],
                "c_min": c_min,
                "retained_docs": retained_doc_ids,
                "filtered_docs": filtered_doc_ids,
                "rule": rule
            },
            "generation": {
                "system_prompt": SYSTEM_PROMPT,
                "user_prompt": prompt,
                "retained_context_doc_ids": retained_doc_ids,
                "model": llm_res.get("model", DEFAULT_MODEL),
                "provider": "OpenRouter",
                "temperature": 0,
                "max_tokens": 512,
                "raw_response": response_text,
                "latency_seconds": latency,
                "execution_status": exec_status,
                "error": llm_res.get("error")
            },
            "classification": {
                "generated_answer": response_text,
                "classification": classification,
                "consequence": consequence
            }
        }
        all_results.append(cve_result)
        
    total_runtime = time.time() - start_time
    
    # Save Raw Results
    raw_results_path = os.path.join(RESULTS_DIR, f"nli_raw_results_{run_id}.json")
    with open(raw_results_path, "w") as f:
        json.dump(all_results, f, indent=2)
        
    raw_results_hash = get_file_hash(raw_results_path)
    
    # Post-execution integrity check
    print("\nPost-execution integrity check...")
    check_integrity()
    
    # Manifest
    manifest = {
        "run_id": run_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cve_count_processed": len(all_results),
        "expected_nli_pairs": total_nli_pairs,
        "expected_llm_calls": len(selected_cves),
        "actual_successful_llm_calls": successful_llm_calls,
        "error_count": error_count,
        "metadata": metadata,
        "environment": {
            "api_key_present": api_key_present,
            "runtime_seconds": total_runtime
        },
        "raw_results_hash": raw_results_hash
    }
    
    manifest_path = os.path.join(RESULTS_DIR, f"nli_run_manifest_{run_id}.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        
    # Summary MD
    summary_md_path = os.path.join(RESULTS_DIR, f"nli_run_summary_{run_id}.md")
    with open(summary_md_path, "w") as f:
        f.write(f"# NLI 25-CVE Run Summary\n\n")
        f.write(f"**Run ID**: `{run_id}`\n")
        f.write(f"**Timestamp**: {manifest['timestamp']}\n\n")
        f.write(f"## Execution Facts\n")
        f.write(f"- **CVEs Processed**: {len(all_results)} / 25\n")
        f.write(f"- **NLI Pair Count Evaluated**: {total_nli_pairs}\n")
        f.write(f"- **LLM Calls Attempted**: {len(selected_cves)}\n")
        f.write(f"- **LLM Calls Successful**: {successful_llm_calls}\n")
        f.write(f"- **LLM Call Errors**: {error_count}\n")
        f.write(f"- **Total Runtime**: {total_runtime:.2f} seconds\n\n")
        f.write(f"## Environment\n")
        f.write(f"- **Model**: {metadata.get('model_identifier', 'cross-encoder/nli-deberta-v3-large')}\n")
        f.write(f"- **Device**: {metadata.get('device', 'cpu')}\n")
        f.write(f"- **Generator**: {DEFAULT_MODEL} (OpenRouter)\n\n")
        f.write(f"## Output Locations\n")
        f.write(f"- **Raw Results**: `{raw_results_path}`\n")
        f.write(f"- **Run Manifest**: `{manifest_path}`\n\n")
        f.write(f"## Data Integrity\n")
        f.write(f"- **Raw Results SHA-256**: `{raw_results_hash}`\n")
        f.write(f"- **Phase 0 Integrity Check**: PASS\n")
        
    print(f"\nRun Complete. ID: {run_id}")
    print(f"Processed {len(all_results)} CVEs in {total_runtime:.2f}s.")
    print(f"Summary saved to {summary_md_path}")

if __name__ == "__main__":
    main()

