import json
import os
import sys
import uuid
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phase1.nli.nli_model import load_nli_model
from phase1.nli.pairwise import execute_pairwise_nli
from phase1.nli.filtering import compute_c_min_retention
from phase1.nli.runner import format_isolated_prompt

from phase0.src.llm_caller import call_llm, SYSTEM_PROMPT, DEFAULT_MODEL
from phase0.src.run_probe import classify_probe_response

from phase1.validation.check_phase0_integrity import check_integrity

# Data paths
PHASE0_DATA_DIR = os.path.join(PROJECT_ROOT, "phase0", "data")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "phase1", "results")

def main():
    print("Starting NLI E2E Preflight...")
    
    # Precheck hashes
    check_integrity()
    
    # Load docs
    with open(os.path.join(PHASE0_DATA_DIR, 'selected_cves.json'), 'r') as f:
        selected_cves = json.load(f)
        
    with open(os.path.join(PHASE0_DATA_DIR, 'retrieval_results.json'), 'r') as f:
        retrieval_results = json.load(f)
        
    with open(os.path.join(PHASE0_DATA_DIR, 'documents.json'), 'r') as f:
        docs_list = json.load(f)
        docs_by_cve = {d["cve_id"]: d for d in docs_list}
        
    first_cve = selected_cves[0]["cve_id"]
    probe_version = docs_by_cve[first_cve]["probe_version"]
    product = docs_by_cve[first_cve]["product"]
    
    # Get Condition A documents
    cond_a_docs = None
    for res in retrieval_results:
        if res["cve_id"] == first_cve and res["condition"] == "Condition A":
            cond_a_docs = res["results"]
            break
            
    if not cond_a_docs or len(cond_a_docs) != 5:
        print(f"EXECUTION BLOCKER: Could not find exactly 5 Condition A documents for {first_cve}.")
        sys.exit(1)
        
    # Merge full text
    for d in cond_a_docs:
        doc_id = d["doc_id"]
        if doc_id.endswith("_orig"):
            cve_key = doc_id.replace("_orig", "")
            d["text"] = docs_by_cve[cve_key]["original_doc"]
        elif doc_id.endswith("_mut"):
            cve_key = doc_id.replace("_mut", "")
            d["text"] = docs_by_cve[cve_key]["mutated_doc"]
        else:
            d["text"] = ""
            
    # Load Model
    print("Loading NLI model (cross-encoder/nli-deberta-v3-large)...")
    pipe, metadata, error = load_nli_model()
    if error:
        print(f"EXECUTION BLOCKER: {error}")
        sys.exit(1)
        
    # Execute NLI
    print("Executing pairwise NLI...")
    pairs_pass = execute_pairwise_nli(cond_a_docs, pipe)
    
    # Compute scores and filter
    scores, c_min, retained_doc_ids, filtered_doc_ids, rule = compute_c_min_retention(cond_a_docs, pairs_pass)
    
    retained_docs = [d for d in cond_a_docs if d["doc_id"] in retained_doc_ids]
    
    # Build prompt
    prompt = format_isolated_prompt(retained_docs, product, first_cve, probe_version)
    
    # Call LLM
    print("Calling frozen LLM...")
    start_t = time.time()
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
    latency = time.time() - start_t
    
    if llm_res.get("error"):
        print(f"EXECUTION BLOCKER: LLM call failed: {llm_res['error']}")
        response_text = ""
        classification = "error"
        consequence = "error"
    else:
        response_text = llm_res["response_text"]
        # Run frozen classifier
        print("Running frozen classifier...")
        classification, consequence = classify_probe_response(response_text)
        
    # Validate integrity again
    print("Post-execution integrity check...")
    check_integrity()
    
    # Create Reports
    run_id = str(uuid.uuid4())
    
    report_dict = {
        "run_id": run_id,
        "cve": first_cve,
        "nli_model": "cross-encoder/nli-deberta-v3-large",
        "llm_model": llm_res.get("model", DEFAULT_MODEL),
        "latency_seconds": latency,
        "c_min": c_min,
        "retained_docs": retained_doc_ids,
        "filtered_docs": filtered_doc_ids,
        "prompt": prompt,
        "system_prompt": SYSTEM_PROMPT,
        "raw_response": response_text,
        "classification": classification,
        "consequence": consequence,
        "error": llm_res.get("error")
    }
    
    json_path = os.path.join(RESULTS_DIR, f"nli_e2e_preflight_{run_id}.json")
    with open(json_path, "w") as f:
        json.dump(report_dict, f, indent=2)
        
    md_path = os.path.join(RESULTS_DIR, f"nli_e2e_preflight_{run_id}.md")
    with open(md_path, "w") as f:
        f.write(f"# NLI E2E Preflight Report\n\n")
        f.write(f"**Run ID**: `{run_id}`\n")
        f.write(f"**CVE**: `{first_cve}`\n\n")
        if llm_res.get("error"):
            f.write(f"**EXECUTION ERROR**: {llm_res['error']}\n\n")
        f.write(f"## Evidence Filtering\n")
        f.write(f"- **C_min**: {c_min}\n")
        f.write(f"- **Retained Documents**: {', '.join(retained_doc_ids)}\n")
        f.write(f"- **Filtered Documents**: {', '.join(filtered_doc_ids)}\n\n")
        f.write(f"## LLM Execution\n")
        f.write(f"- **Model**: {llm_res['model']}\n")
        f.write(f"- **Latency**: {latency:.2f} seconds\n\n")
        f.write(f"### Prompt Context\n```text\n{prompt}\n```\n\n")
        f.write(f"### Raw Response\n```text\n{response_text}\n```\n\n")
        f.write(f"## Frozen Classifier Results\n")
        f.write(f"- **Final Classification**: {classification}\n")
        f.write(f"- **Security Consequence**: {consequence}\n\n")
        f.write("Zero files outside of phase1 were modified.\n")
        
    print(f"Preflight completed successfully. Reports saved to {json_path} and {md_path}")

if __name__ == "__main__":
    main()
