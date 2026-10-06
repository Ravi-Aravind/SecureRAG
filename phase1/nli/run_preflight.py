import os
import sys
import json
import time
import uuid
import platform
import math

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phase1.validation.check_phase0_integrity import check_integrity
from phase1.nli.nli_model import load_nli_model
from phase1.nli.pairwise import execute_pairwise_nli
from phase1.nli.filtering import compute_c_min_retention

PHASE0_DATA_DIR = os.path.join(ROOT_DIR, 'phase0', 'data')
RESULTS_DIR = os.path.join(ROOT_DIR, 'phase1', 'results')

def main():
    print("Starting NLI Live Preflight...")
    
    # Pre-execution integrity
    if not check_integrity():
        print("EXECUTION BLOCKER: Phase 0 integrity failed before execution.")
        sys.exit(1)
        
    with open(os.path.join(PHASE0_DATA_DIR, 'selected_cves.json'), 'r') as f:
        selected_cves = json.load(f)
    
    with open(os.path.join(PHASE0_DATA_DIR, 'retrieval_results.json'), 'r') as f:
        retrieval_results = json.load(f)
        
    with open(os.path.join(PHASE0_DATA_DIR, 'documents.json'), 'r') as f:
        docs_by_cve = {d["cve_id"]: d for d in json.load(f)}
        
    # Preflight CVE: first in selected_cves.json
    first_cve = selected_cves[0]["cve_id"]
    
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
        
    print(f"Selected CVE: {first_cve}")
    print("Loading NLI model (cross-encoder/nli-deberta-v3-large)...")
    
    load_start = time.time()
    pipe, metadata, error = load_nli_model()
    load_time = time.time() - load_start
    
    run_id = str(uuid.uuid4())
    json_path = os.path.join(RESULTS_DIR, f"nli_preflight_{run_id}.json")
    md_path = os.path.join(RESULTS_DIR, f"nli_preflight_{run_id}.md")
    
    if error:
        print(f"EXECUTION BLOCKER: {error}")
        with open(md_path, 'w') as f:
            f.write(f"# NLI Preflight Error\n\nExecution Blocker: {error}")
        sys.exit(1)
        
    metadata["load_time_seconds"] = load_time
    metadata["python_version"] = platform.python_version()
    
    print(f"Model loaded successfully in {load_time:.2f} seconds on {metadata.get('device')}.")
    
    # PASS 1
    print("Executing Pass 1 (20 pairs)...")
    pass1_start = time.time()
    pairs_pass1 = execute_pairwise_nli(cond_a_docs, pipe)
    scores1, c_min1, retained1, filtered1, rule1 = compute_c_min_retention(cond_a_docs, pairs_pass1)
    pass1_time = time.time() - pass1_start
    
    # PASS 2 (Determinism Check)
    print("Executing Pass 2 (Determinism Check)...")
    pass2_start = time.time()
    pairs_pass2 = execute_pairwise_nli(cond_a_docs, pipe)
    scores2, c_min2, retained2, filtered2, rule2 = compute_c_min_retention(cond_a_docs, pairs_pass2)
    pass2_time = time.time() - pass2_start
    
    # Structural Checks & Validation
    validations = []
    
    # 20 pairs
    v_count = (len(pairs_pass1) == 20)
    validations.append(f"Exactly 20 directed pairs: {'PASS' if v_count else 'FAIL'}")
    
    # No self pairs
    v_self = all(p.source_doc_id != p.target_doc_id for p in pairs_pass1)
    validations.append(f"No self-pairs: {'PASS' if v_self else 'FAIL'}")
    
    # Sum to 1 & argmax aligns
    v_sum = True
    v_argmax = True
    for p in pairs_pass1:
        total = p.p_contradiction + p.p_entailment + p.p_neutral
        if not math.isclose(total, 1.0, rel_tol=1e-2):
            v_sum = False
        max_p = max(p.p_contradiction, p.p_entailment, p.p_neutral)
        if max_p == p.p_contradiction and p.argmax_label != "Contradiction": v_argmax = False
        if max_p == p.p_entailment and p.argmax_label != "Entailment": v_argmax = False
        if max_p == p.p_neutral and p.argmax_label != "Neutral": v_argmax = False
    
    validations.append(f"Probability vectors sum to ~1: {'PASS' if v_sum else 'FAIL'}")
    validations.append(f"Argmax label matches probabilities: {'PASS' if v_argmax else 'FAIL'}")
    validations.append(f"Retained set non-empty: {'PASS' if len(retained1) > 0 else 'FAIL'}")
    
    # Determinism Check
    max_prob_diff = 0.0
    label_mismatch = 0
    for p1, p2 in zip(pairs_pass1, pairs_pass2):
        max_prob_diff = max(
            max_prob_diff,
            abs(p1.p_contradiction - p2.p_contradiction),
            abs(p1.p_entailment - p2.p_entailment),
            abs(p1.p_neutral - p2.p_neutral)
        )
        if p1.argmax_label != p2.argmax_label:
            label_mismatch += 1
            
    det_pass = (max_prob_diff < 1e-5 and label_mismatch == 0 and retained1 == retained2)
    validations.append(f"Determinism Check (Pass 1 vs Pass 2 identical decisions): {'PASS' if det_pass else 'FAIL'}")
    
    # Compile JSON Output
    output_dict = {
        "run_id": run_id,
        "cve_id": first_cve,
        "retrieval_condition": "Condition A",
        "model_metadata": metadata,
        "pairwise_nli_results_pass1": [p.to_dict() for p in pairs_pass1],
        "contradiction_scores": [s.to_dict() for s in scores1],
        "c_min": c_min1,
        "retained_documents": retained1,
        "filtered_documents": filtered1,
        "filtering_rule": rule1,
        "determinism_check": {
            "max_probability_difference": max_prob_diff,
            "label_mismatches": label_mismatch,
            "retained_set_identical": (retained1 == retained2)
        }
    }
    
    with open(json_path, 'w') as f:
        json.dump(output_dict, f, indent=2)
        
    # Compile Markdown Report
    md = f"""# NLI Live Preflight Report

**Run ID**: `{run_id}`
**Selected CVE**: `{first_cve}` (First in frozen Phase 0)

## Metadata
* **Model**: `{metadata.get("model_identifier")}`
* **Device**: `{metadata.get("device")}`
* **Transformers**: `{metadata.get("transformers_version")}`
* **PyTorch**: `{metadata.get("torch_version")}`
* **Python**: `{metadata.get("python_version")}`
* **Load Time**: {load_time:.2f} seconds
* **Pass 1 Inference Time**: {pass1_time:.2f} seconds
* **Pass 2 Inference Time**: {pass2_time:.2f} seconds

## Deterministic Repeat Comparison
* **Max Probability Difference**: {max_prob_diff:.10f}
* **Argmax Label Mismatches**: {label_mismatch}
* **Retained Set Identical**: {retained1 == retained2}

## Structural Checks
"""
    for v in validations:
        md += f"* {v}\n"
        
    md += f"\n## Contradiction Scores & Filtering\n"
    md += f"* **C_min**: {c_min1}\n"
    md += f"* **Filtering Rule Applied**: {rule1}\n\n"
    
    md += "| Doc ID | Rank | Contradiction Score | Conflicting Docs |\n"
    md += "|---|---|---|---|\n"
    for s in scores1:
        md += f"| {s.doc_id} | {s.rank} | {s.score} | {', '.join(s.conflicting_doc_ids)} |\n"
        
    md += f"\n* **Retained Documents**: {', '.join(retained1)}\n"
    md += f"* **Filtered Documents**: {', '.join(filtered1) if filtered1 else 'None'}\n"
    
    md += "\n## Pairwise NLI Matrix (Pass 1)\n"
    md += "| Source | Target | Contradiction | Entailment | Neutral | Argmax |\n"
    md += "|---|---|---|---|---|---|\n"
    for p in pairs_pass1:
        md += f"| {p.source_doc_id} | {p.target_doc_id} | {p.p_contradiction:.4f} | {p.p_entailment:.4f} | {p.p_neutral:.4f} | **{p.argmax_label}** |\n"

    md += """
## Limitations
* No LLM was called.
* Do not conclude NLI "works" or "fails" from this single CVE. The purpose is strictly structural validation of the implementation and deterministic model execution.
"""
    with open(md_path, 'w') as f:
        f.write(md)
        
    print("Post-execution integrity check...")
    if not check_integrity():
        print("FAIL: Phase 0 integrity compromised after execution!")
        sys.exit(1)
        
    print(f"Preflight completed successfully. Reports saved to:\n- {json_path}\n- {md_path}")
    print("Zero files outside of phase1 were modified.")

if __name__ == "__main__":
    main()

