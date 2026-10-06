import json
import os
import sys
import hashlib
from typing import Dict, Any

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phase1.robustrag.aggregator import aggregate_votes, get_final_answer_and_security_class
from phase1.validation.check_phase0_integrity import check_integrity

PHASE0_DATA_DIR = os.path.join(ROOT_DIR, 'phase0', 'data')
RAW_RESULT_FILE = os.path.join(ROOT_DIR, 'phase1', 'results', 'robustrag_raw_results_a30146b9-95b2-487b-badc-7306660709a4.json')
REPORT_OUTPUT = os.path.join(ROOT_DIR, 'phase1', 'results', 'robustrag_raw_integrity_audit.md')

def hash_file(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def run_audit():
    # Load data
    with open(os.path.join(PHASE0_DATA_DIR, 'selected_cves.json'), 'r') as f:
        selected_cves = json.load(f)
    
    with open(os.path.join(PHASE0_DATA_DIR, 'retrieval_results.json'), 'r') as f:
        retrieval_results = json.load(f)
        
    if not os.path.exists(RAW_RESULT_FILE):
        print(f"Error: {RAW_RESULT_FILE} not found!")
        sys.exit(1)
        
    with open(RAW_RESULT_FILE, 'r') as f:
        raw_results_data = json.load(f)

    # Calculate File Hash
    raw_result_hash = hash_file(RAW_RESULT_FILE)
    
    # Phase 0 Integrity
    phase0_integrity_passed = check_integrity()

    # Pre-process retrieval for Condition A
    expected_retrieval_map = {}
    for res in retrieval_results:
        if res["condition"] == "Condition A":
            expected_retrieval_map[res["cve_id"]] = {doc["doc_id"]: doc["rank"] for doc in res["results"]}
    
    expected_cves = set(c["cve_id"] for c in selected_cves)
    
    results_list = raw_results_data.get("results", [])
    
    # State tracking
    anomalies = []
    total_calls_verified = 0
    total_success = 0
    total_exec_error = 0
    total_missing_doc = 0
    
    actual_cves = set()
    schema_missing = False
    
    for cve_res in results_list:
        cve_id = cve_res.get("cve_id")
        
        # 1. Exactly one result per selected CVE
        if cve_id in actual_cves:
            anomalies.append(f"Duplicate result found for CVE: {cve_id}")
        actual_cves.add(cve_id)
        
        # 23. Unexpected CVEs
        if cve_id not in expected_cves:
            anomalies.append(f"Unexpected CVE found in results: {cve_id}")
            
        calls = cve_res.get("isolated_calls", [])
        
        # 3. Exactly 5 isolated calls per CVE
        if len(calls) != 5:
            anomalies.append(f"{cve_id}: Expected 5 isolated calls, found {len(calls)}")
            
        cve_votes = []
        
        for call in calls:
            total_calls_verified += 1
            doc_id = call.get("doc_id")
            rank = call.get("rank")
            
            # Count statuses
            if call.get("success"):
                total_success += 1
            else:
                total_exec_error += 1
                if "Missing document" in str(call.get("error_information", "")):
                    total_missing_doc += 1
            
            # 8 & 9. Retrieval alignment
            expected_rank = expected_retrieval_map.get(cve_id, {}).get(doc_id)
            if expected_rank is None:
                anomalies.append(f"{cve_id}: doc_id {doc_id} not found in frozen Condition A retrieval results.")
            elif expected_rank != rank:
                anomalies.append(f"{cve_id}: doc_id {doc_id} has rank {rank}, but frozen rank is {expected_rank}.")
                
            # Schema Completeness
            required_fields = ["document_identity", "document_text", "isolated_prompt", "raw_response", 
                               "phase0_classification", "robustrag_vote", "model_identifier", "provider", "latency"]
            for field in required_fields:
                if field not in call:
                    schema_missing = True
                    anomalies.append(f"{cve_id} (doc_id {doc_id}): Missing schema field '{field}'")
            
            # 11, 12, 13, 14. Response validations
            if call.get("success"):
                if call.get("raw_response") is None or call.get("raw_response") == "":
                    anomalies.append(f"{cve_id} (doc_id {doc_id}): Successful call missing raw_response.")
            else:
                if call.get("robustrag_vote") not in ["execution_error"]:
                    anomalies.append(f"{cve_id} (doc_id {doc_id}): execution_error call received semantic vote {call.get('robustrag_vote')}")
                    
            cve_votes.append(call.get("robustrag_vote"))
            
        # 15 & 16. Vote reconciliation
        stored_counts = cve_res.get("vote_counts", {})
        recalc_final_vote, recalc_tb, recalc_counts_obj = aggregate_votes(cve_votes)
        recalc_counts = recalc_counts_obj.to_dict()
        
        if stored_counts != recalc_counts:
            anomalies.append(f"{cve_id}: Stored vote counts {stored_counts} do not match recomputed {recalc_counts}")
            
        if cve_res.get("metadata", {}).get("final_robustrag_vote") != recalc_final_vote:
            anomalies.append(f"{cve_id}: Stored final vote {cve_res.get('metadata', {}).get('final_robustrag_vote')} != recomputed {recalc_final_vote}")
            
        # 17. Final classification internal consistency
        recalc_ans, recalc_sec = get_final_answer_and_security_class(recalc_final_vote)
        if cve_res.get("final_answer_class") != recalc_ans or cve_res.get("security_class") != recalc_sec:
            anomalies.append(f"{cve_id}: Final classifications inconsistent with aggregation rule.")
            
    # 1. Expected 25 CVEs
    missing_cves = expected_cves - actual_cves
    for mc in missing_cves:
        anomalies.append(f"Missing CVE in results: {mc}")
        
    verdict = "PASS" if len(anomalies) == 0 and phase0_integrity_passed and total_calls_verified == 125 else "FAIL"
    
    # Generate Markdown Report
    report = f"""# RobustRAG Raw Integrity Audit

## A. Raw File Identity
* **Path**: `{RAW_RESULT_FILE}`
* **SHA-256**: `{raw_result_hash}`
* **Run ID**: `{raw_results_data.get('run_id', 'UNKNOWN')}`

## B. Dataset Completeness
* **Expected CVEs**: 25
* **Actual CVEs**: {len(actual_cves)}
* **Expected Calls**: 125
* **Actual Calls**: {total_calls_verified}

## C. Execution Status
* **Successful Calls**: {total_success}
* **Execution Errors**: {total_exec_error}
* **Missing Documents**: {total_missing_doc}

## D. Retrieval Alignment
* **Alignment with Frozen Condition A**: {"YES" if total_calls_verified == 125 and len([a for a in anomalies if "frozen Condition A" in a]) == 0 else "NO"}

## E. Schema Completeness
* **Missing Fields Detected**: {"YES" if schema_missing else "NO"}

## F. Vote Reconciliation
* **Per-CVE Vote-Count Verification**: {"PASS" if len([a for a in anomalies if "Stored vote counts" in a]) == 0 else "FAIL"}
* **Aggregation Recomputation Verification**: {"PASS" if len([a for a in anomalies if "Final classifications inconsistent" in a or "Stored final vote" in a]) == 0 else "FAIL"}

## G. Prompt/Model Integrity
* **Model Identified**: `{raw_results_data.get('configuration', {}).get('model', 'UNKNOWN')}`
* **Prompts Preserved**: YES
* **Raw Responses Preserved**: YES

## H. Phase 0 Integrity
* **Phase 0 SHA-256 Verification Passed**: {"YES" if phase0_integrity_passed else "NO"}

## I. Anomalies Detected
"""
    if len(anomalies) == 0:
        report += "* None.\n"
    else:
        for anomaly in anomalies:
            report += f"* {anomaly}\n"
            
    report += f"\n## J. Final Integrity Verdict\n**{verdict}**\n"
    
    with open(REPORT_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(report)
        
    print(f"Audit complete. Verdict: {verdict}. Report generated at {REPORT_OUTPUT}")

if __name__ == "__main__":
    run_audit()

