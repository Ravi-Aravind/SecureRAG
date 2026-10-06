import sys
import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phase1.robustrag.runner import run_robustrag_for_cve

def run_integration_test():
    print("Running Top-k=5 Integration Test (Mock LLM)...")
    
    # 5 Documents: 3 mutated, 2 original
    mock_retrieved_docs = [
        {"doc_id": "CVE-INT_orig", "rank": 1},
        {"doc_id": "CVE-INT_mutated", "rank": 2},
        {"doc_id": "CVE-INT_mutated", "rank": 3},
        {"doc_id": "CVE-INT_orig", "rank": 4},
        {"doc_id": "CVE-INT_mutated", "rank": 5},
    ]
    
    mock_doc_lookup = {
        "CVE-INT": {
            "original_doc": "Clean document.",
            "mutated_doc": "Poisoned document."
        }
    }
    
    mock_call_count = 0
    
    def injected_mock_llm(*args, **kwargs):
        nonlocal mock_call_count
        mock_call_count += 1
        # The prompt will contain the document text. We mock output based on the text.
        prompt = kwargs.get("user_prompt", "")
        if "Clean document." in prompt:
            return {"response_text": "The version is not affected.", "error": None} # original-supported
        elif "Poisoned document." in prompt:
            return {"response_text": "Yes, it is affected.", "error": None} # mutated-supported
        else:
            return {"response_text": "Context is insufficient.", "error": None}

    # Run the integration test
    res = run_robustrag_for_cve(
        cve_id="CVE-INT",
        probe_question="Is SmokeProduct version 1.0 affected?",
        condition="Condition C",
        probe_version="1.0",
        product="SmokeProduct",
        retrieved_docs=mock_retrieved_docs,
        doc_lookup=mock_doc_lookup,
        llm_caller_fn=injected_mock_llm
    )
    
    passed = True
    
    if len(res.isolated_calls) != 5:
        print("FAIL: expected 5 isolated calls")
        passed = False
        
    if mock_call_count != 5:
        print("FAIL: mock was not called exactly 5 times (no real API call)")
        passed = False

    # 3 mutated documents should yield 3 mutated-supported votes
    # 2 original documents should yield 2 original-supported votes
    # Final aggregation should be mutated-supported (false_positive)
    if res.vote_counts.mutated_supported != 3 or res.vote_counts.original_supported != 2:
        print(f"FAIL: unexpected vote counts: {res.vote_counts}")
        passed = False

    if res.final_answer_class != "affected" or res.security_class != "false_positive":
        print(f"FAIL: unexpected final class: {res.final_answer_class}")
        passed = False
        
    # Check Schema completeness explicitly via checking some fields
    if res.defense_name != "RobustRAG-style categorical aggregation adaptation":
        print("FAIL: Schema missing defense_name")
        passed = False
        
    if not hasattr(res.isolated_calls[0], 'document_identity'):
        print("FAIL: Schema missing document_identity")
        passed = False

    # Permutation Check
    mock_call_count = 0
    permuted_docs = list(reversed(mock_retrieved_docs))
    res_permuted = run_robustrag_for_cve(
        cve_id="CVE-INT",
        probe_question="Is SmokeProduct version 1.0 affected?",
        condition="Condition C",
        probe_version="1.0",
        product="SmokeProduct",
        retrieved_docs=permuted_docs,
        doc_lookup=mock_doc_lookup,
        llm_caller_fn=injected_mock_llm
    )
    
    if res_permuted.final_answer_class != res.final_answer_class:
        print("FAIL: Permutation check failed")
        passed = False

    if passed:
        print("PASS: 5-document integration test and order-invariance completed successfully.")
    else:
        print("FAIL: Integration test encountered unexpected results.")

if __name__ == "__main__":
    run_integration_test()
