import sys
import os
import json

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phase1.robustrag.aggregator import aggregate_votes
from phase1.robustrag.classifier import map_vote_to_robustrag, classify_probe
from phase1.robustrag.schemas import RobustRAGResult, IsolatedCall, VoteCounts
from phase1.robustrag.runner import run_robustrag_for_cve

def run_tests():
    all_passed = True

    def assert_test(name, condition):
        nonlocal all_passed
        if condition:
            print(f"PASS: {name}")
        else:
            print(f"FAIL: {name}")
            all_passed = False

    # Previous aggregation tests
    votes1 = ["original-supported", "original-supported", "insufficient"]
    res1, _, _ = aggregate_votes(votes1)
    assert_test("Test 1 - Original majority", res1 == "original-supported")

    votes2 = ["mutated-supported", "mutated-supported", "insufficient"]
    res2, _, _ = aggregate_votes(votes2)
    assert_test("Test 2 - Mutated majority", res2 == "mutated-supported")

    votes3 = ["original-supported", "mutated-supported", "insufficient"]
    res3, _, _ = aggregate_votes(votes3)
    assert_test("Test 3 - Positive tie", res3 == "conflict")

    votes4 = ["insufficient", "insufficient", "conflict"]
    res4, _, _ = aggregate_votes(votes4)
    assert_test("Test 4 - No signal", res4 == "insufficient")

    votes5 = ["original-supported"] * 5
    res5, _, _ = aggregate_votes(votes5)
    assert_test("Test 5 - All original", res5 == "original-supported")

    votes6 = ["mutated-supported"] * 5
    res6, _, _ = aggregate_votes(votes6)
    assert_test("Test 6 - All mutated", res6 == "mutated-supported")

    _, _, cnt4 = aggregate_votes(votes4)
    assert_test("Test 7 - Conflict preservation", cnt4.conflict == 1 and cnt4.original_supported == 0 and cnt4.mutated_supported == 0)

    votes_err = ["original-supported", "execution_error", "original-supported"]
    res_err, tb_err, cnt_err = aggregate_votes(votes_err)
    assert_test("Test 8 - API Error aggregation aborts resolution", res_err == "execution_error" and tb_err == "incomplete_execution")

    cls6, _ = classify_probe("We have no information on this.")
    assert_test("Test 9 - Classifier Fidelity (no information -> parsing_failure)", cls6 == "parsing_failure")

    def mock_llm_ok(*args, **kwargs):
        return {"response_text": "The version is not affected.", "error": None}

    res_missing = run_robustrag_for_cve(
        cve_id="CVE-MISSING",
        probe_question="Is it vulnerable?",
        condition="Condition A",
        probe_version="1.0",
        product="Prod",
        retrieved_docs=[{"doc_id": "MISSING_DOC", "rank": 1}],
        doc_lookup={}, # Empty lookup
        llm_caller_fn=mock_llm_ok
    )
    assert_test("Test 10 - Missing document explicitly recorded as execution_error", 
                res_missing.failed_call_count == 1 and 
                res_missing.final_answer_class == "execution_error" and
                res_missing.isolated_calls[0].error_information == "Missing document in lookup: MISSING_DOC")

    def mock_llm_err(*args, **kwargs):
        return {"response_text": "", "error": "API timeout"}

    res_apierr = run_robustrag_for_cve(
        cve_id="CVE-APIERR",
        probe_question="Is it vulnerable?",
        condition="Condition A",
        probe_version="1.0",
        product="Prod",
        retrieved_docs=[{"doc_id": "CVE-APIERR_orig", "rank": 1}],
        doc_lookup={"CVE-APIERR": {"original_doc": "Test doc"}},
        llm_caller_fn=mock_llm_err
    )
    assert_test("Test 11 - API error returned dict mapped to execution_error",
                res_apierr.failed_call_count == 1 and
                res_apierr.final_answer_class == "execution_error" and
                res_apierr.isolated_calls[0].robustrag_vote == "execution_error" and
                res_apierr.isolated_calls[0].error_information == "API timeout")

    # TEST 12: ValueError for OPENROUTER_API_KEY
    def mock_llm_valueerror(*args, **kwargs):
        raise ValueError("OPENROUTER_API_KEY is not set sk-or-v1-fake-key-that-should-be-redacted")

    res_valueerror = run_robustrag_for_cve(
        cve_id="CVE-VALUEERR",
        probe_question="Is it vulnerable?",
        condition="Condition A",
        probe_version="1.0",
        product="Prod",
        retrieved_docs=[{"doc_id": "CVE-VALUEERR_orig", "rank": 1}],
        doc_lookup={"CVE-VALUEERR": {"original_doc": "Test doc"}},
        llm_caller_fn=mock_llm_valueerror
    )
    assert_test("Test 12.1 - ValueError caught and mapped to execution_error",
                res_valueerror.failed_call_count == 1 and
                res_valueerror.final_answer_class == "execution_error" and
                res_valueerror.isolated_calls[0].robustrag_vote == "execution_error")
                
    assert_test("Test 12.2 - ValueError does not receive a semantic vote",
                res_valueerror.isolated_calls[0].robustrag_vote not in ["original-supported", "mutated-supported", "insufficient", "conflict"] and
                res_valueerror.isolated_calls[0].phase0_classification == "execution_error")

    assert_test("Test 12.3 - Final result indicates incomplete execution without fake security decision",
                res_valueerror.security_class == "execution_error" and 
                res_valueerror.tie_breaking_applied == "incomplete_execution")

    assert_test("Test 12.4 - Error text is preserved safely and API key is redacted",
                "ValueError" in res_valueerror.isolated_calls[0].error_information and
                "REDACTED_API_KEY" in res_valueerror.isolated_calls[0].error_information and
                "sk-or-v1-fake-key" not in res_valueerror.isolated_calls[0].error_information)
                
    # Verify the serialized string does not contain the key
    serialized_res = json.dumps(res_valueerror.to_dict())
    assert_test("Test 12.5 - API Key absent from serialized output", "sk-or-v1" not in serialized_res)

    # TEST 13: Generic network exception
    def mock_llm_networkerr(*args, **kwargs):
        raise ConnectionError("Network connection reset by peer")
        
    res_networkerr = run_robustrag_for_cve(
        cve_id="CVE-NETERR",
        probe_question="Is it vulnerable?",
        condition="Condition A",
        probe_version="1.0",
        product="Prod",
        retrieved_docs=[{"doc_id": "CVE-NETERR_orig", "rank": 1}],
        doc_lookup={"CVE-NETERR": {"original_doc": "Test doc"}},
        llm_caller_fn=mock_llm_networkerr
    )
    assert_test("Test 13 - Generic network exception mapped properly",
                res_networkerr.failed_call_count == 1 and
                "ConnectionError" in res_networkerr.isolated_calls[0].error_information and
                res_networkerr.final_answer_class == "execution_error")

    return all_passed

if __name__ == "__main__":
    run_tests()
