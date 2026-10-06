import os
import sys
import json
import uuid

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phase1.nli.schemas import NLIResult, DirectedPair, ContradictionScore
from phase1.nli.pairwise import execute_pairwise_nli
from phase1.nli.filtering import compute_c_min_retention
from phase1.nli.runner import run_nli_defense
from phase1.validation.check_phase0_integrity import check_integrity

def test_pairwise_logic():
    # Mock documents
    docs = [
        {"doc_id": "D1", "rank": 1, "text": "text1"},
        {"doc_id": "D2", "rank": 2, "text": "text2"},
        {"doc_id": "D3", "rank": 3, "text": "text3"},
    ]
    
    # Mock predict fn that always returns entailment except D1->D2 is contradiction
    def mock_predict(inputs):
        if inputs["text"] == "text1" and inputs["text_pair"] == "text2":
            return [[{"label": "contradiction", "score": 0.9}]]
        return [[{"label": "entailment", "score": 0.8}]]
        
    pairs = execute_pairwise_nli(docs, mock_predict)
    
    assert len(pairs) == 6, f"Expected 6 pairs for 3 docs, got {len(pairs)}"
    
    # Check deterministic order
    assert pairs[0].source_doc_id == "D1" and pairs[0].target_doc_id == "D2"
    assert pairs[1].source_doc_id == "D1" and pairs[1].target_doc_id == "D3"
    
    # Check no self-pairs
    for p in pairs:
        assert p.source_doc_id != p.target_doc_id
        
    # Check labels
    c_pair = next(p for p in pairs if p.source_doc_id == "D1" and p.target_doc_id == "D2")
    assert c_pair.argmax_label == "Contradiction"
    assert c_pair.p_contradiction == 0.9

def test_filtering_logic():
    docs = [
        {"doc_id": f"D{i}", "rank": i, "text": f"text{i}"}
        for i in range(1, 6)
    ]
    
    # Simulate 1 poisoned (D5) vs 4 clean (D1-D4)
    # D5 contradicts D1, D2, D3, D4. 
    # That means symmetric edges: (D1,D5), (D2,D5), (D3,D5), (D4,D5)
    mock_pairs = []
    for d1 in docs:
        for d2 in docs:
            if d1["doc_id"] == d2["doc_id"]:
                continue
            
            is_conflict = (d1["doc_id"] == "D5" or d2["doc_id"] == "D5")
            mock_pairs.append(DirectedPair(
                source_doc_id=d1["doc_id"], source_rank=d1["rank"],
                target_doc_id=d2["doc_id"], target_rank=d2["rank"],
                premise="", hypothesis="",
                p_contradiction=0.9 if is_conflict else 0.1,
                p_entailment=0.1 if is_conflict else 0.9,
                p_neutral=0.0,
                argmax_label="Contradiction" if is_conflict else "Entailment"
            ))
            
    scores, c_min, retained, filtered, rule = compute_c_min_retention(docs, mock_pairs)
    
    assert c_min == 1
    assert "D5" in filtered
    assert len(filtered) == 1
    assert "D1" in retained and len(retained) == 4
    
    # Test Complete Tie
    mock_pairs_tie = []
    for d1 in docs:
        for d2 in docs:
            if d1["doc_id"] == d2["doc_id"]:
                continue
            mock_pairs_tie.append(DirectedPair(
                source_doc_id=d1["doc_id"], source_rank=d1["rank"],
                target_doc_id=d2["doc_id"], target_rank=d2["rank"],
                premise="", hypothesis="",
                p_contradiction=0.9, p_entailment=0.1, p_neutral=0.0,
                argmax_label="Contradiction"
            ))
            
    scores2, c_min2, retained2, filtered2, rule2 = compute_c_min_retention(docs, mock_pairs_tie)
    
    assert c_min2 == 4
    assert len(retained2) == 5
    assert len(filtered2) == 0
    assert "tie" in rule2.lower()
    
def test_end_to_end_runner():
    docs = [
        {"doc_id": f"D{i}", "rank": i, "text": f"Doc {i}"}
        for i in range(1, 6)
    ]
    
    def mock_predict(inputs):
        return [[{"label": "neutral", "score": 0.99}]]
        
    res = run_nli_defense(
        run_id="test-123",
        cve_id="CVE-TEST",
        probe="Is this vulnerable?",
        product="Prod",
        version="1.0",
        retrieved_documents=docs,
        predict_fn=mock_predict,
        metadata_override={"model_identifier": "mocked", "device": "cpu"}
    )
    
    # Check schema completeness
    d = res.to_dict()
    assert d["cve_id"] == "CVE-TEST"
    assert len(d["pairwise_nli_results"]) == 20
    assert d["c_min"] == 0
    assert len(d["retained_documents"]) == 5
    assert len(d["filtered_documents"]) == 0
    assert d["generation_configuration"]["user_prompt_passed"].startswith("Context documents:\nDoc 1\nDoc 2")
    
def main():
    print("Running NLI validation tests...")
    
    if not check_integrity():
        print("FAIL: Phase 0 integrity compromised.")
        sys.exit(1)
    print("PASS: Phase 0 integrity")
    
    test_pairwise_logic()
    print("PASS: Pairwise generation and matrix logic")
    
    test_filtering_logic()
    print("PASS: Minimum contradiction filtering & tie fallback")
    
    test_end_to_end_runner()
    print("PASS: Runner end-to-end execution and schema completion")
    
    print("All 4 test suites passed. No LLM calls were made.")
    
if __name__ == "__main__":
    main()

