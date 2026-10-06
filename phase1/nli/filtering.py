from typing import List, Tuple, Dict, Any
from .schemas import DirectedPair, ContradictionScore

def compute_c_min_retention(
    documents: List[Dict[str, Any]], 
    pairwise_results: List[DirectedPair]
) -> Tuple[List[ContradictionScore], int, List[str], List[str], str]:
    """
    Implements the parameter-free Minimum Contradiction Consensus Rule.
    """
    # 1. Build conflict edges (OR logic)
    # A pair (A, B) is in conflict if A->B is Contradiction OR B->A is Contradiction
    conflict_edges = set()
    
    for r in pairwise_results:
        if r.argmax_label == "Contradiction":
            # Add undirected edge
            edge = tuple(sorted([r.source_doc_id, r.target_doc_id]))
            conflict_edges.add(edge)
            
    # 2. Compute C_i for each document
    scores = []
    
    # Sort for deterministic processing
    sorted_docs = sorted(documents, key=lambda x: x["rank"])
    
    for doc in sorted_docs:
        doc_id = doc["doc_id"]
        conflicts = []
        for e in conflict_edges:
            if doc_id in e:
                other = e[1] if e[0] == doc_id else e[0]
                conflicts.append(other)
                
        scores.append(ContradictionScore(
            doc_id=doc_id,
            rank=doc["rank"],
            score=len(conflicts),
            conflicting_doc_ids=sorted(conflicts)
        ))
        
    # 3. Find C_min
    if not scores:
        return [], 0, [], [], "Empty document set"
        
    c_min = min(s.score for s in scores)
    
    # 4. Retention selection
    retained_doc_ids = []
    filtered_doc_ids = []
    
    for s in scores:
        if s.score == c_min:
            retained_doc_ids.append(s.doc_id)
        else:
            filtered_doc_ids.append(s.doc_id)
            
    # Fallback sanity check (mathematically guaranteed not to empty unless input is empty)
    if len(retained_doc_ids) == 0:
        # Fallback to all
        retained_doc_ids = [d["doc_id"] for d in sorted_docs]
        filtered_doc_ids = []
        rule = "Fallback: Retained all (C_min empty edgecase)"
    elif len(filtered_doc_ids) == 0:
        rule = f"Retained all (Perfect tie, C_min={c_min})"
    else:
        rule = f"Retained minimum contradiction subset (C_min={c_min})"
        
    return scores, c_min, retained_doc_ids, filtered_doc_ids, rule

