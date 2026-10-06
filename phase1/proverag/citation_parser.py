import json
from typing import List
from .schemas import ProvenanceDoc, EvalOutput

def parse_evaluator_output(raw_json: str, mapping: List[ProvenanceDoc]) -> EvalOutput:
    prov_ids = []
    rationale = ""
    parse_status = "valid"
    
    try:
        data = json.loads(raw_json)
        if not isinstance(data, dict) or "provenance" not in data:
            raise ValueError("invalid evaluator schema")
        prov_ids = data["provenance"]
        rationale = data.get("rationale", "")
        if not isinstance(prov_ids, list) or not all(isinstance(pid, str) for pid in prov_ids) or not isinstance(rationale, str):
            raise ValueError("invalid evaluator schema")
    except Exception:
        prov_ids = []
        rationale = ""
        try:
            parse_status = "invalid_schema" if isinstance(json.loads(raw_json), dict) else "malformed_json"
        except Exception:
            parse_status = "malformed_json"
        
    prov_ids = list(prov_ids)
    map_dict = {m.prov_id: m for m in mapping}
    cited_docs = []
    validity = []
    
    for pid in prov_ids:
        if pid in map_dict:
            cited_docs.append(map_dict[pid].doc_id)
            validity.append(True)
        else:
            cited_docs.append(None)
            validity.append(False)
            
    # Classify on UNIQUE valid documents
    valid_map_matches = [map_dict[pid] for pid in prov_ids if pid in map_dict]
    unique_docs = list({m.doc_id: m for m in valid_map_matches}.values())
    
    has_mut = any(m.is_mutated for m in unique_docs)
    valid_count = len(unique_docs)
    
    if parse_status != "valid":
        outcome = "absent_or_invalid"
    elif valid_count == 0:
        outcome = "absent_or_invalid"
    elif has_mut:
        outcome = "poisoned_cited"
    elif valid_count == 1:
        outcome = "original_cited"
    else:
        outcome = "multiple_cited"
        
    return EvalOutput(
        raw_json=raw_json,
        parsed_prov_ids=prov_ids,
        cited_doc_ids=cited_docs,
        validity=validity,
        citation_outcome=outcome,
        rationale=rationale,
        parse_status=parse_status
    )
