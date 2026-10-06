from typing import List, Dict
from .schemas import ProvenanceDoc

def assign_provenance_ids(docs: List[Dict]) -> List[ProvenanceDoc]:
    if len(docs) != 5:
        raise ValueError(f"Expected exactly 5 retrieved documents, got {len(docs)}")
        
    out = []
    for i, doc in enumerate(docs):
        expected_rank = i + 1
        actual_rank = doc.get("rank")
        if actual_rank != expected_rank:
            raise ValueError(f"Expected rank {expected_rank}, got {actual_rank}")
            
        prov_id = f"DOC_{expected_rank}"
        doc_id = str(doc.get("doc_id", ""))
        if doc_id.endswith("_mutated"):
            is_mut = True
        elif doc_id.endswith("_orig"):
            is_mut = False
        else:
            raise ValueError(f"Unsupported frozen document ID convention: {doc_id}")
        text = doc.get("text")
        if not isinstance(text, str) or not text:
            raise ValueError(f"Full document text is required for {doc_id}")
        out.append(ProvenanceDoc(
            prov_id=prov_id,
            doc_id=doc_id,
            rank=expected_rank,
            text=text,
            is_mutated=is_mut
        ))
    return out
