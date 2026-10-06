from .config import TYPE_C_PROMPT_TEMPLATE

def build_isolated_prompt(document_text: str, product: str, probe_version: str, cve_id: str) -> str:
    """
    Builds the Type-C prompt using only the single isolated document.
    """
    return TYPE_C_PROMPT_TEMPLATE.format(
        context=document_text,
        product=product,
        probe_version=probe_version,
        cve_id=cve_id
    )

def prepare_isolated_contexts(retrieved_docs: list[dict], doc_lookup: dict) -> list[dict]:
    """
    Returns a list of dicts with isolated context info.
    If a document cannot be resolved in doc_lookup, it is explicitly included with error = True.
    """
    isolated_contexts = []
    
    for doc_res in retrieved_docs:
        doc_id = doc_res["doc_id"]
        
        # Exact frozen identifiers used in Phase 0
        if doc_id.endswith("_mutated"):
            doc_cve_id = doc_id.removesuffix("_mutated")
            is_mut = True
            document_identity = "mutated"
        elif doc_id.endswith("_orig"):
            doc_cve_id = doc_id.removesuffix("_orig")
            is_mut = False
            document_identity = "original"
        else:
            doc_cve_id = doc_id
            is_mut = False
            document_identity = "unknown"
            
        if doc_cve_id in doc_lookup:
            if is_mut:
                doc_text = doc_lookup[doc_cve_id].get("mutated_doc", "")
            else:
                doc_text = doc_lookup[doc_cve_id].get("original_doc", "")
            
            isolated_contexts.append({
                "doc_id": doc_id,
                "doc_rank": doc_res.get("rank", 0),
                "doc_text": doc_text,
                "document_identity": document_identity,
                "document_version": doc_lookup[doc_cve_id].get("probe_version", None),
                "error": False,
                "error_msg": None
            })
        else:
            # Task 2: Explicitly record resolution errors
            isolated_contexts.append({
                "doc_id": doc_id,
                "doc_rank": doc_res.get("rank", 0),
                "doc_text": "",
                "document_identity": document_identity,
                "document_version": None,
                "error": True,
                "error_msg": f"Missing document in lookup: {doc_cve_id}"
            })
            
    return isolated_contexts
