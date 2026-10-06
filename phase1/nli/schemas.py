from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

@dataclass
class DirectedPair:
    source_doc_id: str
    source_rank: int
    target_doc_id: str
    target_rank: int
    premise: str
    hypothesis: str
    p_contradiction: float
    p_entailment: float
    p_neutral: float
    argmax_label: str
    
    def to_dict(self):
        return asdict(self)

@dataclass
class ContradictionScore:
    doc_id: str
    rank: int
    score: int
    conflicting_doc_ids: List[str]
    
    def to_dict(self):
        return asdict(self)

@dataclass
class NLIResult:
    run_id: str
    cve_id: str
    probe: str
    retrieval_condition: str
    retrieved_documents: List[Dict[str, Any]]
    pairwise_nli_results: List[DirectedPair]
    contradiction_scores: List[ContradictionScore]
    c_min: int
    retained_documents: List[str]
    filtered_documents: List[str]
    filtering_rule: str
    final_evidence: List[Dict[str, Any]]
    model_metadata: Dict[str, str]
    inference_metadata: Dict[str, Any]
    generation_configuration: Dict[str, Any]
    raw_response: Optional[str] = None
    phase0_classification: Optional[str] = None
    security_class: Optional[str] = None
    validation_status: str = "PENDING"
    
    def to_dict(self):
        d = asdict(self)
        d["pairwise_nli_results"] = [p.to_dict() for p in self.pairwise_nli_results]
        d["contradiction_scores"] = [c.to_dict() for c in self.contradiction_scores]
        return d

