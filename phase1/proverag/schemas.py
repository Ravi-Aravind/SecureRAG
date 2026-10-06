from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class ProvenanceDoc:
    prov_id: str
    doc_id: str
    rank: int
    text: str
    is_mutated: bool

@dataclass
class EvalOutput:
    raw_json: str
    parsed_prov_ids: List[str]
    cited_doc_ids: List[Optional[str]]
    validity: List[bool]
    citation_outcome: str
    rationale: str
    parse_status: str = "valid"

@dataclass
class ProveRAGResult:
    run_id: str
    cve_id: str
    probe: str
    retrieval_condition: str
    retrieved_documents: List[Dict[str, Any]]
    provenance_mapping: List[Dict[str, Any]]
    exact_generation_context: str
    frozen_system_prompt: str
    frozen_user_prompt: str
    
    # PRIMARY
    raw_primary_answer: str
    primary_latency: float
    frozen_classifier_output: str
    security_consequence: str
    primary_model_config: Dict[str, Any]
    
    # AUXILIARY
    proverag_eval: EvalOutput
    auxiliary_model_config: Dict[str, Any]
    auxiliary_latency: float
    
    execution_statuses: Dict[str, str]
    probe_question: str = ""
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        import dataclasses
        return dataclasses.asdict(self)
