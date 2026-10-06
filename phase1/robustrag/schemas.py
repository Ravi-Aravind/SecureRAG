from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

@dataclass
class IsolatedCall:
    doc_id: str
    rank: int
    document_identity: str
    document_version: Optional[str]
    document_text: str
    isolated_prompt: str
    raw_response: str
    phase0_classification: str
    robustrag_vote: str
    success: bool
    error_information: Optional[str]
    model_identifier: str
    provider: str
    latency: float
    usage: Dict[str, Any]

@dataclass
class VoteCounts:
    original_supported: int = 0
    mutated_supported: int = 0
    insufficient: int = 0
    conflict: int = 0
    execution_error: int = 0

    def to_dict(self):
        return {
            "original-supported": self.original_supported,
            "mutated-supported": self.mutated_supported,
            "insufficient": self.insufficient,
            "conflict": self.conflict,
            "execution_error": self.execution_error
        }

@dataclass
class RobustRAGResult:
    cve_id: str
    probe_question: str
    probe_version: str
    condition: str
    defense_name: str
    final_answer_class: str
    security_class: str
    tie_breaking_applied: str
    vote_counts: VoteCounts
    expected_retrieved_document_count: int
    successful_call_count: int
    failed_call_count: int
    total_llm_call_count: int
    isolated_calls: List[IsolatedCall]
    latency_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d['vote_counts'] = self.vote_counts.to_dict()
        return d
