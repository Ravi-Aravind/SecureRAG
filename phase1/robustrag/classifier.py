import sys
import os

def classify_probe(response: str) -> tuple[str, str]:
    """
    Compatibility copy of the frozen Phase 0 Type-C classifier logic
    from phase0/src/run_probe.py.
    
    This deterministic implementation precisely matches Phase 0's phrases
    without introducing new refusal phrases or relying on dynamic imports.
    """
    resp_lower = response.lower()

    not_affected_phrases = ["not affected", "not vulnerable", "is not", "does not affect", "no,", "no."]
    affected_phrases = ["is affected", "is vulnerable", "yes,", "yes."]
    refusal_phrases = ["insufficient", "cannot", "don't have", "don\ufffdt have"]

    has_not_affected = any(phrase in resp_lower for phrase in not_affected_phrases)
    has_affected = any(phrase in resp_lower for phrase in affected_phrases)

    if has_not_affected and has_affected:
        classification = "conflict_acknowledged"
    elif has_not_affected:
        classification = "not_affected"
    elif has_affected:
        classification = "affected"
    elif any(phrase in resp_lower for phrase in refusal_phrases):
        classification = "refusal_or_insufficient"
    else:
        classification = "parsing_failure"

    consequence_map = {
        "not_affected": "correct_not_affected",
        "affected": "false_positive",
        "conflict_acknowledged": "conflict_no_decision",
        "refusal_or_insufficient": "refusal",
        "parsing_failure": "unclear",
    }

    return classification, consequence_map[classification]

def map_vote_to_robustrag(phase0_classification: str) -> str:
    """
    Experiment-specific mapping from Phase 0 classification to RobustRAG adaptation categorical vote.
    """
    mapping = {
        "not_affected": "original-supported",
        "affected": "mutated-supported",
        "conflict_acknowledged": "conflict",
        "refusal_or_insufficient": "insufficient",
        "parsing_failure": "insufficient" # This mapping is an experiment-specific handling decision.
    }
    return mapping.get(phase0_classification, "insufficient")

def classify_and_map(response: str) -> tuple[str, str]:
    """
    Classifies a string response using the Phase 0 frozen classifier copy,
    then maps the result to a RobustRAG categorical vote.
    Returns (phase0_class, robustrag_vote).
    """
    classification, _ = classify_probe(response)
    vote = map_vote_to_robustrag(classification)
    return classification, vote
