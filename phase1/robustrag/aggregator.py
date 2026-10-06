from .schemas import VoteCounts

def aggregate_votes(votes: list[str]) -> tuple[str, str, VoteCounts]:
    """
    Aggregates the votes categorically according to the Phase 1 RobustRAG design.
    Returns: (final_vote, tie_breaking_applied, vote_counts_object)
    """
    counts = VoteCounts()
    for v in votes:
        if v == "original-supported":
            counts.original_supported += 1
        elif v == "mutated-supported":
            counts.mutated_supported += 1
        elif v == "insufficient":
            counts.insufficient += 1
        elif v == "conflict":
            counts.conflict += 1
        elif v == "execution_error":
            counts.execution_error += 1
    
    if counts.execution_error > 0:
        # "If one or more required isolated calls fail, the final result must clearly indicate incomplete execution"
        return "execution_error", "incomplete_execution", counts

    v_orig = counts.original_supported
    v_mut = counts.mutated_supported

    if v_orig > v_mut:
        final_vote = "original-supported"
        tie_breaking = "majority_original"
    elif v_mut > v_orig:
        final_vote = "mutated-supported"
        tie_breaking = "majority_mutated"
    elif v_orig == v_mut and v_orig > 0:
        final_vote = "conflict"
        tie_breaking = "tie_conflict"
    else:
        # v_orig == 0 and v_mut == 0
        final_vote = "insufficient"
        tie_breaking = "no_signal"

    return final_vote, tie_breaking, counts

def get_final_answer_and_security_class(final_vote: str) -> tuple[str, str]:
    """
    Maps the final categorical vote back to Phase 0 answer and security classes.
    """
    if final_vote == "execution_error":
        return "execution_error", "execution_error"
        
    mapping = {
        "original-supported": ("not_affected", "correct_not_affected"),
        "mutated-supported": ("affected", "false_positive"),
        "conflict": ("conflict_acknowledged", "conflict_no_decision"),
        "insufficient": ("refusal_or_insufficient", "refusal")
    }
    return mapping.get(final_vote, ("refusal_or_insufficient", "refusal"))
