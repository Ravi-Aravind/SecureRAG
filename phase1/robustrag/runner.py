import time
import sys
import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from .config import SYSTEM_PROMPT, LLM_MODEL, TEMPERATURE, MAX_TOKENS
from .schemas import IsolatedCall, RobustRAGResult
from .isolation import build_isolated_prompt, prepare_isolated_contexts
from .classifier import classify_and_map
from .aggregator import aggregate_votes, get_final_answer_and_security_class

def run_robustrag_for_cve(
    cve_id: str, 
    probe_question: str,
    condition: str, 
    probe_version: str, 
    product: str, 
    retrieved_docs: list[dict], 
    doc_lookup: dict,
    llm_caller_fn=None
) -> RobustRAGResult:
    """
    Executes the RobustRAG logic for a single CVE and condition.
    """
    if llm_caller_fn is None:
        from phase0.src.llm_caller import call_llm
        llm_caller_fn = call_llm

    isolated_contexts = prepare_isolated_contexts(retrieved_docs, doc_lookup)
    isolated_calls = []
    
    start_time = time.time()
    
    for ctx in isolated_contexts:
        if ctx["error"]:
            isolated_calls.append(IsolatedCall(
                doc_id=ctx["doc_id"],
                rank=ctx["doc_rank"],
                document_identity=ctx["document_identity"],
                document_version=ctx["document_version"],
                document_text="",
                isolated_prompt="",
                raw_response="",
                phase0_classification="execution_error",
                robustrag_vote="execution_error",
                success=False,
                error_information=ctx["error_msg"],
                model_identifier=LLM_MODEL,
                provider="openrouter",
                latency=0.0,
                usage={}
            ))
            continue
            
        # Build prompt
        user_prompt = build_isolated_prompt(
            document_text=ctx["doc_text"],
            product=product,
            probe_version=probe_version,
            cve_id=cve_id
        )
        
        call_start = time.time()
        
        # Exception Handling Boundary
        try:
            res = llm_caller_fn(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
                model=LLM_MODEL,
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS
            )
        except Exception as e:
            error_str = str(e)
            # Ensure we never leak an API key in the traceback string if it somehow got there
            if "sk-or-v1-" in error_str:
                error_str = "REDACTED_API_KEY"
            res = {"error": f"Exception during LLM call: {type(e).__name__} - {error_str}"}

        call_latency = (time.time() - call_start) * 1000.0
        
        # Task 1: API error vs Parsing failure
        if res.get("error"):
            response_text = ""
            phase0_class = "execution_error"
            robustrag_vote = "execution_error"
            success = False
            error_info = res["error"]
        else:
            response_text = res.get("response_text", "")
            phase0_class, robustrag_vote = classify_and_map(response_text)
            success = True
            error_info = None
        
        # Record complete provenance schema
        isolated_calls.append(IsolatedCall(
            doc_id=ctx["doc_id"],
            rank=ctx["doc_rank"],
            document_identity=ctx["document_identity"],
            document_version=ctx["document_version"],
            document_text=ctx["doc_text"],
            isolated_prompt=user_prompt,
            raw_response=response_text,
            phase0_classification=phase0_class,
            robustrag_vote=robustrag_vote,
            success=success,
            error_information=error_info,
            model_identifier=res.get("model", LLM_MODEL),
            provider="openrouter",
            latency=call_latency,
            usage=res.get("usage", {})
        ))
        
    latency_ms = (time.time() - start_time) * 1000.0
    
    # Aggregation
    votes = [call.robustrag_vote for call in isolated_calls]
    final_vote, tie_breaking_applied, vote_counts = aggregate_votes(votes)
    
    # Map final security class
    final_answer_class, security_class = get_final_answer_and_security_class(final_vote)
    
    metadata = {
        "model": LLM_MODEL,
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "final_robustrag_vote": final_vote
    }
    
    successful_calls = sum(1 for call in isolated_calls if call.success)
    failed_calls = len(isolated_calls) - successful_calls
    
    return RobustRAGResult(
        cve_id=cve_id,
        probe_question=probe_question,
        probe_version=probe_version,
        condition=condition,
        defense_name="RobustRAG-style categorical aggregation adaptation",
        final_answer_class=final_answer_class,
        security_class=security_class,
        tie_breaking_applied=tie_breaking_applied,
        vote_counts=vote_counts,
        expected_retrieved_document_count=len(retrieved_docs),
        successful_call_count=successful_calls,
        failed_call_count=failed_calls,
        total_llm_call_count=len(isolated_calls),
        isolated_calls=isolated_calls,
        latency_ms=latency_ms,
        metadata=metadata
    )
