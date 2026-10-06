import dataclasses
from typing import Callable, List, Dict, Any, Tuple
from .schemas import ProveRAGResult, EvalOutput
from .provenance import assign_provenance_ids
from .evaluator import build_evaluator_prompt
from .citation_parser import parse_evaluator_output
from .config import (
    PRIMARY_MODEL, PRIMARY_PROVIDER, PRIMARY_TEMP, PRIMARY_MAX_TOKENS,
    EVALUATOR_MODEL, EVALUATOR_PROVIDER, EVALUATOR_TEMP, EVALUATOR_MAX_TOKENS
)

def run_proverag_pipeline(
    run_id: str,
    cve_id: str,
    probe_version: str,
    retrieved_documents: List[Dict[str, Any]],
    frozen_system_prompt: str,
    frozen_user_prompt: str,
    exact_generation_context: str,
    generate_fn: Callable[[str, str], Tuple[str, float, str]],
    classify_fn: Callable[[str], Tuple[str, str]],
    evaluate_fn: Callable[[List[Dict[str, str]]], Tuple[str, float, str]],
    retrieval_condition: str = "Condition A",
    probe_question: str = ""
) -> ProveRAGResult:
    if retrieval_condition != "Condition A":
        raise ValueError("ProveRAG adaptation requires frozen Condition A retrieval")
    
    errors = []
    execution_statuses = {"primary": "pending", "auxiliary": "skipped"}
    
    # 1. Primary Security Endpoint
    try:
        raw_answer, p_latency, p_status = generate_fn(frozen_system_prompt, frozen_user_prompt)
        execution_statuses["primary"] = p_status
    except Exception as e:
        raw_answer, p_latency = "", 0.0
        execution_statuses["primary"] = "error"
        errors.append(f"Primary Generation Error: {str(e)}")

    # 2. Frozen Primary Classifier (only after successful generation)
    classifier_output, security_consequence = "unavailable", "unavailable"
    if execution_statuses["primary"] == "success":
        try:
            classifier_output, security_consequence = classify_fn(raw_answer)
        except Exception as e:
            classifier_output, security_consequence = "error", "unavailable"
            execution_statuses["primary"] = "classifier_error"
            errors.append(f"Primary Classification Error: {str(e)}")
        
    # 3. Auxiliary Provenance Assignment
    try:
        prov_mapping = assign_provenance_ids(retrieved_documents)
        prov_mapping_dicts = [dataclasses.asdict(p) for p in prov_mapping]
    except Exception as e:
        prov_mapping = []
        prov_mapping_dicts = []
        errors.append(f"Provenance Assignment Error: {str(e)}")
        execution_statuses["auxiliary"] = "error"
        
    # 4. Auxiliary Provenance Evaluation
    eval_output_obj = EvalOutput("", [], [], [], "absent_or_invalid", "", "skipped")
    a_latency = 0.0
    
    if execution_statuses["primary"] == "success" and prov_mapping:
        try:
            eval_prompt = build_evaluator_prompt(raw_answer, prov_mapping)
            raw_eval_json, a_latency, a_status = evaluate_fn(eval_prompt)
            execution_statuses["auxiliary"] = a_status
            
            if a_status == "success":
                eval_output_obj = parse_evaluator_output(raw_eval_json, prov_mapping)
            else:
                eval_output_obj = EvalOutput(raw_eval_json, [], [], [], "absent_or_invalid", "", "evaluation_error")
        except Exception as e:
            execution_statuses["auxiliary"] = "error"
            errors.append(f"Auxiliary Evaluation Error: {str(e)}")
            
    return ProveRAGResult(
        run_id=run_id,
        cve_id=cve_id,
        probe=probe_version,
        retrieval_condition=retrieval_condition,
        probe_question=probe_question or frozen_user_prompt,
        retrieved_documents=retrieved_documents,
        provenance_mapping=prov_mapping_dicts,
        exact_generation_context=exact_generation_context,
        frozen_system_prompt=frozen_system_prompt,
        frozen_user_prompt=frozen_user_prompt,
        primary_model_config={
            "model": PRIMARY_MODEL,
            "provider": PRIMARY_PROVIDER,
            "temperature": PRIMARY_TEMP,
            "max_tokens": PRIMARY_MAX_TOKENS
        },
        raw_primary_answer=raw_answer,
        primary_latency=p_latency,
        frozen_classifier_output=classifier_output,
        security_consequence=security_consequence,
        proverag_eval=eval_output_obj,
        auxiliary_model_config={
            "model": EVALUATOR_MODEL,
            "provider": EVALUATOR_PROVIDER,
            "temperature": EVALUATOR_TEMP,
            "max_tokens": EVALUATOR_MAX_TOKENS
        },
        auxiliary_latency=a_latency,
        execution_statuses=execution_statuses,
        errors=errors
    )
