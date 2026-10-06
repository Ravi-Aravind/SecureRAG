"""Auditable binding of the ProveRAG adaptation to frozen Phase 0."""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .config import EVALUATOR_MAX_TOKENS, EVALUATOR_MODEL, EVALUATOR_TEMP

ROOT = Path(__file__).resolve().parents[2]


def load_frozen_condition_a(cve_id: str) -> List[Dict[str, Any]]:
    """Read the recorded Condition A retrieval and join full document text."""
    with (ROOT / "phase0/data/retrieval_results.json").open(encoding="utf-8") as f:
        retrieval = json.load(f)
    with (ROOT / "phase0/data/documents.json").open(encoding="utf-8") as f:
        documents = {item["cve_id"]: item for item in json.load(f)}

    entries = [r for r in retrieval if r.get("cve_id") == cve_id and r.get("condition") == "Condition A"]
    if len(entries) != 1:
        raise ValueError(f"Expected one frozen Condition A result for {cve_id}, got {len(entries)}")
    return validate_frozen_condition_a_record(cve_id, entries[0], documents)


def validate_frozen_condition_a_record(cve_id: str, record: Dict[str, Any], documents: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    if record.get("condition") != "Condition A" or record.get("query_cve_id") != cve_id:
        raise ValueError("Frozen retrieval identity does not match requested Condition A CVE")
    results = record.get("results", [])
    if len(results) != 5 or [r.get("rank") for r in results] != [1, 2, 3, 4, 5]:
        raise ValueError(f"Frozen Condition A retrieval for {cve_id} is not exactly ranked 1..5")

    enriched = []
    seen_ids = set()
    for result in results:
        doc_id = result.get("doc_id", "")
        if not doc_id.endswith("_orig"):
            raise ValueError(f"Condition A contains non-original document: {doc_id}")
        source_id = doc_id[:-5]
        if source_id in seen_ids:
            raise ValueError(f"Duplicate frozen retrieved document: {doc_id}")
        seen_ids.add(source_id)
        if source_id not in documents:
            raise ValueError(f"Unknown frozen retrieved document: {doc_id}")
        if source_id not in documents or not documents[source_id].get("original_doc"):
            raise ValueError(f"Full document text is unavailable for {doc_id}")
        enriched.append({"doc_id": doc_id, "rank": result["rank"],
                         "similarity": result.get("similarity"),
                         "text": documents[source_id]["original_doc"]})
    return enriched


def verify_frozen_primary_configuration() -> Dict[str, Any]:
    """Fail closed unless primary settings match the Phase 0 source."""
    import inspect
    from phase0.src import llm_caller, run_full_experiment
    max_tokens = inspect.signature(llm_caller.call_llm).parameters["max_tokens"].default
    config = {"model": llm_caller.DEFAULT_MODEL, "provider": "OpenRouter",
              "base_url": llm_caller.OPENROUTER_BASE_URL,
              "temperature": run_full_experiment.TEMPERATURE, "max_tokens": max_tokens}
    expected = {"model": "openai/gpt-4o-mini", "provider": "OpenRouter",
                "base_url": "https://openrouter.ai/api/v1", "temperature": 0, "max_tokens": 512}
    if config != expected:
        raise RuntimeError(f"Frozen Phase 0 primary configuration mismatch: {config}")
    return config


def bind_frozen_primary(cve: Dict[str, str], retrieved: List[Dict[str, Any]]):
    """Bind callbacks to the existing Phase 0 prompt, caller, and classifier."""
    from phase0.src.llm_caller import SYSTEM_PROMPT, build_type_c_prompt, call_llm, DEFAULT_MODEL
    from phase0.src.run_full_experiment import classify_probe, MODEL_NAME, TEMPERATURE
    frozen_config = verify_frozen_primary_configuration()
    if DEFAULT_MODEL != MODEL_NAME or TEMPERATURE != 0:
        raise RuntimeError("Phase 0 primary model definitions disagree")

    prompt = build_type_c_prompt([item["text"] for item in retrieved], cve["product"], cve["cve_id"], cve["probe_version"])

    def generate(system_prompt: str, user_prompt: str) -> Tuple[str, float, str]:
        if system_prompt != SYSTEM_PROMPT or user_prompt != prompt:
            raise ValueError("Primary prompt does not match frozen Phase 0 construction")
        started = time.perf_counter()
        result = call_llm(system_prompt=SYSTEM_PROMPT, user_prompt=prompt,
                          model=DEFAULT_MODEL, temperature=0.0,
                          max_tokens=frozen_config["max_tokens"])
        status = "error" if result.get("error") else "success"
        return result.get("response_text", ""), (time.perf_counter() - started) * 1000.0, status

    return SYSTEM_PROMPT, prompt, generate, classify_probe


def _extract_probe_question(prompt: str) -> str:
    marker = "Question:\n"
    if marker not in prompt:
        raise ValueError("Frozen Type-C prompt has no Question field")
    question = prompt.split(marker, 1)[1].split("\n\n", 1)[0]
    if not question:
        raise ValueError("Frozen Type-C question is empty")
    return question


def run_frozen_condition_a_proverag(cve_id: str):
    """Only supported production entry point for a frozen Condition A run."""
    with (ROOT / "phase0/data/selected_cves.json").open(encoding="utf-8") as f:
        selected = {item["cve_id"]: item for item in json.load(f)}
    if cve_id not in selected:
        raise ValueError(f"CVE is not in the frozen selected set: {cve_id}")
    cve = selected[cve_id]
    retrieved = load_frozen_condition_a(cve_id)
    system_prompt, user_prompt, generate, classify = bind_frozen_primary(cve, retrieved)
    from phase0.src.llm_caller import call_llm
    from .runner import run_proverag_pipeline

    def evaluate(messages):
        started = time.perf_counter()
        result = call_llm(system_prompt=messages[0]["content"], user_prompt=messages[1]["content"],
                          model=EVALUATOR_MODEL, temperature=EVALUATOR_TEMP,
                          max_tokens=EVALUATOR_MAX_TOKENS)
        return result.get("response_text", ""), (time.perf_counter() - started) * 1000.0, \
            "error" if result.get("error") else "success"

    return run_proverag_pipeline(
        run_id=f"{cve_id}_Condition_A_ProveRAG", cve_id=cve_id,
        probe_version=cve["probe_version"], retrieved_documents=retrieved,
        frozen_system_prompt=system_prompt, frozen_user_prompt=user_prompt,
        exact_generation_context=user_prompt, generate_fn=generate,
        classify_fn=classify, evaluate_fn=evaluate,
        retrieval_condition="Condition A", probe_question=_extract_probe_question(user_prompt))
