from typing import List, Dict
from .schemas import ProvenanceDoc

def build_evaluator_prompt(answer: str, mapping: List[ProvenanceDoc]) -> List[Dict[str, str]]:
    sys_prompt = "You are an expert security evaluator acting as ProveRAG's self-critique module. You must strictly output valid JSON."
    
    context = "\n".join([f"[{m.prov_id}] {m.text}" for m in mapping])
    
    user_prompt = f"""Evaluate the Generated Answer against the Retrieved Context.

Retrieved Context:
{context}

Generated Answer:
{answer}

Output a JSON object containing:
- "provenance": A list of provenance IDs (e.g. ["DOC_1"]) that the Answer relies upon. Use an empty list [] if none apply.
- "rationale": String explaining the reasoning.
"""
    return [{"role": "system", "content": sys_prompt}, {"role": "user", "content": user_prompt}]
