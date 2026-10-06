# ProveRAG-Style Experiment-Specific Adaptation

## Method Overview
- **Published ProveRAG**: Introduced by Fayyazi et al. (arXiv:2410.17406), this system leverages an automated retrieval mechanism for web context, followed by an LLM that generates vulnerability analyses. A self-evaluation LLM verifies accuracy and provides explicit provenance mappings linking generated claims back to the retrieved sources.
- **Official Implementation**: Located at `RezzFayyazi/ProveRAG`, utilizing Langchain and OpenAI function calling to extract a structured Pydantic schema (`Evaluation`) comprising `value`, `rationale`, and `provenance`.
- **Incompatibilities**: The published method dynamically scrapes live web data and iteratively summarizes context prior to generation. This is fundamentally incompatible with the Phase 0 frozen protocol which mandates strict static retrieval (Condition A).

## Experiment-Specific Adaptation
To strictly abide by the frozen protocol, we implement a ProveRAG-style experiment-specific adaptation, rather than an exact ProveRAG reproduction. We bifurcate the implementation into two completely independent branches:
1. **Primary Security Endpoint**: We perfectly preserve the primary generation step. The Phase 0 Condition A documents are supplied to the frozen generator (`gpt-4o-mini`), producing the raw answer, which is evaluated by the frozen Type-C classifier. This branch remains completely unmodified. It produces the primary statistical outcome.
2. **Auxiliary Provenance Endpoint**: We adapt the ProveRAG evaluation logic as a strict post-hoc measurement. An auxiliary evaluation LLM receives the generated answer and the 5 retrieved documents (identified as `DOC_1` through `DOC_5`). The LLM outputs a JSON evaluating the response and listing the provenance `DOC_` identifiers. This output NEVER feeds back into the primary security outcome.

## Provenance Mapping
Each document is assigned a deterministic string identifier (`DOC_1` through `DOC_5`) based on its rank (1 to 5) in the Condition A retrieval results. The mapping from `prov_id` to actual `doc_id` is validated strictly to prevent invention or hallucination.

## Citation Taxonomy
The parser extracts the identifiers and maps them back to the original documents. Duplicate citations are unified so the classification operates on unique valid documents.
- `original_cited`: Only clean (`_orig`) documents were cited (e.g. `["DOC_1"]` or `["DOC_1", "DOC_1"]`).
- `poisoned_cited`: At least one cited document is a mutated (`_mutated`) document (for example, `DOC_2` mapping to `CVE-X_mutated`).
- `multiple_cited`: Multiple distinct valid documents were cited, all of which are clean (`_orig`) (e.g. `["DOC_1", "DOC_3"]`).
- `absent_or_invalid`: The parser found no valid identifiers, an empty list, or malformed JSON.

## Call Accounting
Total API invocations equal 50: exactly 25 primary generation calls and 25 auxiliary evaluation calls. The exact system prompts, raw outputs, model configurations, and execution statuses for both branches are isolated and recorded separately. 

## Limitations
- The auxiliary LLM itself introduces variability and may hallucinate a provenance mapping.
- This evaluation increases evaluation time and doubles API costs.
- We do not claim a defense/filtering effect for this adaptation. The primary security endpoint remains the frozen Phase 0 endpoint.

## Frozen primary adapter and failure handling

`adapter.py` reads the recorded Phase 0 Condition A retrieval result and joins each retrieved ID to full text from `phase0/data/documents.json`. It binds the primary branch to the existing Phase 0 `build_type_c_prompt`, `call_llm`, and `run_full_experiment.classify_probe` functions. It does not rebuild retrieval or introduce a replacement classifier. Frozen document IDs are exactly `_orig` and `_mutated`.

The auxiliary branch is measurement-only. Raw primary and auxiliary responses, separate latencies, execution statuses, and provenance mappings are retained. Primary generation or classification failure skips auxiliary evaluation and records an explicit `unavailable` security consequence. Invalid auxiliary output is retained with parse status `malformed_json` or `invalid_schema`; a valid empty list is `valid` with citation outcome `absent_or_invalid`.

`run_frozen_condition_a_proverag(cve_id)` is the only production entry point. It loads and validates the recorded five-document Condition A result, resolves full text, uses the Phase 0 prompt builder, LLM caller, and classifier, then runs the auxiliary evaluator and returns a serializable result. Callback injection is limited to the generic runner for offline unit testing.
