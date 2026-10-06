# Qualitative Cases

Cases are selected deterministically from the frozen CVE order and preserve concise excerpts from raw artifacts.

## RobustRAG classifier/refusal interaction

- CVE: CVE-2022-0219
- Source: `phase1/results/robustrag_raw_results_a30146b9-95b2-487b-badc-7306660709a4.json` and `phase1/results/robustrag_mechanism_analysis.json`
- Observation: isolated irrelevant-document responses contain refusal language that interacts with the frozen classifier; the recorded mechanism is `classifier_error`.
- Limitation: this does not establish genuine poisoning or reproduce certified RobustRAG.

## NLI numeric-boundary sensitivity

- CVEs: the five non-false-positive NLI cases are listed in `phase1_final_individual_results.md`; the remaining 20 are false-positive endpoint outcomes.
- Source: `phase1/results/nli_raw_results_7de9a5ba-aa04-4651-ba45-702de40d6632.json` and `phase1/results/nli_mechanism_analysis.json`
- Observation: the adaptation is sensitive to the experiment's single-token version-boundary changes.
- Limitation: this is not evidence of general NLI defense capability.

## ProveRAG original provenance

- Result: all 25 primary decisions are `correct_not_affected`; all 25 auxiliary outcomes are `original_cited`.
- Source: `phase1/results/proverag_raw_results_20260917T163237Z_35f33821.json`
- Limitation: ProveRAG is post-generation provenance analysis, not a retrieval-layer defense.
