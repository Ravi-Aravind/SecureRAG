# Phase 1 Presentation Summary

## SLIDE 1 — Research Question

- Test preservation/degradation under a frozen poisoning protocol.
- Source: phase1_final_results.md
- Suggested figure: question diagram
- Speaker note: The baseline already has zero false positives.

## SLIDE 2 — Threat Model / Setup

- Single-token version-boundary mutation in retrieved documents.
- Source: phase0/data/documents.json
- Suggested figure: original vs mutated document
- Speaker note: Keep mutation scope precise.

## SLIDE 3 — Frozen Baseline

- Condition A: 0/25 incorrect, 0.0%.
- Source: phase0/data/analysis_ready.csv
- Suggested figure: baseline bar
- Speaker note: No false positives existed to reduce.

## SLIDE 4 — Experimental Design

- 25 CVEs; frozen retrieval, prompts, model, classifier.
- Source: phase0/data/selected_cves.json; phase1 raw JSON
- Suggested figure: pipeline
- Speaker note: All units are paired CVEs.

## SLIDE 5 — Defense Architectures

- RobustRAG and NLI are primary adaptations; ProveRAG auxiliary.
- Source: phase1_defense_status_matrix.md
- Suggested figure: architecture map
- Speaker note: TrustRAG is excluded.

## SLIDE 6 — Primary Results

- RobustRAG 25/25; NLI 20/25 incorrect.
- Source: phase1_final_table.csv
- Suggested figure: comparison table
- Speaker note: Observed endpoint only.

## SLIDE 7 — Statistical Results

- RobustRAG and NLI Holm family; NLI CI [64%,96%].
- Source: phase1_final_statistics.json
- Suggested figure: paired table
- Speaker note: No ProveRAG Holm entry.

## SLIDE 8 — Mechanisms

- RobustRAG degradation is tied to classifier/refusal interaction; NLI has boundary sensitivity.
- Source: phase1_mechanism_table.md
- Suggested figure: mechanism counts
- Speaker note: Do not call all cases genuine poisoning.

## SLIDE 9 — RobustRAG Finding

- 25/25 incorrect endpoint decisions in this categorical adaptation.
- Source: robustrag_raw_results_*.json
- Suggested figure: endpoint flow
- Speaker note: Not a certified reproduction.

## SLIDE 10 — NLI Finding

- 20/25 incorrect; five non-false-positive CVEs.
- Source: nli_raw_results_*.json
- Suggested figure: NLI pair schematic
- Speaker note: Model/protocol-specific.

## SLIDE 11 — ProveRAG Auxiliary

- 25 original-cited; separate from primary comparison.
- Source: phase1_proverag_citation_table.md
- Suggested figure: provenance table
- Speaker note: Citation does not define security correctness.

## SLIDE 12 — TrustRAG

- Not reproducible under frozen protocol; no statistics.
- Source: phase1_defense_status_matrix.md
- Suggested figure: exclusion callout
- Speaker note: Do not fabricate a result.

## SLIDE 13 — Limitations

- Single dataset, frozen model, adaptations, classifier sensitivity.
- Source: phase1_final_results.md
- Suggested figure: limitations list
- Speaker note: Avoid generalization.

## SLIDE 14 — Final Interpretation

- Results expose endpoint degradation and interaction effects.
- Source: phase1_claims_audit.md
- Suggested figure: interpretation summary
- Speaker note: Use precise causal language.

## SLIDE 15 — Does / Does Not Establish

- Establishes observed adaptation outcomes; not general defense capability or reduction.
- Source: phase1_final_results.md
- Suggested figure: scope boundary
- Speaker note: This is the central conclusion.
