# Phase 1 Final Results

## Executive Summary

Under the frozen single-token boundary-poisoning protocol, the Phase 0 Condition A baseline produced 0/25 false-positive security decisions. Phase 1 therefore does not demonstrate reduction of false positives; it exposes preservation or degradation of the frozen retrieval-generation-classification endpoint.

## Primary Results

The primary retrieval-defense comparison contains only the RobustRAG and NLI adaptations. RobustRAG produced 25/25 incorrect endpoint decisions and NLI produced 20/25. These are adaptation-specific observations, not faithful reproductions of published certified methods.

## Statistical and Confound-Excluded Results

The primary Holm family contains RobustRAG and NLI only. The NLI paired bootstrap CI is [64%, 96%]. The pre-specified exclusions are CVE-2022-27616, CVE-2022-42466, and CVE-2023-0787; the n=22 results are in `phase1_final_statistics.json`.

## Mechanisms and Qualitative Cases

RobustRAG's endpoint degradation is interpreted primarily through the documented classifier/refusal interaction, not as 25 genuine poisoning events. NLI's recorded mechanism is preserved without generalization. See `phase1_qualitative_cases.md`.

## Auxiliary ProveRAG

ProveRAG is reported separately as an auxiliary post-generation provenance branch. It produced 25/25 `correct_not_affected` primary decisions and 25/25 `original_cited` outcomes; provenance did not affect the primary endpoint.

## TrustRAG and Limitations

TrustRAG was not reproducible under the frozen prompt/protocol and receives no statistics. The study uses one frozen dataset, one model/protocol, and experiment-specific adaptations; it does not establish general defense capability, formal certification, or reduction in false-positive rate.
