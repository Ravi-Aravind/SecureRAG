# ClaimGuard Phase 2 Specification v1.0

## Question and primary estimand

Can deterministic post-generation claim verification against an independent, pinned NVD snapshot detect incorrect version-status claims in the frozen corpus? The primary endpoint is the number of incorrect generated claims classified `CONTRADICTED` divided by incorrect claims that resolve sufficiently to be verifiable. `UNVERIFIABLE` cases are excluded from that denominator and reported separately.

## Matrix and inputs

Primary paired matrix: A, A+CG, C, C+CG. A+CG and C+CG consume exactly the same frozen outputs as their no-CG partners; ClaimGuard is a downstream measurement and does not regenerate or change answers. The primary comparison is C vs C+CG. The clean control is A vs A+CG. Phase 1 records are secondary only; ProveRAG's available answer output is retained as an auxiliary source, not folded into the primary matrix. RobustRAG, NLI, ProveRAG, and TrustRAG are not represented as a new unified primary condition.

Phase 0 inputs are pinned by `phase1/validation/phase0_frozen_hashes.json`; execution checks these hashes before consuming data. The Phase 1 final package under `final_results_phase1/` governs interpretation. Historical artifacts are left untouched.

## Claim extraction

`claims/extraction.py` uses fixed regular-expression grammars. It uses no model, embedding, or similarity. Probe version (`claimed_version`) and natural-language range (`stated_boundary`) are distinct. Supported boundary phrases include prior to/before/less than (<), through/up to/before or equal (<=), after (>), and from/after or equal (>=). Unsupported syntax, multiple boundaries, missing status/CVE, and incomplete text retain explicit non-extracted/ambiguous states.

## CPE and applicability

CPE matching compares exact CPE 2.3 vendor and product fields after casefolding and whitespace collapse. Wildcard CPE identity is not resolved. No alias database or fuzzy matching is used. The resolver evaluates CPE match leaves and nested Boolean nodes, retaining a trace per configuration/node; top-level configuration branches are ORed. A standalone top-level branch with no exact target product CPE is irrelevant to that claim and is skipped. Unknown leaves within a target-bearing Boolean branch retain tri-state logic, so an unknown required OS component in AND remains UNVERIFIABLE.

**Configuration-level AND limitation:** the current resolver combines target-bearing top-level nodes/configuration entries as OR alternatives. It does not interpret a conjunction encoded at the configuration-wrapper or configuration-collection level. AND/OR operators inside each node subtree are evaluated, but if separate configuration entries must jointly hold, the current OR reduction can produce an overly conclusive result. This limitation is documented for interpretation; it does not change the pinned experiment results.

## Version semantics

`numeric-dot-v1` accepts decimal dot-separated numeric components, compares integer components with zero padding, and rejects suffixes, epochs, ranges embedded in versions, and nonnumeric components. NVD start/end including/excluding properties map directly to interval inclusivity. Unsupported syntax yields UNVERIFIABLE.

## Verdicts and provenance

Malformed or ambiguous claims are always UNVERIFIABLE. A resolved authoritative affected state equal to the prediction is SUPPORTED; an established opposite state is CONTRADICTED. Each output stores the KB, snapshot/manifest reference, CVE, CPE criteria, matched CPE, applicability trace, resolver and implementation versions, verdict, and reason.

## Snapshot and experiment status

The experiment uses NVD's official annual 2022, 2023, and 2024 JSON 2.0 vulnerability feeds. Their original gzip bytes and official `.meta` files are stored under `phase2/data/nvd/`. `config/kb_snapshot_manifest.json` records compressed hashes, NVD uncompressed hashes/sizes, record counts, selected-CVE coverage, snapshot root hash, and immutable snapshot ID. Runtime validation checks those hashes and metadata before use. All 25 selected CVEs exist in the feeds; 24 have applicability configurations. CVE-2024-53984 has no configurations and remains UNVERIFIABLE. The pinned primary experiment has been run and the final results are in `results/derived/phase2_final_report.md`.

## Statistics

For paired binary error outcomes, report paired risk difference, 10,000 paired bootstrap resamples (seed 42), and exact two-sided McNemar test. The pairing unit is CVE. No inferential test is applied to coverage or verification metrics with unsupported denominators. The C primary and A clean-control comparisons form a two-test family; Holm correction is applied to both reported p-values.

## Validation and limitations

Validation covers the golden Condition C extraction, phrasing and malformed states, strict CPE identity, version operators/interval endpoints, applicability branches, and verdict safety. Fixture tests validate software behavior only and are not NVD evidence. Primary conclusions remain unavailable until an authentic snapshot is pinned and the full matrix is executed.
