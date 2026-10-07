# Phase 2 Repository Audit

- Phase 0 implementation: `phase0/src/`, configuration `phase0/config/config.yaml`.
- Phase 0 frozen results/data: `phase0/data/`, `phase0/results/`; six data hashes are authoritative in `phase1/validation/phase0_frozen_hashes.json`.
- Phase 1 implementations: `phase1/robustrag/`, `phase1/nli/`, `phase1/proverag/`; TrustRAG design exists but is not a valid executed defense.
- Phase 1 narrative authority: `final_results_phase1/phase1_final_results.md`; individual records/statistics/audits are adjacent.
- Existing project setup: phase0 requirements and local scripts; no NVD snapshot/credential dependency or Phase 2 implementation existed before this work.
- Inputs consumed for primary generation: frozen Condition A/C Type C answers in `phase0/data/experiment_records.json`; metadata in `selected_cves.json`.
- Phase 1 generated answers: NLI and ProveRAG raw outputs. These remain secondary; ProveRAG includes its raw primary answer.
- Primary knowledge base: authentic official NVD JSON 2.0 annual feeds for 2022-2024, pinned in `phase2/config/kb_snapshot_manifest.json`; selected-CVE coverage audit is in `phase2/results/audits/nvd_selected_cve_coverage.json`.
- Implementation and results were written under `phase2/` only; frozen Phase 0/1 artifacts were not changed.
