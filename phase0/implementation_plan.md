# Phase 0 Repository Audit Plan

The objective is to perform a rigorous read-only audit of the Phase 0 repository to verify if it is safe to use as the frozen baseline for Phase 1.

## Open Questions & Critical Discrepancies

> [!WARNING]
> **CRITICAL DISCREPANCY:** The `README.md` file, which is described as the master experimental reference document, is completely missing from the repository. I ran a recursive search and could not find it. Because of this, I cannot compare the actual repository structure against the structure documented in the README.
> 
> How would you like me to proceed regarding this missing file? Should I continue the rest of the audit and report this as a discrepancy, or can you provide the `README.md`?

> [!NOTE]
> The repository is also not initialized as a git repository (`.git` is missing), so I cannot provide a git status or commit SHA.

## Proposed Changes

To fulfill the requirements without modifying any files, I will write a Python script in a scratch pad to programmatically audit the directory structure and all the JSON files in the `data/` directory.

### Audit Tasks
1. **Repository Inventory**: Iterate through the directory tree, collect file sizes and modification timestamps. Note missing `README.md` and missing `.git`.
2. **Identify Frozen Artifacts**: Verify existence, size, timestamp, and calculate SHA-256 hashes for `data/selected_cves.json`, `data/documents.json`, `data/embeddings.json`, `data/retrieval_results.json`, `data/experiment_records.json`, and `data/analysis_ready.csv`.
3. **Dataset Audit (`data/selected_cves.json`)**: Check for 25 unique CVEs, required fields, `boundary_type == "exclusive"`, and specific mutation logic (including checking `CVE-2023-0248`).
4. **Document Audit (`data/documents.json`)**: Check for 25 records and correct matching with `selected_cves.json`.
5. **Embedding Audit (`data/embeddings.json`)**: Check dimensions (384), L2 normalization, and similarity values.
6. **Retrieval Audit (`data/retrieval_results.json`)**: Calculate Recall@1, Recall@3, Recall@5 for Condition A, and co-retrieval rate, mean/min/max similarity gaps for Condition C.
7. **Experiment Record Audit (`data/experiment_records.json`)**: Check for exactly 175 records, the expected distribution of Conditions and Types, and unique `run_id`s.

The script will dump its findings into a comprehensive `phase0_audit_report.md` artifact.

## Verification Plan

### Automated Tests
- `python C:\Users\ravia\.gemini\antigravity-ide\brain\<conversation-id>\scratch\audit.py` to run the read-only checks and generate the report artifact.

### Manual Verification
- Review the generated `phase0_audit_report.md` to establish if Phase 0 is safe to use as a frozen baseline.
