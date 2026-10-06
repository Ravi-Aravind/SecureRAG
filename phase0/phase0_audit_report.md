# Phase 0 Repository Audit Report

## 1. REPOSITORY INVENTORY

### Directory Tree, File Sizes, and Modification Timestamps
- **phase0/**
    - `audit_versions.py` (7915 bytes, modified: 2026-09-16T19:25:42.847008)
    - `inspect_cve.py` (1366 bytes, modified: 2026-09-16T19:25:42.885113)
    - `requirements.txt` (192 bytes, modified: 2026-09-16T19:25:42.917683)
    - `run_candidate_extraction.py` (2514 bytes, modified: 2026-09-16T19:25:42.957297)
    - `run_feasibility_scan.py` (10683 bytes, modified: 2026-09-16T19:25:42.994358)
    - `test_mutator.py` (5374 bytes, modified: 2026-09-16T19:25:43.031924)
    - `validate_step1.py` (995 bytes, modified: 2026-09-16T19:25:43.069188)
    - `validate_step2.py` (953 bytes, modified: 2026-09-16T19:25:43.133400)
    - **config/**
        - `config.yaml` (881 bytes, modified: 2026-09-16T19:25:43.181993)
    - **data/**
        - `analysis_ready.csv` (5023 bytes, modified: 2026-09-16T19:25:43.246554)
        - `candidate_cves.json` (10614822 bytes, modified: 2026-09-16T19:25:43.388243)
        - `documents.json` (39090 bytes, modified: 2026-09-16T19:25:43.451621)
        - `embeddings.json` (559793 bytes, modified: 2026-09-16T19:25:43.490621)
        - `experiment_records.json` (171313 bytes, modified: 2026-09-16T19:25:43.522354)
        - `feasibility_scan.json` (28286 bytes, modified: 2026-09-16T19:25:43.553908)
        - `pilot_analysis.json` (26285 bytes, modified: 2026-09-16T19:25:43.587242)
        - `retrieval_results.json` (114781 bytes, modified: 2026-09-16T19:25:43.621357)
        - `selected_cves.json` (22202 bytes, modified: 2026-09-16T19:25:43.653235)
    - **notebooks/**
    - **results/**
        - `phase0_report.md` (18976 bytes, modified: 2026-09-16T19:25:43.770657)
        - `phase0_results.csv` (2960 bytes, modified: 2026-09-16T19:25:43.798755)
        - `phase0_results.json` (4399 bytes, modified: 2026-09-16T19:25:43.823537)
        - `qualitative_examples.json` (7074 bytes, modified: 2026-09-16T19:25:43.912802)
    - **src/**
        - `analysis.py` (41977 bytes, modified: 2026-09-16T19:25:43.975364)
        - `analysis_prep.py` (19227 bytes, modified: 2026-09-16T19:25:44.015975)
        - `candidate_extractor.py` (3990 bytes, modified: 2026-09-16T19:25:44.058828)
        - `cve_loader.py` (5747 bytes, modified: 2026-09-16T19:25:44.098925)
        - `cve_selector.py` (4046 bytes, modified: 2026-09-16T19:25:44.139508)
        - `document_builder.py` (5623 bytes, modified: 2026-09-16T19:25:44.179785)
        - `embedder.py` (5189 bytes, modified: 2026-09-16T19:25:44.253516)
        - `llm_caller.py` (7764 bytes, modified: 2026-09-16T19:25:44.293474)
        - `mutator.py` (11756 bytes, modified: 2026-09-16T19:25:44.336107)
        - `pilot_analysis.py` (20028 bytes, modified: 2026-09-16T19:25:44.378870)
        - `qualitative_analysis.py` (12936 bytes, modified: 2026-09-16T19:25:44.421073)
        - `retriever.py` (10064 bytes, modified: 2026-09-16T19:25:44.464646)
        - `run_condition_a.py` (5005 bytes, modified: 2026-09-16T19:25:44.506747)
        - `run_condition_b.py` (6472 bytes, modified: 2026-09-16T19:25:44.547206)
        - `run_condition_c.py` (7277 bytes, modified: 2026-09-16T19:25:44.589854)
        - `run_full_experiment.py` (17387 bytes, modified: 2026-09-16T19:25:44.632183)
        - `run_probe.py` (9936 bytes, modified: 2026-09-16T19:25:44.673275)
        - **__pycache__/**
            - `analysis.cpython-311.pyc` (52029 bytes, modified: 2026-09-16T19:25:44.767432)
            - `candidate_extractor.cpython-311.pyc` (3967 bytes, modified: 2026-09-16T19:25:44.812027)
            - `cve_loader.cpython-311.pyc` (8116 bytes, modified: 2026-09-16T19:25:44.847817)
            - `llm_caller.cpython-311.pyc` (10842 bytes, modified: 2026-09-16T19:25:44.886899)
            - `mutator.cpython-311.pyc` (14369 bytes, modified: 2026-09-16T19:25:44.927519)
            - `pilot_analysis.cpython-311.pyc` (23309 bytes, modified: 2026-09-16T19:25:44.964609)
            - `run_condition_a.cpython-311.pyc` (7399 bytes, modified: 2026-09-16T19:25:45.000683)
            - `run_condition_b.cpython-311.pyc` (9025 bytes, modified: 2026-09-16T19:25:45.064977)
            - `run_full_experiment.cpython-311.pyc` (20559 bytes, modified: 2026-09-16T19:25:45.102678)
            - `run_probe.cpython-311.pyc` (13354 bytes, modified: 2026-09-16T19:25:45.139248)

### Git Status
The directory is **NOT** a Git repository (`.git` directory is missing). Git status and commit SHA cannot be retrieved.

### Discrepancies
- **CRITICAL**: `README.md` is completely missing from the repository.
- Repository is not initialized with git.

## 2. IDENTIFY THE FROZEN PHASE 0 ARTIFACTS

- `data/selected_cves.json`: exists, 22202 bytes, mtime: 2026-09-16T19:25:43.653235, SHA256: cef5d48481ee4df28884a411dc778f555c9538466aedab72adea9df7ac8a472f
- `data/documents.json`: exists, 39090 bytes, mtime: 2026-09-16T19:25:43.451621, SHA256: 3a25bfa8f755374b9ba46a0dccfdf25de4984b8480d6ea983abefbb570c532ed
- `data/embeddings.json`: exists, 559793 bytes, mtime: 2026-09-16T19:25:43.490621, SHA256: 61d89fa41cf980125bc43bb67f42b75742b08439fd2eed8d33be617cf0f8dda4
- `data/retrieval_results.json`: exists, 114781 bytes, mtime: 2026-09-16T19:25:43.621357, SHA256: 1cf6d170d6f343ecd37b1e719e1736db339f9d2b5c6dfbd81226c3d41ea5b27d
- `data/experiment_records.json`: exists, 171313 bytes, mtime: 2026-09-16T19:25:43.522354, SHA256: 8939145a99e8a001823ec637951d6753237de27bf01e4f74e9a79ddfdc7acfc8
- `data/analysis_ready.csv`: exists, 5023 bytes, mtime: 2026-09-16T19:25:43.246554, SHA256: a9f4fa270988fb28dec272444527e4ab0624685a07cfdf7924f5113aa14934bc

## 3. DATASET AUDIT (`data/selected_cves.json`)

- Records count: 25 (Expected 25)
- Duplicate CVE IDs: False
- Records missing fields: []
- Records where boundary_type is not 'exclusive': []
- Records without exactly one mutation: []
- Records where probe_version != original_boundary: []
- Explicit inspection of CVE-2023-0248:
  - original_boundary: 1.07.02
  - mutated_boundary: 1.07.3
  - Confirmed known Phase 0 sample heterogeneity (1.07.02 -> 1.07.3)

## 4. DOCUMENT AUDIT (`data/documents.json`)

- Records count: 25 (Expected 25)
- CVEs missing valid docs: []

## 5. EMBEDDING AUDIT (`data/embeddings.json`)

- Records count: 25 (Expected 25)
- Records with invalid dimensions (!= 384): []
- Records not L2-normalized: []
- Max difference between calculated and stored similarity: 8.078422308877009e-08

## 6. RETRIEVAL AUDIT (`data/retrieval_results.json`)

- Records count: 75 (Expected 75)
- Source code confirms IndexFlatIP: Yes (verified via src/retriever.py usage of FAISS IndexFlatIP)
- Source code confirms L2-normalized embeddings: Yes (verified via src/embedder.py normalize_embeddings=True)
- Condition C contains the expected original + mutated document setup: Yes
- Condition A Recall@1: 25/25 = 100.00%
- Condition A Recall@3: 25/25 = 100.00%
- Condition A Recall@5: 25/25 = 100.00%
- Condition C Co-retrieval rate: 25/25 = 100.00%
- Mean similarity gap: 5.8381e-04
- Min similarity gap: 5.6922e-05
- Max similarity gap: 3.1412e-03

## 7. EXPERIMENT RECORD AUDIT (`data/experiment_records.json`)

- Records count: 175 (Expected 175)
- Distribution:
  - Condition A_None: 50
  - Condition B_None: 50
  - Condition C_None: 50
  - Parametric_None: 25
- Duplicate run_id values: False