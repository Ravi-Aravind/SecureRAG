# NLI Live Preflight Report

**Run ID**: `3b9aa771-b6cb-4f8a-ac41-ba583d61ee47`
**Selected CVE**: `CVE-2022-29225` (First in frozen Phase 0)

## Metadata
* **Model**: `cross-encoder/nli-deberta-v3-large`
* **Device**: `cpu`
* **Transformers**: `5.17.0`
* **PyTorch**: `2.14.0+cpu`
* **Python**: `3.12.0`
* **Load Time**: 18.58 seconds
* **Pass 1 Inference Time**: 7.77 seconds
* **Pass 2 Inference Time**: 7.53 seconds

## Deterministic Repeat Comparison
* **Max Probability Difference**: 0.0000000000
* **Argmax Label Mismatches**: 0
* **Retained Set Identical**: True

## Structural Checks
* Exactly 20 directed pairs: PASS
* No self-pairs: PASS
* Probability vectors sum to ~1: PASS
* Argmax label matches probabilities: PASS
* Retained set non-empty: PASS
* Determinism Check (Pass 1 vs Pass 2 identical decisions): PASS

## Contradiction Scores & Filtering
* **C_min**: 0
* **Filtering Rule Applied**: Retained minimum contradiction subset (C_min=0)

| Doc ID | Rank | Contradiction Score | Conflicting Docs |
|---|---|---|---|
| CVE-2022-29225_orig | 1 | 0 |  |
| CVE-2022-23913_orig | 2 | 2 | CVE-2022-4800_orig, CVE-2024-53984_orig |
| CVE-2022-4800_orig | 3 | 3 | CVE-2022-23913_orig, CVE-2023-21927_orig, CVE-2024-53984_orig |
| CVE-2023-21927_orig | 4 | 1 | CVE-2022-4800_orig |
| CVE-2024-53984_orig | 5 | 2 | CVE-2022-23913_orig, CVE-2022-4800_orig |

* **Retained Documents**: CVE-2022-29225_orig
* **Filtered Documents**: CVE-2022-23913_orig, CVE-2022-4800_orig, CVE-2023-21927_orig, CVE-2024-53984_orig

## Pairwise NLI Matrix (Pass 1)
| Source | Target | Contradiction | Entailment | Neutral | Argmax |
|---|---|---|---|---|---|
| CVE-2022-29225_orig | CVE-2022-23913_orig | 0.0014 | 0.9583 | 0.0403 | **Entailment** |
| CVE-2022-29225_orig | CVE-2022-4800_orig | 0.0006 | 0.0004 | 0.9990 | **Neutral** |
| CVE-2022-29225_orig | CVE-2023-21927_orig | 0.0009 | 0.0021 | 0.9970 | **Neutral** |
| CVE-2022-29225_orig | CVE-2024-53984_orig | 0.0006 | 0.0031 | 0.9963 | **Neutral** |
| CVE-2022-23913_orig | CVE-2022-29225_orig | 0.0360 | 0.0305 | 0.9335 | **Neutral** |
| CVE-2022-23913_orig | CVE-2022-4800_orig | 0.9994 | 0.0001 | 0.0005 | **Contradiction** |
| CVE-2022-23913_orig | CVE-2023-21927_orig | 0.0602 | 0.0092 | 0.9306 | **Neutral** |
| CVE-2022-23913_orig | CVE-2024-53984_orig | 0.9723 | 0.0024 | 0.0252 | **Contradiction** |
| CVE-2022-4800_orig | CVE-2022-29225_orig | 0.0019 | 0.0023 | 0.9958 | **Neutral** |
| CVE-2022-4800_orig | CVE-2022-23913_orig | 0.9353 | 0.0247 | 0.0399 | **Contradiction** |
| CVE-2022-4800_orig | CVE-2023-21927_orig | 0.8626 | 0.0064 | 0.1309 | **Contradiction** |
| CVE-2022-4800_orig | CVE-2024-53984_orig | 0.9898 | 0.0009 | 0.0093 | **Contradiction** |
| CVE-2023-21927_orig | CVE-2022-29225_orig | 0.0011 | 0.0067 | 0.9922 | **Neutral** |
| CVE-2023-21927_orig | CVE-2022-23913_orig | 0.0546 | 0.0431 | 0.9022 | **Neutral** |
| CVE-2023-21927_orig | CVE-2022-4800_orig | 0.0043 | 0.0080 | 0.9877 | **Neutral** |
| CVE-2023-21927_orig | CVE-2024-53984_orig | 0.0032 | 0.0067 | 0.9901 | **Neutral** |
| CVE-2024-53984_orig | CVE-2022-29225_orig | 0.0003 | 0.0021 | 0.9976 | **Neutral** |
| CVE-2024-53984_orig | CVE-2022-23913_orig | 0.0001 | 0.9954 | 0.0045 | **Entailment** |
| CVE-2024-53984_orig | CVE-2022-4800_orig | 0.0012 | 0.0038 | 0.9949 | **Neutral** |
| CVE-2024-53984_orig | CVE-2023-21927_orig | 0.0032 | 0.0124 | 0.9844 | **Neutral** |

## Limitations
* No LLM was called.
* Do not conclude NLI "works" or "fails" from this single CVE. The purpose is strictly structural validation of the implementation and deterministic model execution.
