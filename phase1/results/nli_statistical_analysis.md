# NLI Statistical Analysis

**Run ID**: `7de9a5ba-aa04-4651-ba45-702de40d6632`
**Raw SHA-256**: `b37e930f57a6bcea710f55c3e3b0b463164c0ca3fb1bbb55b33df9676b009d74`
**Integrity Audit**: PASS
**N**: 25
**Primary Comparison**: Phase 0 Condition A vs NLI-based contradiction-filtering adaptation
**Primary Endpoint**: Security-consequential incorrect decision on the frozen Type-C probe

## Raw Primary Analysis
- n = 25
- Phase 0 Condition A Incorrect: 0 (0.0%)
- NLI Incorrect: 20 (80.0%)
- Phase 0 Condition A Correct: 25
- NLI Correct: 5
- Risk Difference (NLI - Phase 0): 0.8000
- 95% Bootstrap CI: [0.6400, 0.9600]
- Exact McNemar p-value: 0.0000

### Paired Contingency Table
| | NLI Correct | NLI Incorrect |
|---|---|---|
| **Phase 0 Correct** | 5 | 20 |
| **Phase 0 Incorrect** | 0 | 0 |

- Discordant Pairs: 20

## Parametric-Confound-Excluded Analysis
- n = 22
- Phase 0 Condition A Incorrect: 0 (0.0%)
- NLI Incorrect: 17 (77.3%)
- Risk Difference: 0.7727
- 95% Bootstrap CI: [0.5909, 0.9545]
- Exact McNemar p-value: 0.0000

### Paired Contingency Table (Excluded)
| | NLI Correct | NLI Incorrect |
|---|---|---|
| **Phase 0 Correct** | 5 | 17 |
| **Phase 0 Incorrect** | 0 | 0 |

## Multiple Comparison Correction
- Raw McNemar p-value (Primary): 0.0000
- Holm-adjusted p-value: PENDING

## NLI Filtering Diagnostics
- Total NLI pairs evaluated: 500
- Pairs classified as Neutral: 249 (49.8%)
- Pairs classified as Contradiction: 218 (43.6%)
- Pairs classified as Entailment: 33 (6.6%)
- Complete ties (all 5 docs retained): 4 CVEs
- Average retained documents per CVE: 2.08
- Average filtered documents per CVE: 2.92

## Mechanism Comparison
Comparison with Phase 0 Condition C indicates whether residual failures arise primarily through filtering artifacts (e.g. failing to discard decoy), post-filtering generation (e.g. model misreads clean evidence), or classifier limitations. Where NLI fails despite correctly filtering the decoy, the failure mirrors Condition C (baseline model limitations).

## Qualitative Residual-FP Analysis
**CVE-2022-0219**
- Assigned Mechanism: inclusive_boundary_misreading
- Retained Docs: CVE-2022-4847_orig, CVE-2023-21927_orig
- Filtered Docs: CVE-2022-0219_orig, CVE-2022-4719_orig, CVE-2022-4800_orig
- Classification: affected (false_positive)

**CVE-2022-0666**
- Assigned Mechanism: inclusive_boundary_misreading
- Retained Docs: CVE-2024-3516_orig, CVE-2022-2931_orig
- Filtered Docs: CVE-2022-0666_orig, CVE-2023-6709_orig, CVE-2022-4800_orig
- Classification: affected (false_positive)

**CVE-2022-0696**
- Assigned Mechanism: inclusive_boundary_misreading
- Retained Docs: CVE-2024-21115_orig
- Filtered Docs: CVE-2022-0696_orig, CVE-2024-53984_orig, CVE-2024-3516_orig, CVE-2022-4847_orig
- Classification: affected (false_positive)

**CVE-2022-0776**
- Assigned Mechanism: inclusive_boundary_misreading
- Retained Docs: CVE-2024-53987_orig
- Filtered Docs: CVE-2022-0776_orig, CVE-2023-0787_orig, CVE-2022-0219_orig, CVE-2024-6772_orig
- Classification: affected (false_positive)

**CVE-2022-0804**
- Assigned Mechanism: inclusive_boundary_misreading
- Retained Docs: CVE-2024-6772_orig
- Filtered Docs: CVE-2022-0804_orig, CVE-2023-6509_orig, CVE-2024-3516_orig, CVE-2023-21448_orig
- Classification: affected (false_positive)

## LLM / Cost Accounting
- Total generation calls: 25
- Successful calls: 25
- Errors: 0
- Mean latency per call: 2.33 seconds

## Limitations
- NLI contradiction modeling relies heavily on semantic alignment. Some conflicts may not trigger contradiction probabilities if domain-specific boundaries are not naturally oppositional.
