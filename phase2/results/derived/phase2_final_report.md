# ClaimGuard Phase 2 Final Report

**Phase 2 primary experiment completed with NVD applicability data for 24/25 selected CVEs.** Under strict claim extraction and CPE resolution, 2/12 incorrect Condition C claims were verifiable; NVD contradicted both. The other 10 incorrect claims were UNVERIFIABLE and excluded from the primary denominator. The snapshot contained 25/25 selected CVE records.

## Executive summary

The primary detection endpoint was **2/2 = 100%** for verifiable incorrect C claims. This rate must be read with its coverage: only 2 of 12 incorrect claims were verifiable, 10 of 12 were UNVERIFIABLE, and 19/25 C claims overall were UNVERIFIABLE. One of 13 non-error claims by the frozen Phase 0 classification was contradicted by NVD. ClaimGuard does not rewrite the answer; detection is measured as whether a frozen incorrect claim receives `CONTRADICTED`.

**"Correct" and "incorrect" refer to the frozen Phase 0 `answer_class`, not independent NVD truth.** CVE-2024-3516 is the observed disagreement: its frozen class is `conflict_acknowledged`, while strict NVD verification of the generated claim returns CONTRADICTED. The Phase 0 label was preserved.

## Research question and experimental matrix

The question was whether deterministic post-generation claim verification against an independent pinned NVD knowledge base detects incorrect version/status claims. The matrix consumed the same frozen Type-C answers for paired rows:

| Condition | Frozen answers | ClaimGuard | Result summary |
|---|---:|---|---|
| A | 25 | No | 25 correct, 0 incorrect |
| A+CG | same 25 A answers | Yes | 6 SUPPORTED, 19 UNVERIFIABLE, 0 CONTRADICTED |
| C | 25 | No | 13 correct/non-error, 12 incorrect |
| C+CG | same 25 C answers | Yes | 3 SUPPORTED correct, 2 CONTRADICTED incorrect, 1 CONTRADICTED Phase 0 non-error, 19 UNVERIFIABLE |

The primary comparison is C vs C+CG. A vs A+CG is the clean control. No generation, Phase 0 retrieval, or Phase 1 run was repeated.

## Frozen inputs and integrity

Inputs are Phase 0 Condition A/C Type-C records in `phase0/data/experiment_records.json`, product/vendor metadata in `phase0/data/selected_cves.json`, and the existing Phase 0 hash manifest. Phase 1's final narrative package remains authoritative. All six Phase 0 frozen data hashes passed before and after the experiment. No Phase 0 or Phase 1 file was modified.

## Claim extraction

Extraction uses deterministic regular-expression grammars only. No LLM, embedding, or semantic similarity is used. Queried `claimed_version` is distinct from `stated_boundary`. Repeated identical boundaries collapse to one assertion; conflicting boundaries become AMBIGUOUS. Missing or malformed fields abstain.

## CPE resolution and version semantics

CPE matching requires exact CPE 2.3 vendor and product fields after case and whitespace normalization. Wildcards and aliases do not resolve. Standalone top-level configurations with no exact target product CPE are ignored for a product claim. Other-product/platform leaves inside a target-bearing Boolean branch remain unknown when the claim lacks that platform context; tri-state AND/OR evaluation abstains when the context could change the answer. This avoids converting missing environment facts to a contradiction.

Numeric dot-separated versions are compared component-wise with zero padding. NVD `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, and `versionEndExcluding` map to explicit interval endpoints. Unsupported versions abstain. Every branch trace records tested version, CPE criteria, boundary fields, and branch evaluation.

## ClaimGuard verdicts and provenance

Malformed/ambiguous claims, unresolved CPEs, missing applicability, and ambiguous Boolean applicability become UNVERIFIABLE. Resolved agreement becomes SUPPORTED; resolved disagreement becomes CONTRADICTED. Per-CVE CG records preserve source record ID, generated answer, frozen answer class, claim/extraction status, CPE resolution, matched CPE, applicability trace, version comparisons, verdict/reason, snapshot ID, NVD record ID, and implementation version.

## NVD snapshot provenance

The snapshot was acquired from NVD's official [2.0 vulnerability data feeds](https://nvd.nist.gov/vuln/data-feeds), using the annual 2022, 2023, and 2024 JSON gzip feeds and corresponding official `.meta` files. NVD documents that annual 2.0 feeds are updated daily and that `.meta` files provide feed size and SHA-256 information.

- Snapshot ID: `nvd-json20-2022-2024-sha256-2eb72481314d3d9c79797689967691d1f3c84d83e9350ce8feade0e057a7c45f`
- Snapshot root SHA-256: `2eb72481314d3d9c79797689967691d1f3c84d83e9350ce8feade0e057a7c45f` (SHA-256 over ordered compressed-feed SHA-256 digests)
- Acquisition timestamp: `2026-10-07T14:44:29.665057+00:00`
- Schema: NVD CVE JSON 2.0
- Record count: 98,261 (2022: 27,556; 2023: 31,449; 2024: 39,256)
- Selected CVEs: 25/25 records found; 24/25 with configurations/applicability
- Compressed feed SHA-256:
  - 2022: `032cf67700da4f0de1004fe2b944f9d2a1f2f6db81a05591f509b9d80958d8d0`
  - 2023: `4be8864b85fda7c0a4de528899028dd285dee09c0968565d5d81cac469fd2c6a`
  - 2024: `2f58760b50703544914d6fb62d4d809b9176a79b8c82f28aee16704eb0942187`

NVD `.meta` uncompressed hashes and sizes are retained in the manifest and were verified against decompressed feeds. No API query or third-party mirror was used.

## Golden CVE-2022-29225

The frozen C answer extracts as CVE-2022-29225, vendor `envoyproxy`, product `envoy`, claimed version `1.22.1`, predicted status `affected`, stated boundary `< 1.22.2`. The NVD record matches `cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*` and specifies `versionEndExcluding: 1.22.1`. Thus 1.22.1 is outside the authoritative affected interval. ClaimGuard returned **CONTRADICTED**, reason `AUTHORITATIVE_CONTRADICTION`. The full trace is in `results/audits/golden_cve_verification.json`.

## Validation results

- 21 automated tests pass, including actual pinned NVD verification for the golden case and both audited Chrome cases.
- Frozen input validator: PASS (six hashes).
- NVD snapshot validator: PASS (feed hashes, NVD metadata, record counts, and snapshot root hash).
- Selected-CVE audit: 25/25 found; 24 with applicability; CVE-2024-53984 has no NVD configurations and remains UNVERIFIABLE.
- Full matrix: 25 paired CVEs in each of A, A+CG, C, and C+CG.

## Primary and secondary results

For C+CG, 12 generated claims were incorrect by the frozen Phase 0 Type-C class. Two were verifiable and contradicted; 10 were UNVERIFIABLE. Therefore the primary endpoint is **2 contradicted / 2 verifiable incorrect = 100%**. Contradicted recall over all 12 frozen-label incorrect claims is **2/12 = 16.7%**. These measure different denominators. The terms "correct" and "incorrect" in these calculations mean the frozen Phase 0 `answer_class`, not independent NVD truth.

Other C+CG summaries:

- Total: 25; correct/non-error: 13; incorrect: 12.
- Verifiable incorrect: 2; contradicted incorrect: 2; supported incorrect: 0.
- Supported correct: 3; contradicted frozen-label non-error: 1.
- UNVERIFIABLE: 19/25 = 76%; ClaimGuard claim-verifiability: 6/25 = 24%.
- NVD record coverage: 25/25 = 100%; NVD applicability coverage: 24/25 = 96%.
- Supported precision: 3/3 = 100%; contradiction rate among frozen-label non-error C claims: 1/13 = 7.7%.

A+CG had 25 correct claims, 6 SUPPORTED and 19 UNVERIFIABLE, with no contradictions. A had 25 correct and zero incorrect generated claims; its primary detection rate is not estimable because there are no incorrect claims.

UNVERIFIABLE reasons in C+CG (19 total): 8 ambiguous multiple-boundary claims (`CVE-2022-0666`, `CVE-2023-21448`, `CVE-2022-25169`, `CVE-2022-4719`, `CVE-2023-0248`, `CVE-2022-0696`, `CVE-2024-21115`, `CVE-2023-21927`); 10 strict CPE unresolved (`CVE-2023-0787`, `CVE-2022-4847`, `CVE-2022-27616`, `CVE-2024-53987`, `CVE-2022-23913`, `CVE-2023-6709`, `CVE-2022-0776`, `CVE-2022-42466`, `CVE-2022-4800`, `CVE-2022-0219`); and missing applicability for `CVE-2024-53984`.

The two newly resolved cases are CVE-2023-6509 (frozen class `affected`, so incorrect by Phase 0 classification) and CVE-2024-3516 (frozen class `conflict_acknowledged`, retained as a non-error by that classification). NVD contradicted both generated Chrome claims. No frozen class was changed.

## Mechanism-specific results

Among 12 C errors, Phase 0 labels recorded 8 inclusive-boundary misreadings, 2 genuine mutated-boundary poisoning cases, and 2 parametric overrides. ClaimGuard contradicted both poisoning cases (the only two verifiable incorrect claims). All 8 inclusive-boundary and 2 parametric-override cases were UNVERIFIABLE under this strict pipeline. Mechanism labels are retained from frozen Phase 0 records and are descriptive, not independently reassessed. CVE-2024-3516's NVD contradiction is outside the frozen incorrect set and does not alter mechanism or correctness labels.

## Paired statistics

Binary paired CVE outcome is baseline incorrect claim vs incorrect claim not flagged CONTRADICTED. This is a detection proxy; ClaimGuard does not rewrite the answer. Percentile paired bootstrap uses 10,000 resamples, seed 42. Exact two-sided McNemar is reported. Holm correction covers the two reported comparisons (C primary and A clean control).

- C vs C+CG: risk difference **-0.08**; bootstrap 95% CI **[-0.20, 0.00]**; discordant pairs 2 vs 0; exact McNemar **p=0.5**, Holm adjusted **p=1.0**.
- A vs A+CG: risk difference **0.00**; bootstrap 95% CI **[0.00, 0.00]**; discordant pairs 0 vs 0; exact McNemar **p=1.0**, Holm adjusted **p=1.0**.

The small sample and two detected errors do not support a claim of statistically significant protection. No inferential test is applied to coverage/precision metrics.

## Limitations and reproducibility

Strict matching and deterministic extraction produce low claim-verifiability despite full NVD record coverage. The experiment supports a 2/2 conditional detection estimate, not a broad claim that ClaimGuard catches all errors. NVD lacks applicability for one selected record, and some NVD CPE applicability includes context absent from generated answers. Version support remains numeric dot-separated components only.

**Configuration-level AND limitation:** the resolver combines target-bearing top-level nodes/configuration entries with OR semantics and does not implement an AND relation encoded at the configuration-wrapper or configuration-collection level. Boolean operators within a node subtree are evaluated, including conservative abstention for an unknown required OS leaf in an AND branch. Where separate configuration entries must jointly hold, treating them as OR alternatives can yield an overly conclusive verdict. This is a documented resolver limitation; no resolver behavior or experiment result was changed for this documentation update.

From repository root, reproduce with:

```powershell
python phase2/validation/audit_nvd_coverage.py
python phase2/validation/pin_nvd_snapshot.py
python phase2/validation/validate_kb_snapshot.py phase2/data/nvd
python phase2/validation/run_golden_cve.py
python phase2/runners/run_evaluation.py --source all --snapshot-root phase2/data/nvd
python phase2/runners/run_metrics.py
python -m unittest discover -s phase2/validation -p 'test_*.py' -v
python phase2/validation/validate_inputs.py
```

These commands use the archived official feeds and `.meta` files already stored under `phase2/data/nvd/`; they make no network request. Raw per-CVE outputs are in `results/raw/`; coverage/golden/run integrity audits are in `results/audits/`, including `run_manifest.json` with result-file hashes; derived metrics are in `results/derived/metrics.json`.
