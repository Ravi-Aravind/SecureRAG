# Statistical Audit

Sources: frozen `analysis_ready.csv`, authoritative raw defense JSON, and frozen mechanism artifacts. Bootstrap uses paired CVE resampling, 10,000 iterations, seed 42, percentile indices 250 and 9750. McNemar is exact two-sided; Holm family is RobustRAG + NLI only.

Condition A baseline: 0/25. RobustRAG: 25/25. NLI: 20/25.

The prior NLI CI `[64%, 92%]` does not reproduce. Independent recomputation gives `[64%, 96%]`; the package uses `[64%, 96%]`. Confound exclusions: ['CVE-2022-27616', 'CVE-2022-42466', 'CVE-2023-0787'].
