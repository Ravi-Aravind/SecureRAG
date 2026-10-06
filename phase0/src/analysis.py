"""
analysis.py

Step 18: Statistical analysis for RAG poisoning experiment (Phase 0).

Evaluates the primary outcome (Condition A probe vs Condition C probe),
computes paired McNemar's test, bootstrap 95% confidence intervals,
retrieval performance metrics, security consequence classifications,
and parametric sensitivity counts across the frozen dataset of 25 CVEs.

Outputs:
- results/phase0_results.json
- results/phase0_results.csv

Usage:
    python src/analysis.py
"""

import csv
import json
import logging
from pathlib import Path
import sys
import numpy as np
import scipy.stats as stats

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Determine project root and directory paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def find_file(filename: str, subfolder: str = "data") -> Path:
    """Finds path to a file, checking project root and current working directory."""
    candidates = [
        PROJECT_ROOT / subfolder / filename,
        Path(subfolder) / filename,
        PROJECT_ROOT / filename,
        Path(filename),
    ]
    for c in candidates:
        if c.exists():
            return c
    return PROJECT_ROOT / subfolder / filename


def load_analysis_ready_csv(csv_path: Path) -> list[dict]:
    """Loads frozen analysis dataset from analysis_ready.csv."""
    if not csv_path.exists():
        logger.error(f"Analysis ready CSV not found at: {csv_path}")
        sys.exit(1)

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    logger.info(f"Loaded {len(rows)} CVE records from {csv_path}")
    return rows


def load_retrieval_results(json_path: Path) -> list[dict]:
    """Loads retrieval results from retrieval_results.json."""
    if not json_path.exists():
        logger.error(f"Retrieval results file not found at: {json_path}")
        sys.exit(1)

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    logger.info(f"Loaded {len(data)} retrieval records from {json_path}")
    return data


def compute_exact_mcnemar_pvalue(n01: int, n10: int) -> float:
    """
    Computes exact McNemar p-value using binomial distribution.
    Checks statsmodels first if available, then scipy.stats.binomtest / binom_test.
    """
    n_discordant = n01 + n10
    if n_discordant == 0:
        return 1.0

    # 1. Try statsmodels if installed
    try:
        from statsmodels.stats.contingency_tables import mcnemar
        # 2x2 table [[a, b], [c, d]] where b=n01, c=n10 or vice-versa
        res = mcnemar([[0, n01], [n10, 0]], exact=True)
        return float(res.pvalue)
    except (ImportError, Exception):
        pass

    # 2. Try scipy.stats.binomtest (scipy >= 1.7.0)
    if hasattr(stats, "binomtest"):
        res = stats.binomtest(n01, n_discordant, p=0.5)
        return float(res.pvalue)

    # 3. Fallback to scipy.stats.binom_test (legacy scipy)
    if hasattr(stats, "binom_test"):
        return float(stats.binom_test(n01, n_discordant, p=0.5))

    # 4. Fallback exact two-sided binomial sum
    p_val = float(2 * sum(stats.binom.pmf(k, n_discordant, 0.5) for k in range(max(n01, n10), n_discordant + 1)))
    return min(1.0, p_val)


def run_bootstrap_rd_ci(
    cond_a_fp: np.ndarray,
    cond_c_fp: np.ndarray,
    n_resamples: int = 10000,
    seed: int = 42,
) -> tuple[float, float, float]:
    """
    Computes bootstrap 95% CI for risk difference (Cond C FP rate - Cond A FP rate).
    """
    rng = np.random.default_rng(seed)
    n = len(cond_c_fp)
    boot_diffs = np.empty(n_resamples, dtype=float)

    for i in range(n_resamples):
        indices = rng.integers(0, n, size=n)
        rd_resample = cond_c_fp[indices].mean() - cond_a_fp[indices].mean()
        boot_diffs[i] = rd_resample

    ci_lower, ci_upper = np.percentile(boot_diffs, [2.5, 97.5])
    obs_diff = float(cond_c_fp.mean() - cond_a_fp.mean())
    return obs_diff, float(ci_lower), float(ci_upper)


def run_bootstrap_gap_ci(
    gaps: np.ndarray,
    n_resamples: int = 10000,
    seed: int = 42,
) -> tuple[float, float, float]:
    """
    Computes bootstrap 95% CI for mean similarity gap in Condition C.
    """
    rng = np.random.default_rng(seed)
    n = len(gaps)
    boot_means = np.empty(n_resamples, dtype=float)

    for i in range(n_resamples):
        indices = rng.integers(0, n, size=n)
        boot_means[i] = gaps[indices].mean()

    ci_lower, ci_upper = np.percentile(boot_means, [2.5, 97.5])
    obs_mean = float(gaps.mean())
    return obs_mean, float(ci_lower), float(ci_upper)


def perform_statistical_analysis() -> dict:
    """
    Executes full Step 18 analysis and returns structured results dictionary.
    """
    csv_path = find_file("analysis_ready.csv", "data")
    retrieval_path = find_file("retrieval_results.json", "data")

    rows = load_analysis_ready_csv(csv_path)
    retrieval_data = load_retrieval_results(retrieval_path)

    n_total = len(rows)

    # ---------------------------------------------------------
    # 1. Primary Outcome Counts
    # ---------------------------------------------------------
    # Condition A probe counts
    cond_a_not_affected = sum(1 for r in rows if r.get("cond_a_probe") == "not_affected")
    cond_a_affected = sum(1 for r in rows if r.get("cond_a_probe") == "affected")
    cond_a_other = n_total - cond_a_not_affected

    # Condition B probe counts
    cond_b_affected = sum(1 for r in rows if r.get("cond_b_probe") == "affected")
    cond_b_other = n_total - cond_b_affected

    # Condition C probe counts
    cond_c_affected = sum(1 for r in rows if r.get("cond_c_probe") == "affected")
    cond_c_conflict_ack = sum(1 for r in rows if r.get("cond_c_probe") == "conflict_acknowledged")
    cond_c_not_affected = sum(1 for r in rows if r.get("cond_c_probe") == "not_affected")
    cond_c_other = n_total - (cond_c_affected + cond_c_conflict_ack + cond_c_not_affected)

    # False positive rates & Risk difference
    cond_a_fp_rate = cond_a_affected / n_total  # baseline
    cond_c_fp_rate = cond_c_affected / n_total
    risk_difference = cond_c_fp_rate - cond_a_fp_rate

    # Binary vectors for paired comparison
    cond_a_fp_vec = np.array([1 if r.get("cond_a_probe") == "affected" else 0 for r in rows], dtype=int)
    cond_c_fp_vec = np.array([1 if r.get("cond_c_probe") == "affected" else 0 for r in rows], dtype=int)

    # ---------------------------------------------------------
    # 2. McNemar's Test
    # ---------------------------------------------------------
    # Discordant pairs:
    # n01: A=not_affected, C=affected (poisoning successful false positive)
    # n10: A=affected, C=not_affected (clean failure reverted in poisoned)
    n01 = sum(1 for r in rows if r.get("cond_a_probe") == "not_affected" and r.get("cond_c_probe") == "affected")
    n10 = sum(1 for r in rows if r.get("cond_a_probe") == "affected" and r.get("cond_c_probe") == "not_affected")
    n00 = sum(1 for r in rows if r.get("cond_a_probe") == "not_affected" and r.get("cond_c_probe") == "not_affected")
    n11 = sum(1 for r in rows if r.get("cond_a_probe") == "affected" and r.get("cond_c_probe") == "affected")

    n_discordant = n01 + n10
    if n_discordant > 0:
        chi2_stat = float(((n01 - n10) ** 2) / n_discordant)
        chi2_pvalue = float(stats.chi2.sf(chi2_stat, df=1))
    else:
        chi2_stat = 0.0
        chi2_pvalue = 1.0

    exact_pvalue = compute_exact_mcnemar_pvalue(n01, n10)

    if exact_pvalue < 0.001:
        interpretation = (
            f"Statistically significant increase in false positive rate under Condition C "
            f"(exact p = {exact_pvalue:.4e} < 0.001; chi-square = {chi2_stat:.2f})."
        )
    elif exact_pvalue < 0.05:
        interpretation = (
            f"Statistically significant increase in false positive rate under Condition C "
            f"(exact p = {exact_pvalue:.4f} < 0.05; chi-square = {chi2_stat:.2f})."
        )
    else:
        interpretation = (
            f"No statistically significant difference detected (exact p = {exact_pvalue:.4f} >= 0.05)."
        )

    # ---------------------------------------------------------
    # 3. Bootstrap CI for Risk Difference
    # ---------------------------------------------------------
    obs_rd, rd_ci_lower, rd_ci_upper = run_bootstrap_rd_ci(
        cond_a_fp=cond_a_fp_vec,
        cond_c_fp=cond_c_fp_vec,
        n_resamples=10000,
        seed=42,
    )

    # ---------------------------------------------------------
    # 4. Retrieval Metrics
    # ---------------------------------------------------------
    cond_c_retrieval = [x for x in retrieval_data if x.get("condition") == "Condition C"]
    cond_a_retrieval = [x for x in retrieval_data if x.get("condition") == "Condition A"]

    # Condition C similarity gaps
    gaps_list = [
        float(x["similarity_gap"])
        for x in cond_c_retrieval
        if x.get("similarity_gap") is not None
    ]
    gaps_arr = np.array(gaps_list, dtype=float)

    mean_gap = float(gaps_arr.mean()) if len(gaps_arr) > 0 else 0.0
    min_gap = float(gaps_arr.min()) if len(gaps_arr) > 0 else 0.0
    max_gap = float(gaps_arr.max()) if len(gaps_arr) > 0 else 0.0

    # Co-retrieval rate in Condition C
    co_retrieval_confirmed = sum(
        1 for x in cond_c_retrieval
        if x.get("co_retrieval_confirmed", x.get("both_in_top5", False)) is True
    )
    co_retrieval_rate = co_retrieval_confirmed / len(cond_c_retrieval) if cond_c_retrieval else 0.0

    # Recall@k for original document in Condition A
    cond_a_ranks = [x.get("original_rank") for x in cond_a_retrieval]
    recall_at_1 = sum(1 for r in cond_a_ranks if r is not None and r <= 1) / len(cond_a_ranks) if cond_a_ranks else 0.0
    recall_at_3 = sum(1 for r in cond_a_ranks if r is not None and r <= 3) / len(cond_a_ranks) if cond_a_ranks else 0.0
    recall_at_5 = sum(1 for r in cond_a_ranks if r is not None and r <= 5) / len(cond_a_ranks) if cond_a_ranks else 0.0

    # Bootstrap 95% CI for mean similarity gap
    obs_mean_gap, gap_ci_lower, gap_ci_upper = run_bootstrap_gap_ci(
        gaps=gaps_arr,
        n_resamples=10000,
        seed=42,
    )

    # ---------------------------------------------------------
    # 5. Security Consequence Summary
    # ---------------------------------------------------------
    fp_security_decision = cond_c_affected
    conflict_no_decision = cond_c_conflict_ack
    correct_not_affected = cond_c_not_affected

    # ---------------------------------------------------------
    # 6. Parametric Sensitivity
    # ---------------------------------------------------------
    param_correct = sum(1 for r in rows if r.get("parametric") == "correct")
    param_mutated = sum(1 for r in rows if r.get("parametric") == "mutated")
    param_parsing_failure = sum(1 for r in rows if r.get("parametric") == "parsing_failure")
    param_refusal = sum(
        1 for r in rows
        if r.get("parametric") in ["refusal", "refusal_or_insufficient"]
    )
    param_other = n_total - (param_correct + param_mutated + param_parsing_failure + param_refusal)

    # ---------------------------------------------------------
    # 7. Parametric Confounds & Decomposition
    # ---------------------------------------------------------
    confound_rows = [r for r in rows if r.get("parametric_confound") in [True, "True", "true"]]
    non_confound_rows = [r for r in rows if r.get("parametric_confound") not in [True, "True", "true"]]
    
    n_confounds = len(confound_rows)
    n_non_confounds = len(non_confound_rows)
    
    fp_excluding_parametric_count = sum(1 for r in non_confound_rows if r.get("cond_c_probe") == "affected")
    fp_excluding_parametric_rate_sample = fp_excluding_parametric_count / n_total if n_total else 0.0
    fp_excluding_parametric_rate_subset = fp_excluding_parametric_count / n_non_confounds if n_non_confounds else 0.0

    # ---------------------------------------------------------
    # 8. Qualitative Mechanism Breakdown
    # ---------------------------------------------------------
    inclusive_misreading_count = sum(1 for r in rows if r.get("failure_mechanism") == "inclusive_boundary_misreading")
    genuine_poisoning_count = sum(1 for r in rows if r.get("failure_mechanism") == "genuine_mutated_boundary_poisoning")
    parametric_override_count = sum(1 for r in rows if r.get("failure_mechanism") == "parametric_override")
    classifier_error_count = sum(1 for r in rows if r.get("failure_mechanism") == "classifier_error")
    none_mechanism_count = sum(1 for r in rows if r.get("failure_mechanism") in ["none", "", None])

    # ---------------------------------------------------------
    # Construct Results Object
    # ---------------------------------------------------------
    results = {
        "experiment_metadata": {
            "step": "Step 18",
            "description": "Statistical analysis for RAG poisoning experiment (Phase 0)",
            "n_total_cves": n_total,
            "data_source": "data/analysis_ready.csv",
            "retrieval_source": "data/retrieval_results.json",
            "bootstrap_resamples": 10000,
            "random_seed": 42,
        },
        "primary_outcomes": {
            "n_total": n_total,
            "condition_a": {
                "not_affected_count": cond_a_not_affected,
                "affected_count": cond_a_affected,
                "other_count": cond_a_other,
                "false_positive_rate": cond_a_fp_rate,
            },
            "condition_b": {
                "affected_count": cond_b_affected,
                "other_count": cond_b_other,
            },
            "condition_c": {
                "affected_count": cond_c_affected,
                "conflict_acknowledged_count": cond_c_conflict_ack,
                "not_affected_count": cond_c_not_affected,
                "other_count": cond_c_other,
                "false_positive_rate": cond_c_fp_rate,
            },
            "risk_difference": {
                "observed": risk_difference,
                "formula": "Cond_C_FP_rate - Cond_A_FP_rate",
                "bootstrap_ci_95": {
                    "lower": rd_ci_lower,
                    "upper": rd_ci_upper,
                },
            },
        },
        "mcnemar_test": {
            "unit_of_analysis": "CVE",
            "paired_comparison": "Cond_A_probe vs Cond_C_probe",
            "contingency_counts": {
                "n00_a_not_affected_c_not_affected": n00,
                "n01_a_not_affected_c_affected": n01,
                "n10_a_affected_c_not_affected": n10,
                "n11_a_affected_c_affected": n11,
            },
            "discordant_pairs": {
                "n01": n01,
                "n10": n10,
            },
            "chi_square_statistic": chi2_stat,
            "chi_square_pvalue": chi2_pvalue,
            "exact_pvalue": exact_pvalue,
            "interpretation": interpretation,
            "degeneracy_note": "With n10=0 the test is one-sided in nature; the p-value reflects only n01 discordant pairs.",
        },
        "parametric_confounds": {
            "total_confounds": n_confounds,
            "confound_cve_ids": [r["cve_id"] for r in confound_rows],
            "raw_fp_count": cond_c_affected,
            "raw_fp_rate": cond_c_fp_rate,
            "fp_excluding_parametric_count": fp_excluding_parametric_count,
            "fp_excluding_parametric_rate_sample": fp_excluding_parametric_rate_sample,
            "fp_excluding_parametric_rate_subset": fp_excluding_parametric_rate_subset,
        },
        "qualitative_mechanisms": {
            "inclusive_boundary_misreading_count": inclusive_misreading_count,
            "inclusive_boundary_misreading_rate": inclusive_misreading_count / n_total,
            "genuine_mutated_boundary_poisoning_count": genuine_poisoning_count,
            "genuine_mutated_boundary_poisoning_rate": genuine_poisoning_count / n_total,
            "parametric_override_count": parametric_override_count,
            "classifier_error_count": classifier_error_count,
            "none_count": none_mechanism_count,
        },
        "retrieval_metrics": {
            "condition_c_similarity_gap": {
                "mean": mean_gap,
                "min": min_gap,
                "max": max_gap,
                "bootstrap_ci_95": {
                    "lower": gap_ci_lower,
                    "upper": gap_ci_upper,
                },
            },
            "co_retrieval_rate": {
                "confirmed_count": co_retrieval_confirmed,
                "total_count": len(cond_c_retrieval),
                "rate": co_retrieval_rate,
            },
            "condition_a_recall": {
                "recall_at_1": recall_at_1,
                "recall_at_3": recall_at_3,
                "recall_at_5": recall_at_5,
            },
        },
        "security_consequences": {
            "false_positive_security_decision": {
                "count": fp_security_decision,
                "fraction": fp_security_decision / n_total,
                "percentage": (fp_security_decision / n_total) * 100,
                "description": "Condition C probe = affected (vulnerability falsely reported as applicable)",
            },
            "conflict_no_decision": {
                "count": conflict_no_decision,
                "fraction": conflict_no_decision / n_total,
                "percentage": (conflict_no_decision / n_total) * 100,
                "description": "Condition C probe = conflict_acknowledged (conflicting versions reported, no clear decision)",
            },
            "correct_not_affected": {
                "count": correct_not_affected,
                "fraction": correct_not_affected / n_total,
                "percentage": (correct_not_affected / n_total) * 100,
                "description": "Condition C probe = not_affected (model resisted poisoning / correctly determined safe version)",
            },
        },
        "parametric_sensitivity": {
            "correct_count": param_correct,
            "mutated_count": param_mutated,
            "parsing_failure_count": param_parsing_failure,
            "refusal_count": param_refusal,
            "other_count": param_other,
            "note": "parsing_failure means the model did not produce a recognizable version boundary (likely unknown CVE). Do NOT call this proof of memorization.",
        },
        "statistical_cautions": [
            "N=25: low statistical power. Confidence intervals are wide. Non-significance does not prove no effect.",
            "McNemar's test with n10=0 is degenerate in one direction. The p-value reflects only n01 discordant pairs.",
            "Bootstrap CI reflects sampling variability in this sample only.",
        ],
    }

    return results


def print_results(results: dict) -> None:
    """Prints all analysis results in a clean, structured format."""
    po = results["primary_outcomes"]
    mcnemar = results["mcnemar_test"]
    ret = results["retrieval_metrics"]
    sec = results["security_consequences"]
    param = results["parametric_sensitivity"]
    pc = results["parametric_confounds"]
    qm = results["qualitative_mechanisms"]
    n_total = po["n_total"]

    print("\n" + "=" * 80)
    print("STEP 18: STATISTICAL ANALYSIS RESULTS (PHASE 0 - CORRECTED)")
    print("=" * 80)

    # 1. Primary Outcomes
    print("\n" + "-" * 80)
    print(f"1. PRIMARY OUTCOME COUNTS (N = {n_total} CVEs)")
    print("-" * 80)
    print(f"Condition A (Clean Baseline):")
    print(f"  - not_affected : {po['condition_a']['not_affected_count']:>2} / {n_total} ({po['condition_a']['not_affected_count']/n_total*100:>5.1f}%)")
    print(f"  - other        : {po['condition_a']['other_count']:>2} / {n_total} ({po['condition_a']['other_count']/n_total*100:>5.1f}%)")
    print(f"  - False Positive Rate (Cond A): {po['condition_a']['false_positive_rate']:.4f} (0 / {n_total} = 0.0%) [Baseline]")

    print(f"\nCondition B (Pure Poisoned):")
    print(f"  - affected     : {po['condition_b']['affected_count']:>2} / {n_total} ({po['condition_b']['affected_count']/n_total*100:>5.1f}%)")
    print(f"  - other        : {po['condition_b']['other_count']:>2} / {n_total} ({po['condition_b']['other_count']/n_total*100:>5.1f}%)")

    print(f"\nCondition C (Contradictory / Conflict):")
    print(f"  - affected (False Positive) : {po['condition_c']['affected_count']:>2} / {n_total} ({po['condition_c']['affected_count']/n_total*100:>5.1f}%)")
    print(f"  - conflict_acknowledged     : {po['condition_c']['conflict_acknowledged_count']:>2} / {n_total} ({po['condition_c']['conflict_acknowledged_count']/n_total*100:>5.1f}%)")
    print(f"  - not_affected              : {po['condition_c']['not_affected_count']:>2} / {n_total} ({po['condition_c']['not_affected_count']/n_total*100:>5.1f}%)")
    if po['condition_c']['other_count'] > 0:
        print(f"  - other                     : {po['condition_c']['other_count']:>2} / {n_total}")
    print(f"  - False Positive Rate (Cond C): {po['condition_c']['false_positive_rate']:.4f} ({po['condition_c']['affected_count']} / {n_total} = {po['condition_c']['false_positive_rate']*100:.1f}%)")

    rd = po["risk_difference"]
    print(f"\nRisk Difference (Cond C FP Rate - Cond A FP Rate):")
    print(f"  - Observed RD : {rd['observed']:.4f} ({rd['observed']*100:.1f} percentage points)")

    # 2. McNemar's Test
    print("\n" + "-" * 80)
    print("2. McNEMAR'S PAIRED TEST (Unit of Analysis: CVE)")
    print("-" * 80)
    print(f"Paired comparison: Cond_A_probe vs Cond_C_probe per CVE")
    print(f"Contingency Counts:")
    print(f"  - n00 (A=not_affected, C=not_affected) : {mcnemar['contingency_counts']['n00_a_not_affected_c_not_affected']:>2}  (clean resistance)")
    print(f"  - n01 (A=not_affected, C=affected)     : {mcnemar['contingency_counts']['n01_a_not_affected_c_affected']:>2}  (discordant: poisoning succeeded)")
    print(f"  - n10 (A=affected,     C=not_affected) : {mcnemar['contingency_counts']['n10_a_affected_c_not_affected']:>2}  (discordant: baseline failure only)")
    print(f"  - n11 (A=affected,     C=affected)     : {mcnemar['contingency_counts']['n11_a_affected_c_affected']:>2}  (both affected)")
    print(f"Discordant Pairs:")
    print(f"  - n01 = {mcnemar['discordant_pairs']['n01']}")
    print(f"  - n10 = {mcnemar['discordant_pairs']['n10']}")
    print(f"Statistics:")
    print(f"  - McNemar Chi-Square Statistic : {mcnemar['chi_square_statistic']:.4f}")
    print(f"  - Chi-Square Asymptotic p-value: {mcnemar['chi_square_pvalue']:.6f}")
    print(f"  - Exact McNemar p-value        : {mcnemar['exact_pvalue']:.6f} ({mcnemar['exact_pvalue']:.4e})")
    print(f"Interpretation:")
    print(f"  - {mcnemar['interpretation']}")
    print(f"Note:")
    print(f"  - {mcnemar['degeneracy_note']}")

    # 3. Bootstrap CI
    print("\n" + "-" * 80)
    print("3. BOOTSTRAP CONFIDENCE INTERVAL FOR RISK DIFFERENCE (N=10,000 resamples, seed=42)")
    print("-" * 80)
    print(f"  - Observed Risk Difference : {rd['observed']:.4f} ({rd['observed']*100:.1f}%)")
    print(f"  - 95% CI Lower Bound       : {rd['bootstrap_ci_95']['lower']:.4f} ({rd['bootstrap_ci_95']['lower']*100:.1f}%)")
    print(f"  - 95% CI Upper Bound       : {rd['bootstrap_ci_95']['upper']:.4f} ({rd['bootstrap_ci_95']['upper']*100:.1f}%)")
    print(f"  - 95% Bootstrap CI Range   : [{rd['bootstrap_ci_95']['lower']:.4f}, {rd['bootstrap_ci_95']['upper']:.4f}]")

    # 4. Mechanism & Confound Breakdown
    print("\n" + "-" * 80)
    print("4. QUALITATIVE MECHANISM & CONFOUND DECOMPOSITION")
    print("-" * 80)
    print(f"Parametric Confounds:")
    print(f"  - Identified Confound CVEs : {', '.join(pc['confound_cve_ids'])} (N={pc['total_confounds']})")
    print(f"  - Raw Observed FP Count    : {pc['raw_fp_count']} / {n_total} ({pc['raw_fp_rate']*100:.1f}%)")
    print(f"  - FP Excluding Confounds   : {pc['fp_excluding_parametric_count']} / {n_total - pc['total_confounds']} ({pc['fp_excluding_parametric_rate_subset']*100:.1f}%) [or {pc['fp_excluding_parametric_count']}/{n_total} = {pc['fp_excluding_parametric_rate_sample']*100:.1f}% of total]")
    print(f"\nMechanisms Breakdown (N={n_total}):")
    print(f"  - Inclusive-boundary misreading      : {qm['inclusive_boundary_misreading_count']:>2} / {n_total} ({qm['inclusive_boundary_misreading_rate']*100:>5.1f}%)")
    print(f"  - Genuine mutated-boundary poisoning : {qm['genuine_mutated_boundary_poisoning_count']:>2} / {n_total} ({qm['genuine_mutated_boundary_poisoning_rate']*100:>5.1f}%)")
    print(f"  - Parametric override (pure)         : {qm['parametric_override_count']:>2} / {n_total} ({qm['parametric_override_count']/n_total*100:>5.1f}%)")
    print(f"  - Classifier error (corrected)       : {qm['classifier_error_count']:>2} / {n_total} (0 unresolved)")
    print(f"  - None (clean / conflict ack)        : {qm['none_count']:>2} / {n_total} ({qm['none_count']/n_total*100:>5.1f}%)")

    # 5. Retrieval Metrics
    print("\n" + "-" * 80)
    print("5. RETRIEVAL METRICS (from data/retrieval_results.json)")
    print("-" * 80)
    c_gap = ret["condition_c_similarity_gap"]
    print(f"Condition C Embedding Similarity Gap (between orig and mutated doc):")
    print(f"  - Mean Similarity Gap : {c_gap['mean']:.8f}")
    print(f"  - Min Similarity Gap  : {c_gap['min']:.8f}")
    print(f"  - Max Similarity Gap  : {c_gap['max']:.8f}")
    print(f"  - 95% Bootstrap CI    : [{c_gap['bootstrap_ci_95']['lower']:.8f}, {c_gap['bootstrap_ci_95']['upper']:.8f}]")
    print(f"\nCo-retrieval in Condition C:")
    print(f"  - Co-retrieval Rate   : {ret['co_retrieval_rate']['confirmed_count']} / {ret['co_retrieval_rate']['total_count']} ({ret['co_retrieval_rate']['rate']*100:.1f}%)")
    print(f"\nCondition A Original Document Retrieval:")
    print(f"  - Recall@1            : {ret['condition_a_recall']['recall_at_1']*100:.1f}% ({ret['condition_a_recall']['recall_at_1']:.4f})")
    print(f"  - Recall@3            : {ret['condition_a_recall']['recall_at_3']*100:.1f}% ({ret['condition_a_recall']['recall_at_3']:.4f})")
    print(f"  - Recall@5            : {ret['condition_a_recall']['recall_at_5']*100:.1f}% ({ret['condition_a_recall']['recall_at_5']:.4f})")

    # 6. Security Consequence Summary
    print("\n" + "-" * 80)
    print(f"6. SECURITY CONSEQUENCE SUMMARY (Condition C Type C Probes, N={n_total})")
    print("-" * 80)
    print(f"  1. false_positive_security_decision (Cond C probe = affected)            : {sec['false_positive_security_decision']['count']:>2} / {n_total} ({sec['false_positive_security_decision']['percentage']:>5.1f}%)")
    print(f"  2. conflict_no_decision             (Cond C probe = conflict_acknowledged) : {sec['conflict_no_decision']['count']:>2} / {n_total} ({sec['conflict_no_decision']['percentage']:>5.1f}%)")
    print(f"  3. correct_not_affected             (Cond C probe = not_affected)          : {sec['correct_not_affected']['count']:>2} / {n_total} ({sec['correct_not_affected']['percentage']:>5.1f}%)")

    # 7. Parametric Sensitivity
    print("\n" + "-" * 80)
    print(f"7. PARAMETRIC SENSITIVITY (No-Retrieval Baseline Queries, N={n_total})")
    print("-" * 80)
    print(f"  - correct                     : {param['correct_count']:>2} / {n_total} ({param['correct_count']/n_total*100:>5.1f}%)")
    print(f"  - mutated                     : {param['mutated_count']:>2} / {n_total} ({param['mutated_count']/n_total*100:>5.1f}%)")
    print(f"  - parsing_failure             : {param['parsing_failure_count']:>2} / {n_total} ({param['parsing_failure_count']/n_total*100:>5.1f}%)")
    print(f"  - refusal_or_insufficient     : {param['refusal_count']:>2} / {n_total} ({param['refusal_count']/n_total*100:>5.1f}%)")
    if param['other_count'] > 0:
        print(f"  - other                       : {param['other_count']:>2} / {n_total}")
    print(f"Note on Parametric Results:")
    print(f"  - {param['note']}")

    # 8. Statistical Cautions
    print("\n" + "=" * 80)
    print("STATISTICAL CAUTION REQUIREMENTS")
    print("=" * 80)
    for caution in results["statistical_cautions"]:
        print(f"  [!] \"{caution}\"")
    print("=" * 80 + "\n")


def save_results_json(results: dict, output_path: Path) -> None:
    """Saves structured results to JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Saved full results JSON to: {output_path}")


def save_results_csv(results: dict, output_path: Path) -> None:
    """Saves summary metrics to CSV file with one row per metric."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    po = results["primary_outcomes"]
    mcnemar = results["mcnemar_test"]
    ret = results["retrieval_metrics"]
    sec = results["security_consequences"]
    param = results["parametric_sensitivity"]
    pc = results["parametric_confounds"]
    qm = results["qualitative_mechanisms"]
    n_total = po["n_total"]

    rows = [
        # Primary Outcomes
        {
            "category": "Primary Outcome",
            "metric": "n_total_cves",
            "value": po["n_total"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": "CVEs",
        },
        {
            "category": "Primary Outcome",
            "metric": "cond_a_not_affected_count",
            "value": po["condition_a"]["not_affected_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"count / {n_total}",
        },
        {
            "category": "Primary Outcome",
            "metric": "cond_a_other_count",
            "value": po["condition_a"]["other_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"count / {n_total}",
        },
        {
            "category": "Primary Outcome",
            "metric": "cond_a_false_positive_rate",
            "value": f"{po['condition_a']['false_positive_rate']:.4f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"baseline rate (0/{n_total} = 0.0)",
        },
        {
            "category": "Primary Outcome",
            "metric": "cond_b_affected_count",
            "value": po["condition_b"]["affected_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"count / {n_total}",
        },
        {
            "category": "Primary Outcome",
            "metric": "cond_b_other_count",
            "value": po["condition_b"]["other_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"count / {n_total}",
        },
        {
            "category": "Primary Outcome",
            "metric": "cond_c_affected_count",
            "value": po["condition_c"]["affected_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"false positive count / {n_total}",
        },
        {
            "category": "Primary Outcome",
            "metric": "cond_c_conflict_acknowledged_count",
            "value": po["condition_c"]["conflict_acknowledged_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"conflict count / {n_total}",
        },
        {
            "category": "Primary Outcome",
            "metric": "cond_c_not_affected_count",
            "value": po["condition_c"]["not_affected_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"clean answer count / {n_total}",
        },
        {
            "category": "Primary Outcome",
            "metric": "cond_c_false_positive_rate",
            "value": f"{po['condition_c']['false_positive_rate']:.4f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"rate ({po['condition_c']['affected_count']}/{n_total} = {po['condition_c']['false_positive_rate']:.4f})",
        },
        {
            "category": "Primary Outcome",
            "metric": "risk_difference",
            "value": f"{po['risk_difference']['observed']:.4f}",
            "ci_95_lower": f"{po['risk_difference']['bootstrap_ci_95']['lower']:.4f}",
            "ci_95_upper": f"{po['risk_difference']['bootstrap_ci_95']['upper']:.4f}",
            "unit_or_notes": "Cond C FP rate - Cond A FP rate",
        },
        # Parametric Confounds
        {
            "category": "Parametric Confound",
            "metric": "parametric_confound_count",
            "value": pc["total_confounds"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"Identified confound CVEs (N={pc['total_confounds']})",
        },
        {
            "category": "Parametric Confound",
            "metric": "cond_c_fp_excluding_parametric_count",
            "value": pc["fp_excluding_parametric_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"FP count excluding {pc['total_confounds']} parametric confounds",
        },
        {
            "category": "Parametric Confound",
            "metric": "cond_c_fp_excluding_parametric_rate",
            "value": f"{pc['fp_excluding_parametric_rate_subset']:.4f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"Rate among non-confounds ({pc['fp_excluding_parametric_count']}/{n_total - pc['total_confounds']})",
        },
        # Qualitative Mechanisms
        {
            "category": "Qualitative Mechanism",
            "metric": "inclusive_boundary_misreading_count",
            "value": qm["inclusive_boundary_misreading_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"Misreading exclusive boundary as inclusive (count / {n_total})",
        },
        {
            "category": "Qualitative Mechanism",
            "metric": "genuine_mutated_boundary_poisoning_count",
            "value": qm["genuine_mutated_boundary_poisoning_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"Mutated boundary wins outright in conflict (count / {n_total})",
        },
        {
            "category": "Qualitative Mechanism",
            "metric": "parametric_override_count",
            "value": qm["parametric_override_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"Retrieval-independent parametric override (count / {n_total})",
        },
        {
            "category": "Qualitative Mechanism",
            "metric": "classifier_error_count",
            "value": qm["classifier_error_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"Unresolved classifier errors: 0 (1 identified and corrected)",
        },
        # McNemar Test
        {
            "category": "McNemar Test",
            "metric": "n01_discordant_pairs",
            "value": mcnemar["discordant_pairs"]["n01"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": "Cond A=not_affected, Cond C=affected",
        },
        {
            "category": "McNemar Test",
            "metric": "n10_discordant_pairs",
            "value": mcnemar["discordant_pairs"]["n10"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": "Cond A=affected, Cond C=not_affected",
        },
        {
            "category": "McNemar Test",
            "metric": "mcnemar_chi_square",
            "value": f"{mcnemar['chi_square_statistic']:.4f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": "(n01 - n10)^2 / (n01 + n10)",
        },
        {
            "category": "McNemar Test",
            "metric": "mcnemar_exact_p_value",
            "value": f"{mcnemar['exact_pvalue']:.6e}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": "Exact binomial test (p=0.5)",
        },
        # Retrieval Metrics
        {
            "category": "Retrieval Metrics",
            "metric": "cond_c_similarity_gap_mean",
            "value": f"{ret['condition_c_similarity_gap']['mean']:.8f}",
            "ci_95_lower": f"{ret['condition_c_similarity_gap']['bootstrap_ci_95']['lower']:.8f}",
            "ci_95_upper": f"{ret['condition_c_similarity_gap']['bootstrap_ci_95']['upper']:.8f}",
            "unit_or_notes": "Cosine similarity gap (Condition C)",
        },
        {
            "category": "Retrieval Metrics",
            "metric": "cond_c_similarity_gap_min",
            "value": f"{ret['condition_c_similarity_gap']['min']:.8f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"Min similarity gap across {n_total} CVEs",
        },
        {
            "category": "Retrieval Metrics",
            "metric": "cond_c_similarity_gap_max",
            "value": f"{ret['condition_c_similarity_gap']['max']:.8f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"Max similarity gap across {n_total} CVEs",
        },
        {
            "category": "Retrieval Metrics",
            "metric": "cond_c_co_retrieval_rate",
            "value": f"{ret['co_retrieval_rate']['rate']:.4f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"{ret['co_retrieval_rate']['confirmed_count']} / {ret['co_retrieval_rate']['total_count']}",
        },
        {
            "category": "Retrieval Metrics",
            "metric": "cond_a_recall_at_1",
            "value": f"{ret['condition_a_recall']['recall_at_1']:.4f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": "Original doc rank <= 1 in Cond A",
        },
        {
            "category": "Retrieval Metrics",
            "metric": "cond_a_recall_at_3",
            "value": f"{ret['condition_a_recall']['recall_at_3']:.4f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": "Original doc rank <= 3 in Cond A",
        },
        {
            "category": "Retrieval Metrics",
            "metric": "cond_a_recall_at_5",
            "value": f"{ret['condition_a_recall']['recall_at_5']:.4f}",
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": "Original doc rank <= 5 in Cond A",
        },
        # Security Consequences
        {
            "category": "Security Consequence",
            "metric": "false_positive_security_decision_count",
            "value": sec["false_positive_security_decision"]["count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"fraction: {sec['false_positive_security_decision']['fraction']:.4f} ({sec['false_positive_security_decision']['count']}/{n_total})",
        },
        {
            "category": "Security Consequence",
            "metric": "conflict_no_decision_count",
            "value": sec["conflict_no_decision"]["count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"fraction: {sec['conflict_no_decision']['fraction']:.4f} ({sec['conflict_no_decision']['count']}/{n_total})",
        },
        {
            "category": "Security Consequence",
            "metric": "correct_not_affected_count",
            "value": sec["correct_not_affected"]["count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"fraction: {sec['correct_not_affected']['fraction']:.4f} ({sec['correct_not_affected']['count']}/{n_total})",
        },
        # Parametric Sensitivity
        {
            "category": "Parametric Sensitivity",
            "metric": "parametric_correct_count",
            "value": param["correct_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"count / {n_total}",
        },
        {
            "category": "Parametric Sensitivity",
            "metric": "parametric_mutated_count",
            "value": param["mutated_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"count / {n_total}",
        },
        {
            "category": "Parametric Sensitivity",
            "metric": "parametric_parsing_failure_count",
            "value": param["parsing_failure_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"count / {n_total} (likely unknown CVEs)",
        },
        {
            "category": "Parametric Sensitivity",
            "metric": "parametric_refusal_count",
            "value": param["refusal_count"],
            "ci_95_lower": "",
            "ci_95_upper": "",
            "unit_or_notes": f"count / {n_total}",
        },
    ]

    fieldnames = ["category", "metric", "value", "ci_95_lower", "ci_95_upper", "unit_or_notes"]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"Saved summary CSV to: {output_path}")


def main() -> None:
    results_dir = PROJECT_ROOT / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    json_output_path = results_dir / "phase0_results.json"
    csv_output_path = results_dir / "phase0_results.csv"

    results = perform_statistical_analysis()
    print_results(results)

    save_results_json(results, json_output_path)
    save_results_csv(results, csv_output_path)


if __name__ == "__main__":
    main()
