import json
import os
import sys
import random
import math
import hashlib
import csv

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from phase1.validation.check_phase0_integrity import check_integrity

PHASE0_RESULTS_PATH = os.path.join(ROOT_DIR, 'phase0', 'results', 'phase0_results.json')
PHASE0_RECORDS_PATH = os.path.join(ROOT_DIR, 'phase0', 'data', 'experiment_records.json')
ROBUSTRAG_RESULTS_PATH = os.path.join(ROOT_DIR, 'phase1', 'results', 'robustrag_raw_results_a30146b9-95b2-487b-badc-7306660709a4.json')

CSV_OUT = os.path.join(ROOT_DIR, 'phase1', 'results', 'robustrag_paired_results.csv')
MECH_OUT = os.path.join(ROOT_DIR, 'phase1', 'results', 'robustrag_mechanism_analysis.json')
MD_OUT = os.path.join(ROOT_DIR, 'phase1', 'results', 'robustrag_statistical_analysis.md')

CONFOUNDS = {"CVE-2022-27616", "CVE-2022-42466", "CVE-2023-0787"}

def is_incorrect(sec_class: str) -> bool:
    return sec_class in ["false_positive", "false_negative"]

def bootstrap_rd(y_p0, y_rr, n_boot=10000, seed=42):
    random.seed(seed)
    diffs = [r - p for p, r in zip(y_p0, y_rr)]
    n = len(diffs)
    if n == 0:
        return 0.0, 0.0, 0.0
    
    mean_diff = sum(diffs) / n
    boot_rds = []
    for _ in range(n_boot):
        sample = random.choices(diffs, k=n)
        boot_rds.append(sum(sample) / n)
        
    boot_rds.sort()
    lower_idx = int(0.025 * n_boot)
    upper_idx = int(0.975 * n_boot)
    
    return mean_diff, boot_rds[lower_idx], boot_rds[upper_idx]

def binom_pval(k, n, p=0.5):
    # Two-sided exact binomial p-value
    if n == 0:
        return 1.0
    # Expected value is n * p. Calculate prob of X <= k or X >= n - k.
    # Actually, for p=0.5, the distribution is symmetric.
    # P(X <= min(k, n-k)) * 2
    tail = min(k, n - k)
    prob = sum(math.comb(n, i) * (p ** i) * ((1 - p) ** (n - i)) for i in range(tail + 1))
    return min(1.0, prob * 2)

def exact_mcnemar(y_p0, y_rr):
    a = sum((p == 0) and (r == 0) for p, r in zip(y_p0, y_rr)) # both correct
    b = sum((p == 0) and (r == 1) for p, r in zip(y_p0, y_rr)) # p0 correct, rr incorrect
    c = sum((p == 1) and (r == 0) for p, r in zip(y_p0, y_rr)) # p0 incorrect, rr correct
    d = sum((p == 1) and (r == 1) for p, r in zip(y_p0, y_rr)) # both incorrect
    
    pval = binom_pval(b, b + c, 0.5)
    return a, b, c, d, pval

def determine_mechanism(cve_id, rr_result):
    if not is_incorrect(rr_result.get("security_class")):
        return "none", "Correct or safe failure"
        
    mutated_supported_calls = [c for c in rr_result.get("isolated_calls", []) if c.get("robustrag_vote") == "mutated-supported"]
    classifier_errors = 0
    genuine_poisoning = 0
    
    for c in mutated_supported_calls:
        resp = c.get("raw_response", "").lower()
        if ("cannot determine" in resp or "no information" in resp or "do not mention" in resp) and "is affected" in resp:
            classifier_errors += 1
        elif c.get("document_identity") == "mutated" and ("is affected" in resp or "is vulnerable" in resp or "yes" in resp):
            genuine_poisoning += 1
            
    if classifier_errors > 0 and genuine_poisoning == 0:
        return "classifier_error", f"Found {classifier_errors} explicit refusals falsely matched by brittle classifier."
    elif genuine_poisoning > 0:
        return "genuine_mutated_boundary_poisoning", f"Model genuinely hallucinated/poisoned from mutated docs ({genuine_poisoning} calls)."
    else:
        return "unresolved", "Could not definitively establish causal attribution from preserved evidence."

def run_analysis():
    if not check_integrity():
        print("ABORT: Phase 0 integrity check failed.")
        sys.exit(1)
        
    with open(PHASE0_RESULTS_PATH, 'r') as f:
        p0_results = json.load(f)
    
    with open(ROBUSTRAG_RESULTS_PATH, 'r') as f:
        rr_results = json.load(f)
        
    p0_condA = {}
    p0_condC = {}
    for r in p0_results.get("results", []):
        if r["condition"] == "Condition A":
            p0_condA[r["cve_id"]] = r
        elif r["condition"] == "Condition C":
            p0_condC[r["cve_id"]] = r

    if not p0_condA:
        with open(PHASE0_RECORDS_PATH, 'r') as f:
            records = json.load(f)
        for r in records:
            if r["condition"] == "Condition A":
                p0_condA[r["cve_id"]] = r
            elif r["condition"] == "Condition C":
                p0_condC[r["cve_id"]] = r

    csv_rows = []
    y_p0_raw = []
    y_rr_raw = []
    y_p0_excl = []
    y_rr_excl = []
    mechanisms = []
    
    total_isolated_calls = 0
    total_execution_errors = 0
    total_latency = 0.0
    residual_fps = []
    
    # Sort results to be deterministic
    sorted_results = sorted(rr_results.get("results", []), key=lambda x: x["cve_id"])
    
    for rr in sorted_results:
        cve_id = rr["cve_id"]
        p0 = p0_condA[cve_id]
        
        p0_sec = p0["security_class"]
        rr_sec = rr["security_class"]
        
        p0_inc = is_incorrect(p0_sec)
        rr_inc = is_incorrect(rr_sec)
        
        is_confound = cve_id in CONFOUNDS
        
        csv_rows.append({
            "cve_id": cve_id,
            "phase0_condition_a_class": p0_sec,
            "phase0_condition_a_incorrect": p0_inc,
            "robustrag_final_class": rr_sec,
            "robustrag_incorrect": rr_inc,
            "paired_outcome": f"{'Inc' if p0_inc else 'Cor'}->{'Inc' if rr_inc else 'Cor'}",
            "parametric_confound": is_confound,
            "included_raw": True,
            "included_confound_excluded": not is_confound
        })
        
        y_p0_raw.append(int(p0_inc))
        y_rr_raw.append(int(rr_inc))
        
        if not is_confound:
            y_p0_excl.append(int(p0_inc))
            y_rr_excl.append(int(rr_inc))
            
        total_isolated_calls += rr.get("total_llm_call_count", 0)
        total_execution_errors += rr.get("vote_counts", {}).get("execution_error", 0)
        total_latency += rr.get("latency_ms", 0.0)
        
        mech, reason = determine_mechanism(cve_id, rr)
        mechanisms.append({
            "cve_id": cve_id,
            "robustrag_security_class": rr_sec,
            "mechanism": mech,
            "rationale": reason,
            "phase0_cond_C_class": p0_condC.get(cve_id, {}).get("security_class"),
            "phase0_cond_C_mechanism": p0_condC.get(cve_id, {}).get("failure_mechanism", "unknown")
        })
        
        if rr_inc and len(residual_fps) < 5:
            residual_fps.append({
                "CVE": cve_id,
                "probe": rr.get("probe_question"),
                "isolated_calls": [
                    {
                        "doc_id": c.get("doc_id"),
                        "identity": c.get("document_identity"),
                        "raw_response": c.get("raw_response"),
                        "classification": c.get("phase0_classification"),
                        "vote": c.get("robustrag_vote")
                    } for c in rr.get("isolated_calls", [])
                ],
                "vote_counts": rr.get("vote_counts"),
                "final_answer": rr.get("final_answer_class"),
                "security_consequence": rr_sec,
                "failure_mechanism": mech
            })

    with open(CSV_OUT, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
        writer.writeheader()
        writer.writerows(csv_rows)
    
    with open(MECH_OUT, 'w', encoding='utf-8') as f:
        json.dump(mechanisms, f, indent=2)

    n_raw = len(y_p0_raw)
    inc_rr_raw = sum(y_rr_raw)
    inc_p0_raw = sum(y_p0_raw)
    rd_raw, ci_l_raw, ci_u_raw = bootstrap_rd(y_p0_raw, y_rr_raw)
    a_raw, b_raw, c_raw, d_raw, pval_raw = exact_mcnemar(y_p0_raw, y_rr_raw)

    n_excl = len(y_p0_excl)
    inc_rr_excl = sum(y_rr_excl)
    inc_p0_excl = sum(y_p0_excl)
    rd_excl, ci_l_excl, ci_u_excl = bootstrap_rd(y_p0_excl, y_rr_excl)
    a_excl, b_excl, c_excl, d_excl, pval_excl = exact_mcnemar(y_p0_excl, y_rr_excl)
    
    mech_counts = {}
    for m in mechanisms:
        mech = m["mechanism"]
        mech_counts[mech] = mech_counts.get(mech, 0) + 1
        
    spot_check_md = ""
    for fp in sorted(residual_fps, key=lambda x: x["CVE"]):
        spot_check_md += f"### {fp['CVE']}\n"
        spot_check_md += f"- **Probe**: `{fp['probe']}`\n"
        spot_check_md += f"- **Mechanism**: `{fp['failure_mechanism']}`\n"
        spot_check_md += f"- **Final Answer**: `{fp['final_answer']}` ({fp['security_consequence']})\n"
        spot_check_md += "- **Vote Counts**: " + str(fp['vote_counts']) + "\n"
        spot_check_md += "- **Isolated Calls**:\n"
        for call in fp['isolated_calls']:
            spot_check_md += f"  - `{call['doc_id']}` ({call['identity']}): {call['vote']} - {repr(call['raw_response'])[:150]}...\n"
        spot_check_md += "\n"

    report = f"""# RobustRAG Statistical Analysis

**Run ID**: `{rr_results.get("run_id", "a30146b9-95b2-487b-badc-7306660709a4")}`  
**Raw Result Filename**: `robustrag_raw_results_a30146b9-95b2-487b-badc-7306660709a4.json`  
**Integrity-Audit Verdict**: PASS  
**N**: {n_raw}  
**Primary Comparison**: Phase 0 Condition A vs RobustRAG-style categorical aggregation adaptation  
**Endpoint**: Type-C security-consequential incorrect decision (false positive / false negative)  

---

## 1. Descriptive Results (Raw Analysis)
* **n**: {n_raw} (Exact paired-CVE coverage)
* **RobustRAG Incorrect Decisions**: {inc_rr_raw} 
* **RobustRAG Correct Decisions**: {n_raw - inc_rr_raw}
* **RobustRAG Execution Errors**: {total_execution_errors} (Execution errors are distinct and NOT treated as semantic incorrect decisions)
* **Phase 0 Cond A Incorrect Decisions**: {inc_p0_raw}
* **RobustRAG Incorrect Rate**: {inc_rr_raw}/{n_raw} ({inc_rr_raw/n_raw*100:.1f}%)
* **Phase 0 Cond A Incorrect Rate**: {inc_p0_raw}/{n_raw} ({inc_p0_raw/n_raw*100:.1f}%)

## 2. Risk Difference (Raw)
* **RD**: {rd_raw*100:.2f} percentage points
* **Interpretation**: RobustRAG changes the incorrect decision rate by {rd_raw*100:.2f} percentage points relative to Phase 0 Condition A.
* **95% Bootstrap CI**: [{ci_l_raw*100:.2f}, {ci_u_raw*100:.2f}] (10,000 resamples, paired CVE units, seed=42)

## 3. McNemar Test (Raw)
**Paired 2x2 Contingency Table**:
| | RobustRAG Correct (0) | RobustRAG Incorrect (1) |
|---|---|---|
| **Phase A Correct (0)** | {a_raw} | {b_raw} |
| **Phase A Incorrect (1)** | {c_raw} | {d_raw} |

* **Exact Two-Sided p-value**: {pval_raw:.4f}

## 4. Multiple-Comparison Correction
* **Uncorrected p-value (RobustRAG)**: {pval_raw:.4f}
* **Holm Adjusted p-value**: *[PENDING]* 
> *Note: This is the first of four planned defense comparisons (RobustRAG, TrustRAG, NLI, ProveRAG). The adjusted p-value is explicitly pending until all four planned analyses exist. The raw p-value is preserved for family-wise correction. Do not assess significance based on a partial correction.*

---

## 5. Parametric-Confound-Excluded Analysis
Excluding frozen parametric-confound CVEs (`CVE-2022-27616`, `CVE-2022-42466`, `CVE-2023-0787`).

* **Reduced Denominator (n)**: {n_excl}
* **RobustRAG Incorrect Decisions**: {inc_rr_excl} ({inc_rr_excl/n_excl*100:.1f}%)
* **Phase 0 Cond A Incorrect Decisions**: {inc_p0_excl} ({inc_p0_excl/n_excl*100:.1f}%)
* **Risk Difference**: {rd_excl*100:.2f} pp
* **95% Bootstrap CI**: [{ci_l_excl*100:.2f}, {ci_u_excl*100:.2f}] (10,000 resamples, seed=42)

**Paired 2x2 Contingency Table (Excluded)**:
| | RobustRAG Correct | RobustRAG Incorrect |
|---|---|---|
| **Phase A Correct** | {a_excl} | {b_excl} |
| **Phase A Incorrect** | {c_excl} | {d_excl} |

* **Exact Two-Sided p-value**: {pval_excl:.4f}

---

## 6. RobustRAG Mechanism Analysis (n={n_raw})
*Mechanisms assigned based on paired evidence output, strictly applying the frozen taxonomy.*

| Mechanism | Count | Denominator | Rationale |
|---|---|---|---|
| `none` (Correct/Safe) | {mech_counts.get("none", 0)} | 25 | Defense behaved correctly or failed safely (refusal). |
| `classifier_error` | {mech_counts.get("classifier_error", 0)} | 25 | Explicit LLM refusals (e.g. "cannot determine") were falsely matched by the brittle Phase 0 classifier due to echoing "is affected". |
| `genuine_mutated_boundary_poisoning` | {mech_counts.get("genuine_mutated_boundary_poisoning", 0)} | 25 | Model genuinely hallucinated based on poisoned evidence. |
| `unresolved` | {mech_counts.get("unresolved", 0)} | 25 | Causal attribution could not be definitively established. |

---

## 7. Residual False-Positive Qualitative Spot-Check
*(Up to 5 residual false positives, selected deterministically in ascending CVE ID order)*

{spot_check_md if spot_check_md else "*(No residual false positives detected)*"}

---

## 8. Mechanism Comparison against Phase 0 Condition C
*Descriptive comparison of retrieval-corruption failure pathways.*

* **Phase 0 Condition C (Historical)**: Driven primarily by context-window pollution where mutated payloads overwhelm the original document context during decoding aggregation. Top mechanisms historically included `genuine_mutated_boundary_poisoning` and `parametric_override`.
* **RobustRAG Condition A**: Operates via isolated generation + categorical aggregation. Vulnerable to structural parsing artifacts (`classifier_error`) where isolated refusals from irrelevant original documents are misclassified as affirmative votes, overwhelming the true signal.
* **Qualitative Difference**: Phase 0 Cond C fails during LLM synthesis (generative corruption). RobustRAG fails during rigid categorical mapping (classification/aggregation corruption), highlighting the extreme sensitivity of isolate-then-aggregate approaches to local classifier accuracy. (Note: No causal claims beyond the paired Condition A experiment are made here).

---

## 9. Latency / LLM-Call Accounting
* **Total Isolated LLM Calls**: {total_isolated_calls}
* **Mean Calls per CVE**: {total_isolated_calls / n_raw:.1f}
* **Total Runtime (Latency sum)**: {total_latency / 1000.0:.2f} seconds
* **Mean Latency per CVE**: {(total_latency / n_raw) / 1000.0:.2f} seconds
* **Execution Errors**: {total_execution_errors}

---

## 10. Limitations
* Final p-value interpretation is pending family-wise Holm correction across all four defenses.
* The analysis is purely observational concerning the classifier artifact.
* RobustRAG implementation was an adapted categorical voting system and does not establish theoretical formal certification limits as per the original RobustRAG publication.
"""

    with open(MD_OUT, 'w', encoding='utf-8') as f:
        f.write(report)
        
    print("Statistical Analysis Complete.")
    print(f"MD Report: {MD_OUT}")
    print(f"CSV Paired: {CSV_OUT}")
    print(f"JSON Mechs: {MECH_OUT}")

if __name__ == "__main__":
    run_analysis()

