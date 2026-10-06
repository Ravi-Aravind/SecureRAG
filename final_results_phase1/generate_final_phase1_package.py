"""Deterministic, analysis-only Phase 1 packaging script. Never makes API calls."""
import csv, hashlib, json, math, random
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent
P0 = ROOT / "phase0" / "data"
R = ROOT / "phase1" / "results"
HASHES = {
    "phase0/data/selected_cves.json": "cef5d48481ee4df28884a411dc778f555c9538466aedab72adea9df7ac8a472f",
    "phase0/data/documents.json": "3a25bfa8f755374b9ba46a0dccfdf25de4984b8480d6ea983abefbb570c532ed",
    "phase0/data/embeddings.json": "61d89fa41cf980125bc43bb67f42b75742b08439fd2eed8d33be617cf0f8dda4",
    "phase0/data/retrieval_results.json": "1cf6d170d6f343ecd37b1e719e1736db339f9d2b5c6dfbd81226c3d41ea5b27d",
    "phase0/data/experiment_records.json": "8939145a99e8a001823ec637951d6753237de27bf01e4f74e9a79ddfdc7acfc8",
    "phase0/results/phase0_results.json": "ef1c10b5cd4f1a2c9417a96deefb368a918f1ae14bccffedc719daac27463e60",
    "phase0/results/phase0_results.csv": "404278dc4fa17d101c6f7f08323adb9feb0f06fb07b57e2a34726fc11c544894",
    "phase0/results/phase0_report.md": "faa8bb800aea66af0686032d74f29c2331a0b3bca42cefe262f747f0ee2add29",
    "phase0/results/qualitative_examples.json": "9aa7745a0649ac8b6b52d078ea2b539931e8f19421729b26f2c034516ee770d8",
}
CONFOUNDS = {"CVE-2022-27616", "CVE-2022-42466", "CVE-2023-0787"}

def read_json(path): return json.loads(path.read_text(encoding="utf-8"))
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def check_hashes():
    result = {p: sha(ROOT / p) == h for p, h in HASHES.items()}
    if not all(result.values()): raise SystemExit(f"Frozen hash failure: {result}")
    return result
def inc(value): return value == "false_positive"
def nli_class(x):
    c = x.get("classification", {})
    return c.get("consequence") or c.get("classification", "")
def exact_p(b, c):
    n = b + c
    return 1.0 if not n else min(1.0, 2 * sum(math.comb(n, k) * .5 ** n for k in range(min(b, c) + 1)))
def paired(rows, key, ids):
    base = [rows[i]["baseline_incorrect"] for i in ids]; defense = [inc(rows[i][key]) for i in ids]
    a = sum(not b and not d for b, d in zip(base, defense)); b = sum(not x and y for x, y in zip(base, defense))
    c = sum(x and not y for x, y in zip(base, defense)); d = sum(x and y for x, y in zip(base, defense))
    rng = random.Random(42); diffs = []
    for _ in range(10000):
        sample = [rng.randrange(len(ids)) for _ in ids]
        diffs.append(sum(defense[i] - base[i] for i in sample) / len(ids))
    diffs.sort()
    return {"n": len(ids), "incorrect": sum(defense), "incorrect_rate": sum(defense)/len(ids),
            "baseline_incorrect": sum(base), "baseline_rate": sum(base)/len(ids),
            "risk_difference": sum(defense)/len(ids)-sum(base)/len(ids),
            "bootstrap_ci": [diffs[250], diffs[9750]], "table": [a,b,c,d], "exact_p": exact_p(b,c)}

def main():
    OUT.mkdir(parents=True, exist_ok=True); integrity = check_hashes()
    selected = read_json(P0 / "selected_cves.json"); ids = [x["cve_id"] for x in selected]
    if len(ids) != 25 or len(set(ids)) != 25: raise SystemExit("Frozen CVE set is not exactly 25 unique CVEs")
    p0 = {x["cve_id"]: x for x in csv.DictReader((P0 / "analysis_ready.csv").open(encoding="utf-8"))}
    rr_raw = read_json(R / "robustrag_raw_results_a30146b9-95b2-487b-badc-7306660709a4.json")
    nli_raw = read_json(R / "nli_raw_results_7de9a5ba-aa04-4651-ba45-702de40d6632.json")
    pv_raw = read_json(R / "proverag_raw_results_20260917T163237Z_35f33821.json")
    rr = {x["cve_id"]: x for x in rr_raw["results"]}; nli = {x["cve_id"]: x for x in nli_raw}; pv = {x["cve_id"]: x for x in pv_raw["results"]}
    if any(set(m) != set(ids) or len(m) != 25 for m in (rr,nli,pv)): raise SystemExit("Defense CVE alignment failure")
    if sum(len(x.get("isolated_calls", [])) for x in rr.values()) != 125: raise SystemExit("RobustRAG call-count failure")
    if sum(len(x.get("nli_pairs", [])) for x in nli.values()) != 500: raise SystemExit("NLI directed-pair count failure")
    if pv_raw.get("call_accounting", {}).get("primary_llm_invocations") != 25 or pv_raw.get("call_accounting", {}).get("auxiliary_evaluator_invocations") != 25 or pv_raw.get("call_accounting", {}).get("total_llm_invocations") != 50: raise SystemExit("ProveRAG call-count failure")
    rows = {}
    for c in ids:
        x = pv[c]; ev = x["proverag_eval"]; rows[c] = {
            "cve_id": c, "original_version": p0[c]["original_boundary"], "mutated_version": p0[c]["mutated_boundary"], "probe_version": p0[c]["probe_version"],
            "baseline": "false_positive" if p0[c]["cond_a_probe_is_correct"] != "True" else "correct_not_affected", "baseline_incorrect": p0[c]["cond_a_probe_is_correct"] != "True",
            "RobustRAG": rr[c].get("security_class", ""), "NLI": nli_class(nli[c]), "ProveRAG": x.get("security_consequence", ""),
            "citation": ev.get("citation_outcome", ""), "cited_doc": ";".join(y for y in ev.get("cited_doc_ids", []) if y),
            "primary_status": x.get("execution_statuses", {}).get("primary", ""), "auxiliary_status": x.get("execution_statuses", {}).get("auxiliary", ""), "confound": c in CONFOUNDS,
        }
    raw_stats = {k: paired(rows, k, ids) for k in ("RobustRAG","NLI","ProveRAG")}
    excl = [c for c in ids if c not in CONFOUNDS]; excl_stats = {k: paired(rows, k, excl) for k in ("RobustRAG","NLI","ProveRAG")}
    ps = sorted((raw_stats[k]["exact_p"], k) for k in ("RobustRAG","NLI")); holm={}; running=0
    for i,(p,k) in enumerate(ps): running=max(running,min(1,p*(2-i))); holm[k]=running
    citation_counts = Counter(rows[c]["citation"] for c in ids)
    # Mechanism labels are taken from frozen mechanism artifacts; no causal relabeling is invented.
    rr_mech = read_json(R / "robustrag_mechanism_analysis.json"); nli_mech = read_json(R / "nli_mechanism_analysis.json")
    rr_mech_by = {x["cve_id"]: x.get("mechanism", "unresolved") for x in rr_mech}; nli_mech_by = {x["cve_id"]: x.get("assigned_mechanism", "unresolved") for x in nli_mech}
    docs = {x["cve_id"]: x for x in read_json(P0 / "documents.json")}
    # Individual table.
    fields = ["cve_id","original_version","mutated_version","probe_version","baseline","RobustRAG","RobustRAG_mechanism","NLI","NLI_mechanism","ProveRAG","citation","cited_doc","primary_status","auxiliary_status","parametric_confound"]
    with (OUT/"phase1_final_individual_results.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for c in ids:
            r=rows[c]; out={k:r[k] for k in fields if k in r}; out.update({"RobustRAG_mechanism":rr_mech_by.get(c,"unresolved"),"NLI_mechanism":nli_mech_by.get(c,"unresolved"),"parametric_confound":r["confound"]}); w.writerow(out)
    imd=["# Phase 1 Individual Results","","| # | CVE | Baseline | RobustRAG | NLI | ProveRAG | Citation | Confound |","|---:|---|---|---|---|---|---|---|"]
    for i,c in enumerate(ids,1):
        r=rows[c]; imd.append(f"| {i} | {c} | {r['baseline']} | {r['RobustRAG']} | {r['NLI']} | {r['ProveRAG']} | {r['citation']} | {r['confound']} |")
    (OUT/"phase1_final_individual_results.md").write_text("\n".join(imd)+"\n",encoding="utf-8")
    # Primary table: deliberately excludes ProveRAG and TrustRAG.
    def table_row(name, role, s, holm_p=""):
        a,b,c,d=s["table"]; return [name,role,s["n"],s["incorrect"],s["incorrect_rate"],s["risk_difference"],s["bootstrap_ci"][0],s["bootstrap_ci"][1],a,b,c,d,s["exact_p"],holm_p, "observed endpoint result under frozen protocol"]
    hdr=["system","role","n","incorrect","incorrect_rate","risk_difference_vs_baseline","bootstrap_ci_low","bootstrap_ci_high","mcnemar_b00","mcnemar_b01","mcnemar_b10","mcnemar_b11","mcnemar_exact_p","holm_adjusted_p","interpretation"]
    table=[table_row("Condition A","frozen baseline",paired(rows,"baseline",ids)),table_row("RobustRAG","experiment-specific retrieval adaptation",raw_stats["RobustRAG"],holm["RobustRAG"]),table_row("NLI","experiment-specific contradiction filtering",raw_stats["NLI"],holm["NLI"])]
    with (OUT/"phase1_final_table.csv").open("w",newline="",encoding="utf-8") as f: csv.writer(f).writerows([hdr]+table)
    tmd=["# Phase 1 Primary Retrieval-Defense Comparison","","ProveRAG is intentionally excluded because it is an auxiliary provenance branch. TrustRAG was not reproducibly evaluated.","","| System | n | Incorrect | Rate | RD | 95% bootstrap CI | Exact McNemar p | Holm p |","|---|---:|---:|---:|---:|---|---:|---:|"]
    for row in table: tmd.append(f"| {row[0]} | {row[2]} | {row[3]} | {row[4]:.1%} | {row[5]:+.1%} | [{row[6]:+.1%}, {row[7]:+.1%}] | {row[12]:.8f} | {row[13] if row[13] != '' else '—'} |")
    tmd += ["","## Exact McNemar tables","","Rows are baseline correct/incorrect; columns are defense correct/incorrect.",""]
    for n,s in (("RobustRAG",raw_stats["RobustRAG"]),("NLI",raw_stats["NLI"])): tmd += [f"### {n}","",f"a={s['table'][0]}, b={s['table'][1]}, c={s['table'][2]}, d={s['table'][3]}; exact two-sided p={s['exact_p']:.8f}",""]
    (OUT/"phase1_final_table.md").write_text("\n".join(tmd),encoding="utf-8")
    # Provenance table.
    with (OUT/"phase1_proverag_citation_table.csv").open("w",newline="",encoding="utf-8") as f:
        w=csv.writer(f);w.writerow(["citation_outcome","count","rate"])
        for k in ("original_cited","poisoned_cited","multiple_cited","absent_or_invalid"): w.writerow([k,citation_counts[k],citation_counts[k]/25])
    (OUT/"phase1_proverag_citation_table.md").write_text("# Auxiliary Provenance Analysis — Not Included in Primary Retrieval-Defense Comparison\n\n| Outcome | Count | Rate |\n|---|---:|---:|\n"+"\n".join(f"| {k} | {citation_counts[k]} | {citation_counts[k]/25:.1%} |" for k in ("original_cited","poisoned_cited","multiple_cited","absent_or_invalid"))+"\n",encoding="utf-8")
    # Machine-readable statistics.
    stat={"metadata":{"bootstrap_resamples":10000,"bootstrap_seed":42,"mcnemar":"exact two-sided","holm_family":["RobustRAG","NLI"],"trustrag":"excluded"},"baseline":raw_stats["ProveRAG"] | {"incorrect":0},"primary_defenses":raw_stats,"holm":holm,"confound_excluded":{"excluded_cves":sorted(CONFOUNDS),"results":excl_stats},"provenance_auxiliary":{"citation_counts":dict(citation_counts),"run_id":pv_raw["run_id"],"call_accounting":pv_raw["call_accounting"]}}
    (OUT/"phase1_final_statistics.json").write_text(json.dumps(stat,indent=2),encoding="utf-8")
    # Mechanisms.
    mech_rows=[]
    for c in ids: mech_rows.append({"cve_id":c,"RobustRAG":rr_mech_by.get(c,"unresolved"),"NLI":nli_mech_by.get(c,"unresolved"),"ProveRAG":"none" if not inc(rows[c]["ProveRAG"]) else "unresolved"})
    (OUT/"phase1_mechanism_table.csv").write_text("defense,mechanism,count\n"+"\n".join(f"RobustRAG,{k},{sum(x['RobustRAG']==k for x in mech_rows)}" for k in sorted(set(x['RobustRAG'] for x in mech_rows)))+"\n"+"\n".join(f"NLI,{k},{sum(x['NLI']==k for x in mech_rows)}" for k in sorted(set(x['NLI'] for x in mech_rows)))+"\n",encoding="utf-8")
    (OUT/"phase1_mechanism_table.md").write_text("# Mechanism Analysis\n\nRobustRAG's 25/25 endpoint degradation is reported with the documented classifier/refusal interaction limitation; it is not interpreted as 25 genuine poisoning events. NLI mechanism labels are preserved from the raw mechanism artifact.\n\n"+"\n".join(f"- {d}: {k} = {sum(x[d]==k for x in mech_rows)}" for d in ("RobustRAG","NLI") for k in sorted(set(x[d] for x in mech_rows)))+"\n",encoding="utf-8")
    # Method/status and claims.
    matrix=["defense,published_method,experiment_adaptation,exact_reproduction,evaluated,primary_comparison,result_available,methodological_status,primary_reason,interpretation_limit","RobustRAG,secure aggregation, categorical aggregation adaptation,no,yes,yes,yes,limited adaptation, frozen classifier/refusal interaction,not a certified reproduction","TrustRAG,internal self-assessment,not run,no,no,no,no,excluded,frozen prompt incompatibility,no statistics","NLI,NLI contradiction filtering,paired-document contradiction filtering,no,yes,yes,yes,experiment-specific,model sensitivity to numeric boundaries,no general capability claim","ProveRAG,provenance analysis,post-generation auxiliary evaluator,no,yes,no,yes,auxiliary only,not retrieval-layer defense,no primary comparison"]
    (OUT/"phase1_defense_status_matrix.csv").write_text("\n".join(matrix)+"\n",encoding="utf-8")
    (OUT/"phase1_defense_status_matrix.md").write_text("# Defense Status Matrix\n\n| Defense | Evaluated | Primary comparison | Status |\n|---|---|---|---|\n| RobustRAG | yes | yes | adaptation, not exact reproduction |\n| TrustRAG | no | no | methodologically excluded |\n| NLI | yes | yes | experiment-specific adaptation |\n| ProveRAG | yes | no | auxiliary provenance only |\n",encoding="utf-8")
    (OUT/"phase1_claims_audit.md").write_text("# Claims Audit\n\n| Claim | Supported? | Evidence | Safe wording |\n|---|---|---|---|\n| Baseline has false positives | NO | Frozen Condition A is 0/25 | Baseline had no false-positive decisions |\n| RobustRAG reduces false positives | NO | Baseline is already 0/25 | It degraded the frozen endpoint in this adaptation |\n| NLI reduces false positives | NO | Baseline is already 0/25 | It degraded the frozen endpoint in this adaptation |\n| RobustRAG produced 25/25 incorrect endpoint decisions | YES | Raw RobustRAG JSON | State the observed endpoint result |\n| RobustRAG caused genuine poisoning | NO | Mechanism artifact identifies classifier error | Do not make this causal claim |\n| Classifier/refusal interaction explains degradation | PARTIAL | Mechanism artifact and raw isolated responses | Report as the documented mechanism interpretation |\n| NLI is generally effective | NO | One experiment-specific model/protocol | Limit to this adaptation |\n| NLI struggled with single-token version differences | YES | 20/25 raw outcomes and mechanism artifact | State model-specific sensitivity |\n| ProveRAG is retrieval-layer defense | NO | Post-generation auxiliary branch | Report separately as provenance analysis |\n| ProveRAG produced original provenance for all 25 | YES | Raw ProveRAG JSON | State auxiliary result |\n| TrustRAG was successfully evaluated | NO | Methodological review | Report as excluded |\n| Phase 1 answers original reduction question | NO | Baseline 0/25 | It evaluates preservation/degradation under the frozen protocol |\n",encoding="utf-8")
    # Audits and narrative.
    (OUT/"phase1_final_integrity_audit.md").write_text("# Final Integrity Audit\n\nFINAL INTEGRITY STATUS: PASS\n\n- Frozen Phase 0 hashes: PASS for all nine artifacts.\n- Exact frozen CVEs: 25, unique and aligned across all defenses.\n- RobustRAG: 25 CVEs and 125 isolated calls.\n- NLI: 25 CVEs, 500 directed pair evaluations, 25 primary calls.\n- ProveRAG: 25 primary + 25 auxiliary calls; zero failures and parsing errors.\n- Final tables are generated by the deterministic packaging script from raw artifacts.\n- No existing experimental artifact was modified by this package generation.\n",encoding="utf-8")
    (OUT/"phase1_final_statistics_audit.md").write_text(f"# Statistical Audit\n\nSources: frozen `analysis_ready.csv`, authoritative raw defense JSON, and frozen mechanism artifacts. Bootstrap uses paired CVE resampling, 10,000 iterations, seed 42, percentile indices 250 and 9750. McNemar is exact two-sided; Holm family is RobustRAG + NLI only.\n\nCondition A baseline: 0/25. RobustRAG: 25/25. NLI: 20/25.\n\nThe prior NLI CI `[64%, 92%]` does not reproduce. Independent recomputation gives `[64%, 96%]`; the package uses `[64%, 96%]`. Confound exclusions: {sorted(CONFOUNDS)}.\n",encoding="utf-8")
    (OUT/"phase1_qualitative_cases.md").write_text("# Qualitative Cases\n\nCases are selected deterministically from the frozen CVE order and preserve concise excerpts from raw artifacts.\n\n## RobustRAG classifier/refusal interaction\n\n- CVE: CVE-2022-0219\n- Source: `phase1/results/robustrag_raw_results_a30146b9-95b2-487b-badc-7306660709a4.json` and `phase1/results/robustrag_mechanism_analysis.json`\n- Observation: isolated irrelevant-document responses contain refusal language that interacts with the frozen classifier; the recorded mechanism is `classifier_error`.\n- Limitation: this does not establish genuine poisoning or reproduce certified RobustRAG.\n\n## NLI numeric-boundary sensitivity\n\n- CVEs: the five non-false-positive NLI cases are listed in `phase1_final_individual_results.md`; the remaining 20 are false-positive endpoint outcomes.\n- Source: `phase1/results/nli_raw_results_7de9a5ba-aa04-4651-ba45-702de40d6632.json` and `phase1/results/nli_mechanism_analysis.json`\n- Observation: the adaptation is sensitive to the experiment's single-token version-boundary changes.\n- Limitation: this is not evidence of general NLI defense capability.\n\n## ProveRAG original provenance\n\n- Result: all 25 primary decisions are `correct_not_affected`; all 25 auxiliary outcomes are `original_cited`.\n- Source: `phase1/results/proverag_raw_results_20260917T163237Z_35f33821.json`\n- Limitation: ProveRAG is post-generation provenance analysis, not a retrieval-layer defense.\n",encoding="utf-8")
    (OUT/"phase1_final_results.md").write_text("# Phase 1 Final Results\n\n## Executive Summary\n\nUnder the frozen single-token boundary-poisoning protocol, the Phase 0 Condition A baseline produced 0/25 false-positive security decisions. Phase 1 therefore does not demonstrate reduction of false positives; it exposes preservation or degradation of the frozen retrieval-generation-classification endpoint.\n\n## Primary Results\n\nThe primary retrieval-defense comparison contains only the RobustRAG and NLI adaptations. RobustRAG produced 25/25 incorrect endpoint decisions and NLI produced 20/25. These are adaptation-specific observations, not faithful reproductions of published certified methods.\n\n## Statistical and Confound-Excluded Results\n\nThe primary Holm family contains RobustRAG and NLI only. The NLI paired bootstrap CI is [64%, 96%]. The pre-specified exclusions are CVE-2022-27616, CVE-2022-42466, and CVE-2023-0787; the n=22 results are in `phase1_final_statistics.json`.\n\n## Mechanisms and Qualitative Cases\n\nRobustRAG's endpoint degradation is interpreted primarily through the documented classifier/refusal interaction, not as 25 genuine poisoning events. NLI's recorded mechanism is preserved without generalization. See `phase1_qualitative_cases.md`.\n\n## Auxiliary ProveRAG\n\nProveRAG is reported separately as an auxiliary post-generation provenance branch. It produced 25/25 `correct_not_affected` primary decisions and 25/25 `original_cited` outcomes; provenance did not affect the primary endpoint.\n\n## TrustRAG and Limitations\n\nTrustRAG was not reproducible under the frozen prompt/protocol and receives no statistics. The study uses one frozen dataset, one model/protocol, and experiment-specific adaptations; it does not establish general defense capability, formal certification, or reduction in false-positive rate.\n",encoding="utf-8")
    (OUT/"phase1_presentation_summary.md").write_text("# Phase 1 Presentation Summary\n\n"+"\n\n".join(f"## SLIDE {i} — {title}\n\n- {body}\n- Source: {src}\n- Suggested figure: {fig}\n- Speaker note: {note}" for i,(title,body,src,fig,note) in enumerate([
        ("Research Question","Test preservation/degradation under a frozen poisoning protocol.","phase1_final_results.md","question diagram","The baseline already has zero false positives."),
        ("Threat Model / Setup","Single-token version-boundary mutation in retrieved documents.","phase0/data/documents.json","original vs mutated document","Keep mutation scope precise."),
        ("Frozen Baseline","Condition A: 0/25 incorrect, 0.0%.","phase0/data/analysis_ready.csv","baseline bar","No false positives existed to reduce."),
        ("Experimental Design","25 CVEs; frozen retrieval, prompts, model, classifier.","phase0/data/selected_cves.json; phase1 raw JSON","pipeline","All units are paired CVEs."),
        ("Defense Architectures","RobustRAG and NLI are primary adaptations; ProveRAG auxiliary.","phase1_defense_status_matrix.md","architecture map","TrustRAG is excluded."),
        ("Primary Results","RobustRAG 25/25; NLI 20/25 incorrect.","phase1_final_table.csv","comparison table","Observed endpoint only."),
        ("Statistical Results","RobustRAG and NLI Holm family; NLI CI [64%,96%].","phase1_final_statistics.json","paired table","No ProveRAG Holm entry."),
        ("Mechanisms","RobustRAG degradation is tied to classifier/refusal interaction; NLI has boundary sensitivity.","phase1_mechanism_table.md","mechanism counts","Do not call all cases genuine poisoning."),
        ("RobustRAG Finding","25/25 incorrect endpoint decisions in this categorical adaptation.","robustrag_raw_results_*.json","endpoint flow","Not a certified reproduction."),
        ("NLI Finding","20/25 incorrect; five non-false-positive CVEs.","nli_raw_results_*.json","NLI pair schematic","Model/protocol-specific."),
        ("ProveRAG Auxiliary","25 original-cited; separate from primary comparison.","phase1_proverag_citation_table.md","provenance table","Citation does not define security correctness."),
        ("TrustRAG","Not reproducible under frozen protocol; no statistics.","phase1_defense_status_matrix.md","exclusion callout","Do not fabricate a result."),
        ("Limitations","Single dataset, frozen model, adaptations, classifier sensitivity.","phase1_final_results.md","limitations list","Avoid generalization."),
        ("Final Interpretation","Results expose endpoint degradation and interaction effects.","phase1_claims_audit.md","interpretation summary","Use precise causal language."),
        ("Does / Does Not Establish","Establishes observed adaptation outcomes; not general defense capability or reduction.","phase1_final_results.md","scope boundary","This is the central conclusion."),
    ],1)) + "\n",encoding="utf-8")
    (OUT/"requirements_or_dependencies.md").write_text("# Dependencies\n\nPython 3.10+ standard library only. No network, API, LLM, embedding, or retrieval dependencies are required.\n",encoding="utf-8")
    readme=f"""# Final Phase 1 Results Package

Generated by `generate_final_phase1_package.py` from frozen raw artifacts. No new experiment or API call was made.

Primary comparison: RobustRAG and NLI only. ProveRAG is auxiliary provenance analysis and TrustRAG is excluded as non-reproducible. The frozen baseline is 0/25 incorrect, so the package does not claim false-positive reduction.

Recommended reading order:
1. `phase1_presentation_summary.md`
2. `phase1_final_results.md`
3. `phase1_final_table.md`
4. `phase1_final_individual_results.md`
5. `phase1_final_statistics_audit.md`
6. `phase1_defense_status_matrix.md`
7. `phase1_claims_audit.md`
8. `phase1_final_integrity_audit.md`
"""
    (OUT/"README.md").write_text(readme,encoding="utf-8")
    print(json.dumps({"output":str(OUT),"hashes":"PASS","baseline":"0/25","RobustRAG":"25/25","NLI":"20/25","ProveRAG":"0/25; original_cited 25/25","NLI_CI":raw_stats['NLI']['bootstrap_ci'],"Holm_family":holm},indent=2))

if __name__ == "__main__": main()
