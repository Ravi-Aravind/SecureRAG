import json, math, random
from pathlib import Path

def paired_stats(a,b,resamples=10000,seed=42):
    if len(a)!=len(b) or not a: raise ValueError("paired binary arrays must have equal nonzero length")
    diffs=[y-x for x,y in zip(a,b)]; rd=sum(diffs)/len(diffs)
    rng=random.Random(seed); boots=[]
    for _ in range(resamples): boots.append(sum(diffs[rng.randrange(len(diffs))] for _ in diffs)/len(diffs))
    boots.sort(); lo=boots[int(.025*resamples)]; hi=boots[min(resamples-1,int(.975*resamples))]
    n10=sum(x==1 and y==0 for x,y in zip(a,b)); n01=sum(x==0 and y==1 for x,y in zip(a,b)); n=n10+n01
    p=1.0 if n==0 else min(1.0,2*sum(math.comb(n,k) for k in range(min(n10,n01)+1))/2**n)
    return {"risk_difference":rd,"bootstrap_95_ci":[lo,hi],"bootstrap_resamples":resamples,"seed":seed,"mcnemar_exact_two_sided_p":p,"discordant_pairs":[n10,n01]}

def holm_adjust(comparisons):
    ordered=sorted(comparisons.items(),key=lambda kv:kv[1]["mcnemar_exact_two_sided_p"])
    m=len(ordered); running=0.0; output={}
    for rank,(name,result) in enumerate(ordered):
        adjusted=min(1.0,(m-rank)*result["mcnemar_exact_two_sided_p"])
        running=max(running,adjusted); output[name]=running
    return output

def main():
    root=Path(__file__).resolve().parents[1]; raw=root/"results/raw"; derived=root/"results/derived"
    names=("A","A+CG","C","C+CG")
    if not all((raw/f"{n}_claimguard.json").is_file() for n in names): raise SystemExit("BLOCKED: complete primary matrix raw files are required")
    sets={n:json.loads((raw/f"{n}_claimguard.json").read_text(encoding="utf-8"))["records"] for n in names}
    if any(len(rows)!=25 for rows in sets.values()): raise SystemExit("BLOCKED: expected 25 paired CVEs per matrix row")
    for base,cg in (("A","A+CG"),("C","C+CG")):
        a={r["cve"]:r for r in sets[base]}; b={r["cve"]:r for r in sets[cg]}
        if set(a)!=set(b): raise SystemExit(f"BLOCKED: {base}/{cg} CVE sets differ")
        if any(r.get("verdict")!="NOT_APPLIED" for r in sets[base]) or any(r.get("verdict") not in {"SUPPORTED","CONTRADICTED","UNVERIFIABLE"} for r in sets[cg]):
            raise SystemExit(f"BLOCKED: invalid matrix condition state for {base}/{cg}")
    audit=json.loads((root/"results/audits/nvd_selected_cve_coverage.json").read_text(encoding="utf-8"))
    records_found={x["cve"] for x in audit["selected_cve_coverage"] if x["state"].startswith("FOUND")}
    applicability={x["cve"] for x in audit["selected_cve_coverage"] if x["state"]=="FOUND_APPLICABILITY"}
    metrics={"matrix":{},"statistical_comparisons":{},"statistical_notes":"Paired CVE error outcomes compare baseline incorrect claims with incorrect claims not flagged CONTRADICTED by CG. The estimand is a detection proxy; CG does not rewrite model answers. Holm correction covers the two reported paired comparisons (primary C and clean-control A)."}
    for base,cg in (("A","A+CG"),("C","C+CG")):
        baseline={r["cve"]:r for r in sets[base]}; guarded={r["cve"]:r for r in sets[cg]}
        total=len(baseline); wrong=[]; correct=[]; verdicts=[]
        for cve,row in baseline.items():
            is_wrong=row["ground_truth_answer_class"]=="affected"
            verdict=guarded[cve]["verdict"]
            (wrong if is_wrong else correct).append((cve,verdict))
            verdicts.append(verdict)
        verifiable_wrong=[(c,v) for c,v in wrong if v!="UNVERIFIABLE"]
        contradicted=sum(v=="CONTRADICTED" for _,v in verifiable_wrong)
        supported_correct=sum(v=="SUPPORTED" for _,v in correct)
        supported_wrong=sum(v=="SUPPORTED" for _,v in wrong)
        contradicted_correct=sum(v=="CONTRADICTED" for _,v in correct)
        supported_total=supported_correct+supported_wrong
        unv=sum(v=="UNVERIFIABLE" for v in verdicts)
        metrics["matrix"][base]={"total":total,"correct":len(correct),"incorrect":len(wrong),"claimguard":"NOT_APPLIED"}
        metrics["matrix"][cg]={"total":total,"correct":len(correct),"incorrect":len(wrong),
          "verifiable_incorrect":len(verifiable_wrong),"unverifiable":unv,"contradicted_incorrect":contradicted,
          "contradicted_total":contradicted+contradicted_correct,"contradicted_correct":contradicted_correct,
          "supported_correct":supported_correct,"supported_incorrect":supported_wrong,
          "supported_total":supported_total,"primary_detection_rate":contradicted/len(verifiable_wrong) if verifiable_wrong else None,
          "unverifiable_rate":unv/total,"kb_record_coverage":sum(c in records_found for c in baseline)/total,
          "kb_applicability_coverage":sum(c in applicability for c in baseline)/total,
          "claim_verifiability_rate":sum(v!="UNVERIFIABLE" for v in verdicts)/total,
          "supported_precision":supported_correct/supported_total if supported_total else None,
          "contradicted_recall_all_incorrect":contradicted/len(wrong) if wrong else None,
          "false_verification_rate":contradicted_correct/len(correct) if correct else None,
          "abstention_rate":unv/total,"residual_incorrect_after_detection":sum(v!="CONTRADICTED" for _,v in wrong)}
        by_mech={}
        for mechanism in sorted({r.get("mechanism") or "none" for r in sets[cg]}):
            group=[r for r in sets[cg] if (r.get("mechanism") or "none")==mechanism]
            bad=[r for r in group if r["ground_truth_answer_class"]=="affected"]
            valid=[r for r in bad if r["verdict"]!="UNVERIFIABLE"]
            by_mech[mechanism]={"claims":len(group),"incorrect":len(bad),"verifiable_incorrect":len(valid),
              "contradicted_incorrect":sum(r["verdict"]=="CONTRADICTED" for r in valid),
              "detection_rate":sum(r["verdict"]=="CONTRADICTED" for r in valid)/len(valid) if valid else None}
        metrics["matrix"][cg]["mechanism_specific"]=by_mech
        base_errors=[int(baseline[c]["ground_truth_answer_class"]=="affected") for c in sorted(baseline)]
        residual=[int(baseline[c]["ground_truth_answer_class"]=="affected" and guarded[c]["verdict"]!="CONTRADICTED") for c in sorted(baseline)]
        metrics["statistical_comparisons"][base+"_vs_"+cg]=paired_stats(base_errors,residual)
    adjusted=holm_adjust(metrics["statistical_comparisons"])
    for name,p in adjusted.items(): metrics["statistical_comparisons"][name]["holm_adjusted_p"] = p
    derived.mkdir(parents=True,exist_ok=True); out=derived/"metrics.json"; out.write_text(json.dumps(metrics,indent=2),encoding="utf-8")
    print(json.dumps(metrics,indent=2))
if __name__=="__main__": main()
