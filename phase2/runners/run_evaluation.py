import argparse, hashlib, json, sys
from dataclasses import asdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from phase2.claims.extraction import extract_claim
from phase2.knowledge_base.snapshot import load_manifest, validate_manifest
from phase2.knowledge_base.client import NvdSnapshot
from phase2.verifier.claimguard import verify

def frozen_ok():
    manifest=json.loads((ROOT/"phase1/validation/phase0_frozen_hashes.json").read_text())
    for name,expected in manifest.items():
        p=ROOT/"phase0/data"/name
        if hashlib.sha256(p.read_bytes()).hexdigest()!=expected: raise RuntimeError(f"frozen Phase 0 hash mismatch: {name}")

def main(argv=None):
    ap=argparse.ArgumentParser(); ap.add_argument("--source",choices=["A","C","phase1","all"],default="all")
    ap.add_argument("--dry-run",action="store_true"); ap.add_argument("--snapshot-root",type=Path)
    args=ap.parse_args(argv); frozen_ok()
    manifest_path=ROOT/"phase2/config/kb_snapshot_manifest.json"; manifest=load_manifest(manifest_path)
    selected=json.loads((ROOT/"phase0/data/selected_cves.json").read_text(encoding="utf-8"))
    meta_by_id={x["cve_id"]:x for x in selected}
    if args.dry_run:
        claim=extract_claim("Yes, envoy version 1.22.1 is affected by CVE-2022-29225, as the vulnerability exists in versions prior to 1.22.2.","CVE-2022-29225","envoyproxy","envoy")
        print(json.dumps({"mode":"fixture_only","claim":asdict(claim),"snapshot_status":manifest.get("status"),"primary_experiment":"NOT_RUN"},indent=2)); return
    if not args.snapshot_root: raise SystemExit("BLOCKED: provide authentic offline NVD snapshot via --snapshot-root")
    validate_manifest(manifest,args.snapshot_root); snapshot=NvdSnapshot(args.snapshot_root,manifest)
    records=json.loads((ROOT/"phase0/data/experiment_records.json").read_text(encoding="utf-8"))
    def process(name, rows, status):
        output=[]
        for r in rows:
            meta=meta_by_id[r["cve_id"]]
            claim=extract_claim(r["response_text"],r["cve_id"],meta.get("vendor"),meta.get("product")) if name.endswith("+CG") else None
            v=verify(claim,snapshot) if claim else None
            record={"cve":r["cve_id"],"condition":name,"source_record_id":r.get("run_id"),
              "generated_answer":r["response_text"],"ground_truth_answer_class":r.get("answer_class"),"mechanism":r.get("failure_mechanism"),
              "extracted_claim":v["claim"] if v else None,"extraction_status":claim.extraction_status if claim else "NOT_APPLIED",
              "cpe_resolution":v["provenance"].get("cpe_resolution") if v else "NOT_APPLIED","matched_cpe":v["provenance"].get("matched_cpe") if v else None,
              "nvd_applicability_branch":v["provenance"].get("applicability_branch") if v else None,
              "version_comparison":v["provenance"].get("version_comparison") if v else None,
              "verdict":v["provenance"]["verdict"] if v else "NOT_APPLIED","verdict_reason":v["provenance"]["reason"] if v else "NOT_APPLIED",
              "kb_snapshot_id":v["provenance"]["snapshot_id"] if v else manifest["snapshot_id"],"kb_record_identifier":claim.cve if claim else r["cve_id"],
              "implementation_version":v["provenance"]["implementation_version"] if v else None}
            if v: record["verification"]=v
            output.append(record)
        out=ROOT/"phase2/results/raw"/f"{name}_claimguard.json"; out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps({"status":status,"records":output},indent=2),encoding="utf-8")
        print(f"wrote {len(output)} records to {out}")
    sources=("A","C") if args.source=="phase1" else (args.source,)
    if args.source in ("A","C","all"):
        condition={"A":"Condition A","C":"Condition C"}.get(args.source)
        if condition is None:
            for label, cond in (("A","Condition A"),("C","Condition C")):
                rows=[r for r in records if r.get("query_type")=="Type C" and r.get("condition")==cond]
                process(label,rows,"PRIMARY")
                process(label+"+CG",rows,"PRIMARY_CLAIMGUARD")
            return
        selected_records=[r for r in records if r.get("query_type")=="Type C" and r.get("condition")==condition]
    else:
        data=json.loads((ROOT/"phase1/results/proverag_raw_results_20260917T163237Z_35f33821.json").read_text(encoding="utf-8"))
        selected_records=[{"cve_id":r["cve_id"],"response_text":r["raw_primary_answer"],"answer_class":r["security_consequence"],"condition":"Phase 1 ProveRAG secondary"} for r in data["results"]]
    if args.source=="phase1": process("phase1_secondary",selected_records,"SECONDARY_PHASE1")
    else:
        process(args.source,selected_records,"PRIMARY")
        process(args.source+"+CG",selected_records,"PRIMARY_CLAIMGUARD")
if __name__=="__main__": main()
