import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from phase2.claims.extraction import extract_claim
from phase2.knowledge_base.snapshot import load_manifest,validate_manifest
from phase2.knowledge_base.client import NvdSnapshot
from phase2.verifier.claimguard import verify

def main():
    manifest=load_manifest(ROOT/"phase2/config/kb_snapshot_manifest.json"); kbroot=ROOT/"phase2/data/nvd"
    validate_manifest(manifest,kbroot); snapshot=NvdSnapshot(kbroot,manifest)
    selected=json.loads((ROOT/"phase0/data/selected_cves.json").read_text(encoding="utf-8"))
    meta=next(x for x in selected if x["cve_id"]=="CVE-2022-29225")
    records=json.loads((ROOT/"phase0/data/experiment_records.json").read_text(encoding="utf-8"))
    source=next(x for x in records if x["run_id"]=="CVE-2022-29225_Condition_C_Type_C")
    claim=extract_claim(source["response_text"],source["cve_id"],meta["vendor"],meta["product"])
    result={"source_record_id":source["run_id"],"generated_answer":source["response_text"],"verification":verify(claim,snapshot)}
    out=ROOT/"phase2/results/audits/golden_cve_verification.json"; out.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2))
if __name__=="__main__": main()
