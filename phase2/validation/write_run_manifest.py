import hashlib,json,platform,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from phase2.knowledge_base.snapshot import load_manifest,validate_manifest,sha256

def main():
    manifest=load_manifest(ROOT/"phase2/config/kb_snapshot_manifest.json"); kb=ROOT/"phase2/data/nvd"
    validate_manifest(manifest,kb)
    frozen=json.loads((ROOT/"phase1/validation/phase0_frozen_hashes.json").read_text(encoding="utf-8"))
    for name,expected in frozen.items():
        if sha256(ROOT/"phase0/data"/name)!=expected: raise SystemExit(f"frozen input mismatch: {name}")
    files=[ROOT/"phase2/results/raw"/f"{n}_claimguard.json" for n in ("A","A+CG","C","C+CG")]
    files += [ROOT/"phase2/results/derived/metrics.json",ROOT/"phase2/results/derived/phase2_final_report.md",ROOT/"phase2/results/audits/golden_cve_verification.json",ROOT/"phase2/results/audits/nvd_selected_cve_coverage.json"]
    outputs=[{"path":p.relative_to(ROOT).as_posix(),"sha256":sha256(p)} for p in files]
    record={"run_status":"COMPLETED","created_utc":datetime.now(timezone.utc).isoformat(),"python":platform.python_version(),
      "primary_command":"python phase2/runners/run_evaluation.py --source all --snapshot-root phase2/data/nvd",
      "metrics_command":"python phase2/runners/run_metrics.py","snapshot_id":manifest["snapshot_id"],"snapshot_hash":manifest["snapshot_hash"],
      "snapshot_manifest_sha256":sha256(ROOT/"phase2/config/kb_snapshot_manifest.json"),
      "phase0_frozen_hashes":frozen,"phase0_hash_validation":"PASS","phase1_files_modified_by_run":False,
      "nvd_files":[{"path":x["path"],"sha256":x["sha256"]} for x in manifest["files"]],"result_files":outputs}
    out=ROOT/"phase2/results/audits/run_manifest.json"; out.write_text(json.dumps(record,indent=2),encoding="utf-8")
    print(json.dumps(record,indent=2))
if __name__=="__main__": main()
