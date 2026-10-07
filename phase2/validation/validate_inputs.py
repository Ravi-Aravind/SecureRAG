import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def validate():
    manifest=json.loads((ROOT/"phase1/validation/phase0_frozen_hashes.json").read_text())
    bad=[]
    for name,digest in manifest.items():
        actual=hashlib.sha256((ROOT/"phase0/data"/name).read_bytes()).hexdigest()
        if actual!=digest: bad.append(name)
    records=json.loads((ROOT/"phase0/data/selected_cves.json").read_text())
    if len(records)!=25 or len({r['cve_id'] for r in records})!=25: bad.append("selected_cves.json:count-or-duplicates")
    if bad: raise AssertionError(bad)
    return {"phase0_hashes":"PASS","selected_cves":25,"phase1_final_authority":"final_results_phase1/phase1_final_results.md"}
if __name__=="__main__": print(validate())
