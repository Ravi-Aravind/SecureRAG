import hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from phase2.knowledge_base.snapshot import load_manifest,sha256,validate_nvd_meta

def main():
    cfg=ROOT/"phase2/config/kb_snapshot_manifest.json"; manifest=load_manifest(cfg)
    root=ROOT/"phase2/data/nvd"; audit=json.loads((ROOT/"phase2/results/audits/nvd_selected_cve_coverage.json").read_text(encoding="utf-8"))
    items=[]; meta_items=[]
    for year in (2022,2023,2024):
        stem=f"nvdcve-2.0-{year}"; feed=root/(stem+".json.gz"); meta=root/(stem+".meta")
        official=validate_nvd_meta(feed,meta)
        records=next(f["record_count"] for f in audit["files"] if f["path"]==feed.name)
        items.append({"path":feed.name,"sha256":sha256(feed),"record_count":records,"nvd_meta":meta.name,"official_uncompressed_sha256":official["sha256"],"official_uncompressed_size":int(official["size"]),"nvd_last_modified":official["lastModifiedDate"]})
        meta_items.append({"path":meta.name,"sha256":sha256(meta)})
    coverage=audit["selected_cve_coverage"]
    if len(coverage)!=25 or any(not x["state"].startswith("FOUND") for x in coverage): raise SystemExit("coverage failure: cannot pin incomplete selected CVE set")
    combined=hashlib.sha256("\n".join(x["sha256"] for x in items).encode("ascii")).hexdigest()
    manifest.update({"snapshot_id":f"nvd-json20-2022-2024-sha256-{combined}","status":"READY","validation_status":"PASSED",
      "acquisition_timestamp_utc":datetime.now(timezone.utc).isoformat(),"record_count":audit["total_records"],
      "files":items,"metadata_files":meta_items,"selected_cve_coverage":{"selected_count":25,"found_count":25,
      "with_applicability":sum(x["state"]=="FOUND_APPLICABILITY" for x in coverage),
      "without_applicability":[x["cve"] for x in coverage if x["state"]=="FOUND_NO_APPLICABILITY"],
      "audit_file":"results/audits/nvd_selected_cve_coverage.json"},
      "snapshot_hash_algorithm":"SHA-256","snapshot_hash":combined,
      "source_version":"NVD CVE JSON 2.0 annual feeds","source_years":[2022,2023,2024]})
    cfg.write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    print(json.dumps({"snapshot_id":manifest["snapshot_id"],"snapshot_hash":combined,"record_count":manifest["record_count"],"coverage":manifest["selected_cve_coverage"]},indent=2))
if __name__=="__main__": main()
