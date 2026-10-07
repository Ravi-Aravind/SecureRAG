import gzip,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from phase2.knowledge_base.snapshot import validate_nvd_meta,sha256

def main():
    root=ROOT/"phase2/data/nvd"; years=(2022,2023,2024); index={}; total=0; files=[]
    for year in years:
        name=f"nvdcve-2.0-{year}.json.gz"; feed=root/name; meta=root/f"nvdcve-2.0-{year}.meta"
        official=validate_nvd_meta(feed,meta)
        with gzip.open(feed,"rt",encoding="utf-8") as handle: data=json.load(handle)
        if data.get("format")!="NVD_CVE" or not str(data.get("version","")).startswith("2."):
            raise SystemExit(f"unexpected NVD schema in {name}")
        total+=len(data.get("vulnerabilities",[]))
        for wrapper in data.get("vulnerabilities",[]):
            cve=wrapper.get("cve",wrapper); index[cve.get("id")]=cve
        files.append({"path":name,"sha256":sha256(feed),"record_count":len(data.get("vulnerabilities",[])),"official_metadata":official})
    selected=json.loads((ROOT/"phase0/data/selected_cves.json").read_text(encoding="utf-8"))
    report=[]
    for item in selected:
        cve=item["cve_id"]; record=index.get(cve)
        state="NOT_FOUND" if record is None else ("FOUND_APPLICABILITY" if record.get("configurations") else "FOUND_NO_APPLICABILITY")
        report.append({"cve":cve,"state":state,"record_id":record.get("id") if record else None,"has_configurations":bool(record and record.get("configurations"))})
    out=ROOT/"phase2/results/audits/nvd_selected_cve_coverage.json"; out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps({"years":years,"total_records":total,"files":files,"selected_cve_coverage":report},indent=2),encoding="utf-8")
    print("\n".join(f"{x['cve']} -> {x['state']}" for x in report)); print(f"{sum(x['state'].startswith('FOUND') for x in report)}/{len(report)} FOUND; {sum(x['state']=='FOUND_APPLICABILITY' for x in report)}/{len(report)} WITH APPLICABILITY; {total} records")
if __name__=="__main__": main()
