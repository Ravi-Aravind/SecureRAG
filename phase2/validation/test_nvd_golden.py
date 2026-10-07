import gzip,json,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from phase2.claims.extraction import extract_claim
from phase2.knowledge_base.resolver import resolve_applicability
from phase2.verifier.verdicts import decide
from phase2.knowledge_base.snapshot import load_manifest,validate_manifest

class PinnedNvdGoldenTests(unittest.TestCase):
 def test_condition_c_golden_against_official_nvd_record(self):
  manifest=load_manifest(ROOT/"phase2/config/kb_snapshot_manifest.json"); kbroot=ROOT/"phase2/data/nvd"
  validate_manifest(manifest,kbroot)
  with gzip.open(kbroot/"nvdcve-2.0-2022.json.gz","rt",encoding="utf-8") as handle: data=json.load(handle)
  record=next(x["cve"] for x in data["vulnerabilities"] if x["cve"]["id"]=="CVE-2022-29225")
  text="Yes, envoy version 1.22.1 is affected by CVE-2022-29225, as the vulnerability exists in versions prior to 1.22.2."
  claim=extract_claim(text,"CVE-2022-29225","envoyproxy","envoy")
  self.assertEqual((claim.claimed_version,claim.stated_boundary.operator,claim.stated_boundary.version),("1.22.1","<","1.22.2"))
  resolution=resolve_applicability(claim,record)
  verdict,reason=decide(claim,resolution)
  self.assertEqual((resolution.state,resolution.affected,verdict),("RESOLVED",False,"CONTRADICTED"))
 def test_audited_chrome_cases_against_official_records_without_relabeling(self):
  selected=json.loads((ROOT/"phase0/data/selected_cves.json").read_text(encoding="utf-8"))
  phase0=json.loads((ROOT/"phase0/data/experiment_records.json").read_text(encoding="utf-8"))
  cases=(("CVE-2023-6509",2023,"affected"),("CVE-2024-3516",2024,"conflict_acknowledged"))
  for cve,year,frozen_class in cases:
   with gzip.open(ROOT/f"phase2/data/nvd/nvdcve-2.0-{year}.json.gz","rt",encoding="utf-8") as handle: data=json.load(handle)
   record=next(x["cve"] for x in data["vulnerabilities"] if x["cve"]["id"]==cve)
   source=next(x for x in phase0 if x["cve_id"]==cve and x["condition"]=="Condition C" and x["query_type"]=="Type C")
   self.assertEqual(source["answer_class"],frozen_class)
   meta=next(x for x in selected if x["cve_id"]==cve)
   claim=extract_claim(source["response_text"],cve,meta["vendor"],meta["product"])
   verdict,_=decide(claim,resolve_applicability(claim,record))
   self.assertEqual(verdict,"CONTRADICTED",cve)
if __name__=="__main__": unittest.main()
