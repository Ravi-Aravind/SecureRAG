import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from phase2.claims.extraction import extract_claim

class ExtractionTests(unittest.TestCase):
 def test_golden(self):
  c=extract_claim("Yes, envoy version 1.22.1 is affected by CVE-2022-29225, as the vulnerability exists in versions prior to 1.22.2.","CVE-2022-29225","envoyproxy","envoy")
  self.assertEqual((c.cve,c.vendor,c.product,c.claimed_version,c.predicted_status,c.stated_boundary.operator,c.stated_boundary.version,c.extraction_status),("CVE-2022-29225","envoyproxy","envoy","1.22.1","affected","<","1.22.2","EXTRACTED"))
 def test_not_affected(self): self.assertEqual(extract_claim("Envoy version 1.2.3 is not affected by CVE-2022-29225.","CVE-2022-29225",product_hint="Envoy").predicted_status,"not_affected")
 def test_phrases(self):
  for phrase,op in [("prior to","<"),("before","<"),("less than","<"),("through","<="),("up to","<="),("before or equal","<=")]:
   c=extract_claim(f"product version 1.2.3 is affected by CVE-2022-29225 {phrase} 1.2.4","CVE-2022-29225")
   self.assertEqual(c.stated_boundary.operator,op,phrase)
 def test_malformed(self):
  for s in ["nonsense","version 1.2.3 affected","affected by product"]:
   self.assertNotEqual(extract_claim(s).extraction_status,"EXTRACTED")
 def test_missing_version_and_cve(self):
  self.assertEqual(extract_claim("Envoy is affected by CVE-2022-29225").extraction_status,"MALFORMED")
  self.assertEqual(extract_claim("product version 1.2.3 is affected",None).extraction_status,"MALFORMED")
if __name__=="__main__": unittest.main()
