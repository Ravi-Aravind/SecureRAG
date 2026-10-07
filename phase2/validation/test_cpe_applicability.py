import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from phase2.claims.schemas import Claim
from phase2.knowledge_base.resolver import strict_cpe_match,resolve_applicability
from phase2.verifier.verdicts import decide

class CpeTests(unittest.TestCase):
 def setUp(self): self.claim=Claim("CVE-2022-29225","envoyproxy","envoy","affected_version","1.22.1","affected",None,"EXTRACTED")
 def test_exact_case_space(self):
  self.assertTrue(strict_cpe_match("Envoy","ENVOYPROXY","cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"))
  self.assertTrue(strict_cpe_match(" envoy "," envoyproxy ","cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"))
 def test_unresolved_and_wildcard(self):
  self.assertFalse(strict_cpe_match("envoy","other","cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"))
  self.assertFalse(strict_cpe_match("unknown","envoyproxy","cpe:2.3:a:*:envoy:*:*:*:*:*:*:*:*"))
 def test_single_and_missing(self):
  cpe="cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"
  rec={"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"criteria":cpe,"vulnerable":True,"versionEndExcluding":"1.22.2"}]}]}]}
  self.assertTrue(resolve_applicability(self.claim,rec).affected)
  self.assertEqual(resolve_applicability(self.claim,{}).reason,"APPLICABILITY_MISSING")
 def test_or_and(self):
  c1="cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"; c2="cpe:2.3:o:envoyproxy:envoy-os:*:*:*:*:*:*:*:*"
  rec={"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"criteria":c1,"vulnerable":True,"versionEndExcluding":"1.22.2"}]},{"operator":"AND","cpeMatch":[{"criteria":c1,"vulnerable":True,"versionEndExcluding":"1.22.2"},{"criteria":c2,"vulnerable":True}]}]}]}
  self.assertTrue(resolve_applicability(self.claim,rec).affected)
 def test_unrelated_standalone_configuration_is_ignored(self):
  claim=Claim("CVE-2023-6509","google","chrome","affected_version","120.0.6099.62","affected",None,"EXTRACTED")
  chrome="cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
  fedora="cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*"
  record={"configurations":[
   {"nodes":[{"operator":"OR","cpeMatch":[{"criteria":chrome,"vulnerable":True,"versionEndExcluding":"120.0.6099.62"}]}]},
   {"nodes":[{"operator":"OR","cpeMatch":[{"criteria":fedora,"vulnerable":True}]}]},
  ]}
  resolution=resolve_applicability(claim,record)
  self.assertEqual((resolution.state,resolution.affected),("RESOLVED",False))
  self.assertEqual(decide(claim,resolution)[0],"CONTRADICTED")
  self.assertEqual(resolution.branch_trace[1]["evaluation"],"ignored")
 def test_unknown_required_os_in_relevant_and_branch_abstains(self):
  chrome="cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"
  fedora="cpe:2.3:o:fedoraproject:fedora:39:*:*:*:*:*:*:*"
  claim=Claim("CVE-2023-6509","google","chrome","affected_version","120.0.6099.61","affected",None,"EXTRACTED")
  record={"configurations":[{"nodes":[{"operator":"AND","cpeMatch":[
   {"criteria":chrome,"vulnerable":True,"versionEndExcluding":"120.0.6099.62"},
   {"criteria":fedora,"vulnerable":True}
  ]}]}]}
  resolution=resolve_applicability(claim,record)
  self.assertEqual((resolution.state,resolution.reason),("UNVERIFIABLE","APPLICABILITY_AMBIGUOUS"))
if __name__=="__main__": unittest.main()
