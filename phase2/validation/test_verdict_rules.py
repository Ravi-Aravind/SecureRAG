import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from phase2.claims.schemas import Claim
from phase2.knowledge_base.resolver import Resolution
from phase2.verifier.verdicts import decide

class VerdictTests(unittest.TestCase):
 def claim(self,status="affected",state="EXTRACTED"): return Claim("CVE-2022-29225","envoyproxy","envoy","affected_version","1.22.1",status,None,state)
 def test_supported(self): self.assertEqual(decide(self.claim(),Resolution("RESOLVED",True))[0],"SUPPORTED")
 def test_contradicted(self): self.assertEqual(decide(self.claim(),Resolution("RESOLVED",False))[0],"CONTRADICTED")
 def test_unverifiable(self): self.assertEqual(decide(self.claim(),Resolution("UNVERIFIABLE",reason="missing"))[0],"UNVERIFIABLE")
 def test_malformed_never_contradicted(self): self.assertEqual(decide(self.claim(state="MALFORMED"),Resolution("RESOLVED",False))[0],"UNVERIFIABLE")
if __name__=="__main__": unittest.main()
