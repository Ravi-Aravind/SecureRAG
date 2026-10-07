import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from phase2.knowledge_base.version_rules import VersionBound,evaluate_bound,in_interval

class VersionTests(unittest.TestCase):
 def test_operators(self):
  for op,expected in [("<",False),("<=",True),(">",False),(">=",True),("=",True)]: self.assertEqual(evaluate_bound("1.2.0",VersionBound(op,"1.2.0")),expected)
 def test_intervals(self):
  self.assertTrue(in_interval("2.0", "2.0",True,"3.0",True)); self.assertFalse(in_interval("2.0","2.0",False,"3.0",True)); self.assertTrue(in_interval("3.0","2.0",True,"3.0",True)); self.assertFalse(in_interval("3.0","2.0",True,"3.0",False))
 def test_invalid(self):
  with self.assertRaises(ValueError): evaluate_bound("1.2rc1",VersionBound("<","2.0"))
 def test_exclusive_start_boundary(self):
  self.assertFalse(in_interval("1.22.1", "1.22.1", False, "2.0", True))
  self.assertTrue(in_interval("1.22.2", "1.22.1", False, "2.0", True))
if __name__=="__main__": unittest.main()
