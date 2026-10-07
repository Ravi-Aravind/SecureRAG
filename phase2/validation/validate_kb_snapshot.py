import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from knowledge_base.snapshot import load_manifest,validate_manifest
p=argparse.ArgumentParser(); p.add_argument("root",type=Path); a=p.parse_args()
validate_manifest(load_manifest(Path(__file__).resolve().parents[1]/"config/kb_snapshot_manifest.json"),a.root)
print("NVD snapshot integrity PASS")
