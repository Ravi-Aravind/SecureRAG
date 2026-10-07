import gzip, json
from pathlib import Path

class NvdSnapshot:
    def __init__(self, root, manifest):
        self.root=Path(root); self.manifest=manifest; self.index={}
        for item in manifest["files"]:
            path=self.root/item["path"]
            if path.suffix==".gz":
                with gzip.open(path,"rt",encoding="utf-8") as handle: data=json.load(handle)
            else:
                data=json.loads(path.read_text(encoding="utf-8"))
            for wrapper in data.get("vulnerabilities",[]):
                cve=wrapper.get("cve",wrapper)
                self.index[cve.get("id","")]=cve
    def get(self,cve): return self.index.get(cve)
