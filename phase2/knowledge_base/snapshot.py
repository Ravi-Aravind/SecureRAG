import hashlib, json
from pathlib import Path

def sha256(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()

def load_manifest(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def validate_manifest(manifest, root):
    if manifest.get("status") != "READY" or not manifest.get("snapshot_id"):
        raise ValueError("NVD snapshot manifest is not READY")
    if not manifest.get("acquisition_date") or not manifest.get("record_count") or not manifest.get("files"):
        raise ValueError("manifest lacks acquisition metadata")
    checked=[]; count=0
    for item in manifest["files"]:
        p=Path(root)/item["path"]
        if not p.is_file() or sha256(p)!=item["sha256"]: raise ValueError(f"missing/hash mismatch: {p}")
        count+=int(item["record_count"]); checked.append(item["sha256"])
        if item.get("nvd_meta"):
            nvd_meta=Path(root)/item["nvd_meta"]
            official=validate_nvd_meta(p,nvd_meta)
            if official.get("sha256","").casefold()!=item.get("official_uncompressed_sha256","").casefold():
                raise ValueError(f"official NVD metadata hash mismatch for {p.name}")
            if int(official["size"])!=int(item.get("official_uncompressed_size",-1)):
                raise ValueError(f"official NVD metadata size mismatch for {p.name}")
    if count!=int(manifest["record_count"]): raise ValueError("manifest record count mismatch")
    combined=hashlib.sha256("\n".join(checked).encode("ascii")).hexdigest()
    if combined!=manifest.get("snapshot_hash"): raise ValueError("snapshot root hash mismatch")
    if not manifest.get("snapshot_id","").endswith(combined): raise ValueError("snapshot ID does not match snapshot hash")
    for item in manifest.get("metadata_files",[]):
        p=Path(root)/item["path"]
        if not p.is_file() or sha256(p)!=item["sha256"]: raise ValueError(f"metadata hash mismatch: {p}")

def validate_nvd_meta(feed_path, meta_path):
    """Validate downloaded gzip bytes against NVD's published uncompressed size/hash."""
    import gzip
    feed=Path(feed_path); metadata={}
    for line in Path(meta_path).read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key,value=line.split(":",1); metadata[key]=value
    if int(metadata.get("gzSize","-1"))!=feed.stat().st_size:
        raise ValueError(f"NVD gzip size mismatch for {feed.name}")
    h=hashlib.sha256(); size=0
    with gzip.open(feed,"rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""):
            size+=len(block); h.update(block)
    if size!=int(metadata.get("size","-1")) or h.hexdigest().casefold()!=metadata.get("sha256","").casefold():
        raise ValueError(f"NVD official uncompressed size/hash mismatch for {feed.name}")
    return metadata
