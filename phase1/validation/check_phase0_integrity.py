import hashlib
import json
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
PHASE0_DATA_DIR = os.path.join(ROOT_DIR, 'phase0', 'data')
MANIFEST_PATH = os.path.join(ROOT_DIR, 'phase1', 'validation', 'phase0_frozen_hashes.json')

def hash_file(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def check_integrity():
    if not os.path.exists(MANIFEST_PATH):
        print(f"FAIL: Manifest not found at {MANIFEST_PATH}")
        return False
        
    with open(MANIFEST_PATH, 'r') as f:
        manifest = json.load(f)
        
    all_passed = True
    for filename, expected_hash in manifest.items():
        filepath = os.path.join(PHASE0_DATA_DIR, filename)
        if not os.path.exists(filepath):
            print(f"FAIL: {filename} not found!")
            all_passed = False
            continue
            
        actual_hash = hash_file(filepath)
        if actual_hash == expected_hash:
            print(f"PASS: {filename} (SHA-256 matches)")
        else:
            print(f"FAIL: {filename} hash mismatch! Expected: {expected_hash}, Actual: {actual_hash}")
            all_passed = False
            
    if all_passed:
        print("Phase 0 integrity: PASS")
    else:
        print("Phase 0 integrity: FAIL")
        
    return all_passed

if __name__ == "__main__":
    check_integrity()
