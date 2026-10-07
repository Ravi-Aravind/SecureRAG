from dataclasses import dataclass
from phase2.claims.normalization import compare_versions

RULE_VERSION = "numeric-dot-v1"

@dataclass(frozen=True)
class VersionBound:
    operator: str
    version: str

def evaluate_bound(version: str, bound: VersionBound) -> bool:
    cmp = compare_versions(version, bound.version)
    return {"<": cmp < 0, "<=": cmp <= 0, ">": cmp > 0, ">=": cmp >= 0, "=": cmp == 0}[bound.operator]

def in_interval(version, start=None, start_inclusive=True, end=None, end_inclusive=True):
    if start is not None:
        cmp = compare_versions(version, start)
        if cmp < 0 or (cmp == 0 and not start_inclusive): return False
    if end is not None:
        cmp = compare_versions(version, end)
        if cmp > 0 or (cmp == 0 and not end_inclusive): return False
    return True
