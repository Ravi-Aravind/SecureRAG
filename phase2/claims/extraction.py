import re
from .schemas import Boundary, Claim

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
VERSION_RE = r"\d+(?:\.\d+)+"
BOUNDARY_PATTERNS = [
    (r"\b(?:before\s+or\s+equal(?:\s+to)?|through|up\s+to)\s+(?:version\s+)?(" + VERSION_RE + r")", "<="),
    (r"\b(?:prior\s+to|before|less\s+than)\s+(?:versions?\s+)?(" + VERSION_RE + r")", "<"),
    (r"\b(?:after\s+or\s+equal(?:\s+to)?|from)\s+(?:version\s+)?(" + VERSION_RE + r")", ">="),
    (r"\b(?:after|greater\s+than)\s+(?:version\s+)?(" + VERSION_RE + r")", ">"),
    (r"\bexactly\s+(" + VERSION_RE + r")", "="),
]

def extract_claim(text: str, cve_hint=None, vendor_hint=None, product_hint=None) -> Claim:
    cves = list(dict.fromkeys(m.group(0).upper() for m in CVE_RE.finditer(text)))
    cve = cves[0] if len(cves) == 1 else (cve_hint.upper() if not cves and cve_hint else None)
    status = None
    if re.search(r"\b(?:not affected|unaffected|not vulnerable|is not vulnerable)\b", text, re.I):
        status = "not_affected"
    elif re.search(r"\b(?:affected|vulnerable)\b", text, re.I):
        status = "affected"
    boundaries = []
    for pattern, op in BOUNDARY_PATTERNS:
        boundaries.extend((op, m.group(1)) for m in re.finditer(pattern, text, re.I))
    # Repeated identical boundary statements are one assertion; differing
    # bounds remain ambiguous and are never collapsed.
    boundaries = list(dict.fromkeys(boundaries))
    # The probe is distinct from the stated range. Extract version only when tied to a product claim.
    claimed = None
    if product_hint:
        escaped = re.escape(product_hint)
        m = re.search(r"\b" + escaped + r"\s+version\s+(" + VERSION_RE + r")", text, re.I)
        if m: claimed = m.group(1)
    if claimed is None:
        m = re.search(r"\bversion\s+(" + VERSION_RE + r")\s+(?:is\s+)?(?:not\s+)?(?:affected|vulnerable)", text, re.I)
        if m: claimed = m.group(1)
    if claimed is None:
        m = re.search(r"\b(?:version\s+)?(" + VERSION_RE + r")\s+is\s+(?:not\s+)?(?:affected|vulnerable)", text, re.I)
        if m: claimed = m.group(1)
    if not cve: state, reason = "MALFORMED", "CVE_MISSING_OR_AMBIGUOUS"
    elif not status: state, reason = "MALFORMED", "STATUS_MISSING"
    elif not claimed and not boundaries: state, reason = "MALFORMED", "VERSION_AND_BOUNDARY_MISSING"
    elif len(boundaries) > 1: state, reason = "AMBIGUOUS", "MULTIPLE_BOUNDARIES"
    else: state, reason = "EXTRACTED", None
    return Claim(cve, vendor_hint, product_hint, "affected_version", claimed, status,
                 Boundary(*boundaries[0]) if len(boundaries) == 1 else None, state, reason)
