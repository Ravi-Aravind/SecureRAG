"""
mutator.py

Implements the version-boundary increment mutation for Phase 0.

For every mutation:
1. Extract the target version string from the description
2. Increment its last component by 1
3. Replace exactly one occurrence in the description
4. Verify using difflib that exactly one token changed
5. Verify probe version semantic logic
6. Return structured result — never silently repair failures

Attack type: increment-only
Semantic consequence: false positive (probe version appears safe in
original, appears vulnerable in mutated)
"""

import re
import difflib
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Version extraction (same as feasibility scan — kept here as single source)
# ---------------------------------------------------------------------------

RIGHT_SIDE_RE = re.compile(
    r"(?:before|prior\s+to|earlier\s+than|up\s+to(?:\s+and\s+including)?|"
    r"through|fixed\s+in)\s+(?:version\s+)?(\d+(?:\.\d+)+)",
    re.IGNORECASE
)

LEFT_SIDE_RE = re.compile(
    r"(\d+(?:\.\d+)+)\s+(?:and|or)\s+earlier",
    re.IGNORECASE
)


def extract_all_versions(description: str) -> list[str]:
    versions = []
    for m in RIGHT_SIDE_RE.finditer(description):
        versions.append(m.group(1))
    for m in LEFT_SIDE_RE.finditer(description):
        versions.append(m.group(1))
    return versions


def component_count(version_str: str) -> int:
    return len(version_str.split("."))


def is_calendar_version(version_str: str) -> bool:
    try:
        return int(version_str.split(".")[0]) >= 2000
    except ValueError:
        return False


def is_allowed_component_count(version_str: str) -> bool:
    return component_count(version_str) in (3, 4)


def increment_version(version_str: str) -> str:
    """
    Increment the last numeric component of a version string by 1.
    '2.4.52' -> '2.4.53'
    '1.7.16.1' -> '1.7.16.2'
    Raises ValueError if the last component is not a plain integer.
    """
    parts = version_str.split(".")
    try:
        parts[-1] = str(int(parts[-1]) + 1)
    except ValueError:
        raise ValueError(
            f"Last component of '{version_str}' is not a plain integer."
        )
    return ".".join(parts)


def select_target_version(description: str) -> Optional[str]:
    """
    Select the single version string to mutate from a description.

    Rules:
    - Extract all versions
    - Exclude calendar and disallowed component counts
    - If multiple remain, prefer 3-component over 4-component
    - Within same component count, prefer the first occurrence
    - If version appears more than once in description: exclude (ambiguous)
    - Return None if no safe target found
    """
    all_versions = extract_all_versions(description)

    usable = [
        v for v in all_versions
        if not is_calendar_version(v) and is_allowed_component_count(v)
    ]

    if not usable:
        return None

    three = [v for v in usable if component_count(v) == 3]
    four  = [v for v in usable if component_count(v) == 4]
    chosen = three[0] if three else four[0]

    # Must appear exactly once in the description
    if description.count(chosen) != 1:
        return None

    return chosen


def get_boundary_type(description: str, version: str) -> str:
    """
    Determine whether the pattern that anchors *version* in *description*
    is exclusive or inclusive.

    Exclusive patterns: "before", "prior to", "earlier than", "fixed in"
    Inclusive patterns: "through", "up to", "up to and including", "and earlier"

    Strategy: search for each pattern followed (optionally) by "version" and
    then the version string.  Return the category of the first match found.
    If no known pattern is found, fall back to "exclusive" (safe default).
    """
    inclusive_re = re.compile(
        r"(?:through|up\s+to(?:\s+and\s+including)?)"
        r"\s+(?:version\s+)?" + re.escape(version),
        re.IGNORECASE,
    )
    left_inclusive_re = re.compile(
        re.escape(version) + r"\s+(?:and|or)\s+earlier",
        re.IGNORECASE,
    )
    if inclusive_re.search(description) or left_inclusive_re.search(description):
        return "inclusive"
    return "exclusive"


# ---------------------------------------------------------------------------
# Diff verification
# ---------------------------------------------------------------------------

def get_changed_tokens(original: str, mutated: str) -> list[tuple[str, str]]:
    """
    Use difflib to find tokens that differ between original and mutated.
    Tokenizes by splitting on whitespace and punctuation boundaries.
    Returns list of (original_token, mutated_token) pairs that differ.
    """
    # Tokenize: split on whitespace, keeping tokens
    def tokenize(text: str) -> list[str]:
        return re.findall(r"\S+", text)

    orig_tokens = tokenize(original)
    mut_tokens  = tokenize(mutated)

    matcher = difflib.SequenceMatcher(None, orig_tokens, mut_tokens)
    changes = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "replace":
            orig_chunk = " ".join(orig_tokens[i1:i2])
            mut_chunk  = " ".join(mut_tokens[j1:j2])
            changes.append((orig_chunk, mut_chunk))
        elif tag in ("delete", "insert"):
            orig_chunk = " ".join(orig_tokens[i1:i2]) if tag == "delete" else ""
            mut_chunk  = " ".join(mut_tokens[j1:j2])  if tag == "insert" else ""
            changes.append((orig_chunk, mut_chunk))
    return changes


# ---------------------------------------------------------------------------
# Probe version semantic verification
# ---------------------------------------------------------------------------

def verify_probe_semantics(
    original_boundary: str,
    mutated_boundary: str,
    probe_version: str,
) -> tuple[bool, str]:
    """
    For increment-only mutation:
        original: before X   -> probe X is NOT vulnerable
        mutated:  before X+1 -> probe X IS vulnerable

    Verify this by comparing version tuples numerically.

    Returns (is_correct, explanation).
    """
    def parse_tuple(v: str) -> tuple[int, ...]:
        return tuple(int(x) for x in v.split("."))

    try:
        orig_t  = parse_tuple(original_boundary)
        mut_t   = parse_tuple(mutated_boundary)
        probe_t = parse_tuple(probe_version)
    except ValueError as e:
        return False, f"parse_error:{e}"

    # Original: probe < original_boundary means vulnerable.
    # For "before X": vulnerable if version < X.
    # Probe IS original_boundary, so probe is NOT vulnerable (boundary is exclusive).
    probe_vulnerable_in_original = probe_t < orig_t
    probe_vulnerable_in_mutated  = probe_t < mut_t

    if probe_vulnerable_in_original:
        return False, (
            f"SEMANTIC ERROR: probe {probe_version} is already < "
            f"original boundary {original_boundary}. "
            f"Probe should equal original boundary."
        )

    if not probe_vulnerable_in_mutated:
        return False, (
            f"SEMANTIC ERROR: probe {probe_version} is not < "
            f"mutated boundary {mutated_boundary}. "
            f"Mutation did not create expected false positive."
        )

    return True, (
        f"OK: probe {probe_version} >= original {original_boundary} "
        f"(not vulnerable per original), "
        f"probe {probe_version} < mutated {mutated_boundary} "
        f"(vulnerable per mutated = false positive)."
    )


# ---------------------------------------------------------------------------
# Main mutation result dataclass
# ---------------------------------------------------------------------------

@dataclass
class MutationResult:
    cve_id: str
    vendor: str
    product: str

    original_description: str
    mutated_description: Optional[str]

    original_boundary: Optional[str]
    mutated_boundary: Optional[str]
    probe_version: Optional[str]

    mutation_valid: bool
    failure_reason: Optional[str]
    boundary_type: Optional[str] = None  # "exclusive", "inclusive", or None
    diff_changes: list[tuple[str, str]] = field(default_factory=list)
    probe_semantic_ok: bool = False
    probe_semantic_explanation: str = ""
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Primary mutation function
# ---------------------------------------------------------------------------

def mutate_cve(record: dict) -> MutationResult:
    """
    Attempt to produce a valid mutation of a CVE record.

    Steps:
    1. Select target version
    2. Increment it
    3. Replace in description
    4. Verify diff (exactly one token changed)
    5. Verify probe semantics
    6. Return MutationResult

    Never raises — all failures are captured in MutationResult.
    """
    cve_id  = record["cve_id"]
    vendor  = record["vendor"]
    product = record["product"]
    desc    = record["description"]

    base = MutationResult(
        cve_id=cve_id,
        vendor=vendor,
        product=product,
        original_description=desc,
        mutated_description=None,
        original_boundary=None,
        mutated_boundary=None,
        probe_version=None,
        mutation_valid=False,
        failure_reason=None,
    )

    # Step 1: Select target version
    target = select_target_version(desc)
    if target is None:
        base.failure_reason = "no_safe_target_version"
        return base

    base.original_boundary = target

    # Step 1b: Boundary-type gate — skip inclusive boundaries
    btype = get_boundary_type(desc, target)
    base.boundary_type = btype
    if btype == "inclusive":
        base.failure_reason = "inclusive_boundary_excluded"
        return base

    # Step 2: Increment
    try:
        mutated_ver = increment_version(target)
    except ValueError as e:
        base.failure_reason = f"increment_failed:{e}"
        return base

    base.mutated_boundary = mutated_ver
    base.probe_version    = target  # probe = original boundary

    # Step 3: Replace exactly one occurrence
    mutated_desc = desc.replace(target, mutated_ver, 1)
    base.mutated_description = mutated_desc

    # Step 4: Diff verification
    changes = get_changed_tokens(desc, mutated_desc)
    base.diff_changes = changes

    if len(changes) != 1:
        base.failure_reason = (
            f"diff_check_failed:expected_1_change_got_{len(changes)}"
        )
        base.notes.append(f"Changes found: {changes}")
        return base

    orig_tok, mut_tok = changes[0]
    # The changed token must contain (or equal) the version strings
    if target not in orig_tok or mutated_ver not in mut_tok:
        base.failure_reason = (
            f"diff_check_failed:changed_token_does_not_match_versions "
            f"orig_tok='{orig_tok}' mut_tok='{mut_tok}'"
        )
        return base

    # Step 5: Probe semantic verification
    sem_ok, sem_explanation = verify_probe_semantics(
        target, mutated_ver, target
    )
    base.probe_semantic_ok          = sem_ok
    base.probe_semantic_explanation = sem_explanation

    if not sem_ok:
        base.failure_reason = f"probe_semantic_failed:{sem_explanation}"
        return base

    # All checks passed
    base.mutation_valid = True
    return base