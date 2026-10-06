"""
candidate_extractor.py

Scans all CVE records and extracts candidates that contain
natural-language version boundary patterns in their descriptions.

Produces candidate_cves.json with passing records and a count report.
"""

import re
import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Version boundary patterns
# ---------------------------------------------------------------------------
# These are the natural-language phrases we expect to precede a version number.
# We deliberately keep this broad at this stage — false positives will be
# caught in Step 3 during version parsing.
#
# Each pattern must be followed (eventually) by something that looks like
# a version number: digits with at least one dot, e.g. 2.4.52 or 3.1
# ---------------------------------------------------------------------------

VERSION_NUMBER_RE = r"\d+\.\d+[\d.]*"

BOUNDARY_PATTERNS = [
    # "before X", "before version X", "before versions X"
    r"before\s+(?:version\s+|versions?\s+)?" + VERSION_NUMBER_RE,

    # "prior to X", "prior to version X"
    r"prior\s+to\s+(?:version\s+|versions?\s+)?" + VERSION_NUMBER_RE,

    # "earlier than X"
    r"earlier\s+than\s+(?:version\s+|versions?\s+)?" + VERSION_NUMBER_RE,

    # "X and earlier", "X or earlier"
    VERSION_NUMBER_RE + r"\s+and\s+earlier",
    VERSION_NUMBER_RE + r"\s+or\s+earlier",

    # "up to and including X", "up to X"
    r"up\s+to\s+(?:and\s+including\s+)?" + VERSION_NUMBER_RE,

    # "through X", "versions X through Y"
    r"through\s+" + VERSION_NUMBER_RE,

    # "fixed in X", "fixed in version X"
    r"fixed\s+in\s+(?:version\s+)?" + VERSION_NUMBER_RE,

    # "versions X through Y" (range form)
    r"versions?\s+" + VERSION_NUMBER_RE + r"\s+through\s+" + VERSION_NUMBER_RE,
]

# Compile all patterns into one combined regex (case-insensitive)
COMBINED_PATTERN = re.compile(
    "|".join(f"(?:{p})" for p in BOUNDARY_PATTERNS),
    re.IGNORECASE,
)


def contains_version_boundary(description: str) -> bool:
    """
    Returns True if the description contains at least one recognizable
    natural-language version boundary pattern.
    """
    return bool(COMBINED_PATTERN.search(description))


def extract_boundary_matches(description: str) -> list[str]:
    """
    Returns all matched boundary substrings found in the description.
    Used for inspection and logging.
    """
    return [m.group() for m in COMBINED_PATTERN.finditer(description)]


# ---------------------------------------------------------------------------
# Exclusion filters
# ---------------------------------------------------------------------------

EXCLUDED_STATES = {"REJECTED", "DISPUTED", "RESERVED"}
EXCLUDED_VENDORS = {"n/a", "unknown", ""}
TARGET_YEARS = {2022, 2023, 2024}


def check_exclusions(record: dict) -> Optional[str]:
    """
    Check whether a record should be excluded.

    Returns:
        None if the record passes all checks.
        A string describing the exclusion reason if it fails.
    """
    # State check
    if record["state"] in EXCLUDED_STATES:
        return f"excluded_state:{record['state']}"

    # Year check
    if record["year"] not in TARGET_YEARS:
        return f"excluded_year:{record['year']}"

    # Vendor check — reject "n/a" and UNKNOWN
    vendor_lower = record["vendor"].lower().strip()
    if vendor_lower in EXCLUDED_VENDORS:
        return "excluded_vendor:n/a_or_unknown"

    # Description must exist and be non-trivial
    desc = record["description"].strip()
    if len(desc) < 50:
        return "excluded_description:too_short"

    # Must contain a version boundary pattern
    if not contains_version_boundary(desc):
        return "excluded_no_version_boundary"

    return None  # passed all checks