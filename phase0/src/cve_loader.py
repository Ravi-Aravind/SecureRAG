"""
cve_loader.py

Loads and parses individual CVE records from the cvelistV5 repository.
Extracts only the fields needed for the Phase 0 experiment.

Usage:
    from cve_loader import load_cve_record, iter_cve_records
"""

import json
import os
import logging
from pathlib import Path
from typing import Optional, Iterator
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def load_cve_record(filepath: str | Path) -> Optional[dict]:
    """
    Load and parse a single CVE JSON file.

    Returns a dict with extracted fields, or None if the file cannot
    be parsed or is missing required fields.

    Fields returned:
        cve_id          : str   e.g. "CVE-2023-12345"
        state           : str   e.g. "PUBLISHED"
        date_published  : str   e.g. "2023-06-15" (date only, no time)
        year            : int   e.g. 2023
        description     : str   English description text
        vendor          : str   first vendor listed, or "UNKNOWN"
        product         : str   first product listed, or "UNKNOWN"
        raw_path        : str   path to the source file
    """
    filepath = Path(filepath)

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.debug(f"Could not load {filepath}: {e}")
        return None

    # --- CVE ID ---
    try:
        cve_id = data["cveMetadata"]["cveId"]
    except KeyError:
        logger.debug(f"Missing cveId in {filepath}")
        return None

    # --- State ---
    try:
        state = data["cveMetadata"]["state"].upper()
    except KeyError:
        logger.debug(f"Missing state in {cve_id}")
        return None

    # --- Date published ---
    raw_date = data["cveMetadata"].get("datePublished", "")
    if not raw_date:
        logger.debug(f"Missing datePublished in {cve_id}")
        return None

    try:
        # Dates are ISO 8601: "2023-06-15T00:00:00Z" or "2023-06-15"
        date_published = raw_date[:10]  # take only YYYY-MM-DD
        year = int(date_published[:4])
    except (ValueError, IndexError):
        logger.debug(f"Unparseable date '{raw_date}' in {cve_id}")
        return None

    # --- Description (English) ---
    description = _extract_english_description(data, cve_id)
    if description is None:
        return None

    # --- Vendor and Product ---
    vendor, product = _extract_vendor_product(data, cve_id)

    return {
        "cve_id": cve_id,
        "state": state,
        "date_published": date_published,
        "year": year,
        "description": description,
        "vendor": vendor,
        "product": product,
        "raw_path": str(filepath),
    }


def _extract_english_description(data: dict, cve_id: str) -> Optional[str]:
    """
    Extract the English description from the CNA container.
    Returns None if no English description is found.
    """
    try:
        descriptions = data["containers"]["cna"]["descriptions"]
    except KeyError:
        logger.debug(f"No descriptions in {cve_id}")
        return None

    for desc in descriptions:
        lang = desc.get("lang", "").lower()
        # Accept "en", "en-US", "en_US", etc.
        if lang.startswith("en"):
            value = desc.get("value", "").strip()
            if value:
                return value

    logger.debug(f"No English description found in {cve_id}")
    return None


def _extract_vendor_product(data: dict, cve_id: str) -> tuple[str, str]:
    """
    Extract vendor and product from the affected list.
    Returns ("UNKNOWN", "UNKNOWN") if not found.
    Falls back gracefully — missing vendor/product is not fatal.
    """
    try:
        affected = data["containers"]["cna"]["affected"]
        if affected:
            vendor = affected[0].get("vendor", "UNKNOWN").strip()
            product = affected[0].get("product", "UNKNOWN").strip()
            return vendor, product
    except (KeyError, IndexError, TypeError):
        pass

    logger.debug(f"No vendor/product found in {cve_id}")
    return "UNKNOWN", "UNKNOWN"


def iter_cve_records(
    cvelistv5_root: str | Path,
    years: Optional[list[int]] = None,
) -> Iterator[dict]:
    """
    Walk the cvelistV5 directory tree and yield parsed CVE records.

    Args:
        cvelistv5_root : path to the cloned cvelistV5 repository
        years          : list of years to include, e.g. [2022, 2023, 2024]
                         If None, all years are included.

    Yields:
        Parsed CVE record dicts (same fields as load_cve_record)
        Only yields successfully parsed records.
    """
    root = Path(cvelistv5_root) / "cves"

    if not root.exists():
        raise FileNotFoundError(
            f"Expected 'cves/' directory not found at {root}. "
            f"Did the clone succeed?"
        )

    year_dirs = sorted(root.iterdir())

    for year_dir in year_dirs:
        if not year_dir.is_dir():
            continue

        try:
            dir_year = int(year_dir.name)
        except ValueError:
            continue

        if years is not None and dir_year not in years:
            continue

        # Walk subdirectories (0xxx, 1xxx, etc.)
        for subdir in sorted(year_dir.iterdir()):
            if not subdir.is_dir():
                continue

            for json_file in sorted(subdir.glob("*.json")):
                record = load_cve_record(json_file)
                if record is not None:
                    yield record