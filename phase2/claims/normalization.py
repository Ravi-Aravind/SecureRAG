import re


def normalize_name(value: str) -> str:
    """Only case/whitespace normalization; no alias or semantic mapping."""
    return re.sub(r"\s+", " ", value).strip().casefold()


def parse_numeric_version(value: str):
    """Accept dot-separated decimal components only; reject suffixes/epochs."""
    value = value.strip()
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        raise ValueError(f"unsupported or ambiguous version syntax: {value!r}")
    return tuple(int(part) for part in value.split("."))


def compare_versions(left: str, right: str) -> int:
    a, b = parse_numeric_version(left), parse_numeric_version(right)
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return (a > b) - (a < b)
