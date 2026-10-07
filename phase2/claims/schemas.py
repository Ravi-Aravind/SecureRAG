from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Boundary:
    operator: str
    version: str


@dataclass(frozen=True)
class Claim:
    cve: Optional[str]
    vendor: Optional[str]
    product: Optional[str]
    claim_type: str
    claimed_version: Optional[str]
    predicted_status: Optional[str]
    stated_boundary: Optional[Boundary]
    extraction_status: str
    extraction_reason: Optional[str] = None
