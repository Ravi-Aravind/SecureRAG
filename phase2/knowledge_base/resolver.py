from dataclasses import dataclass
from .version_rules import in_interval
from ..claims.normalization import normalize_name

@dataclass
class Resolution:
    state: str
    affected: object = None
    cpe_match_criteria: object = None
    matched_cpe: object = None
    branch_trace: object = None
    reason: object = None
    cpe_resolution: str = "UNRESOLVED"

def strict_cpe_match(product, vendor, criteria):
    """Match CPE 2.3 part/vendor/product fields; no wildcards or aliases."""
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3": return False
    cpe_vendor, cpe_product = parts[3], parts[4]
    return (cpe_vendor not in ("*", "-") and cpe_product not in ("*", "-" )
            and normalize_name(cpe_vendor) == normalize_name(vendor or "")
            and normalize_name(cpe_product) == normalize_name(product or ""))

def find_product_cpes(claim, record):
    found=[]
    for config in record.get("configurations", []):
        for node in config.get("nodes", []):
            stack=[node]
            while stack:
                item=stack.pop()
                for m in item.get("cpeMatch", []):
                    criteria=m.get("criteria", "")
                    if strict_cpe_match(claim.product, claim.vendor, criteria): found.append((m, criteria))
                stack.extend(item.get("children", []))
    unique={criteria:(m,criteria) for m,criteria in found}
    return list(unique.values())

def _contains_claimed_product(node, claim):
    """True when this Boolean subtree contains an exact target vendor/product CPE."""
    for match in node.get("cpeMatch", []):
        if strict_cpe_match(claim.product, claim.vendor, match.get("criteria", "")):
            return True
    return any(_contains_claimed_product(child, claim) for child in node.get("children", []))

def _leaf(m, claimed_version):
    criteria=m.get("criteria", "")
    vulnerable=m.get("vulnerable", False)
    if not vulnerable: return False, {"criteria":criteria,"vulnerable":False,"evaluation":"non-vulnerable-cpe"}
    try:
        criteria_parts=criteria.split(":")
        leaf_vendor=criteria_parts[3] if len(criteria_parts)>4 else ""
        leaf_product=criteria_parts[4] if len(criteria_parts)>4 else ""
        # A different product/OS leaf is unknown from this software-only claim.
        if not strict_cpe_match(claimed_version[1],claimed_version[0],criteria):
            return None,{"criteria":criteria,"evaluation":"other-cpe-context-unknown"}
        cpe_version=criteria_parts[5] if len(criteria_parts)>5 else ""
        if cpe_version not in ("", "*", "-"):
            match=(claimed_version[2] == cpe_version)
            return match,{"criteria":criteria,"tested_version":claimed_version[2],"cpe_version":cpe_version,"evaluation":"match" if match else "no-match","version_semantics":"exact-cpe-version"}
        low=m.get("versionStartIncluding") or m.get("versionStartExcluding")
        high=m.get("versionEndIncluding") or m.get("versionEndExcluding")
        match=in_interval(claimed_version[2],low,
          True if m.get("versionStartIncluding") else False,high,bool(m.get("versionEndIncluding")))
    except (ValueError, TypeError) as e:
        return None, {"criteria":criteria,"evaluation":"unsupported-version","detail":str(e)}
    return match, {"criteria":criteria,"tested_version":claimed_version[2],
      "version_start_including":m.get("versionStartIncluding"),"version_start_excluding":m.get("versionStartExcluding"),
      "version_end_including":m.get("versionEndIncluding"),"version_end_excluding":m.get("versionEndExcluding"),
      "evaluation":"match" if match else "no-match"}

def _node(node, claim):
    child_results=[_node(ch,claim) for ch in node.get("children",[])]
    leaf_results=[_leaf(m,(claim.vendor,claim.product,claim.claimed_version)) for m in node.get("cpeMatch",[])]
    results=[v for v,_ in child_results]+[v for v,_ in leaf_results]
    traces=[t for _,t in child_results]+[t for _,t in leaf_results]
    op=node.get("operator", "OR").upper()
    if not results: return None,{"operator":op,"children":traces,"evaluation":"empty"}
    if op=="AND":
        value=False if any(v is False for v in results) else (True if all(v is True for v in results) else None)
    else:
        value=True if any(v is True for v in results) else (False if all(v is False for v in results) else None)
    return value,{"operator":op,"children":traces,"evaluation":value}

def resolve_applicability(claim, record):
    if not claim.product or not claim.vendor:
        return Resolution("UNVERIFIABLE",reason="CPE_UNRESOLVED",cpe_resolution="UNRESOLVED")
    configs=record.get("configurations")
    if not configs: return Resolution("UNVERIFIABLE",reason="APPLICABILITY_MISSING",cpe_resolution="NOT_EVALUATED")
    matches=find_product_cpes(claim,record)
    if not matches: return Resolution("UNVERIFIABLE",reason="CPE_UNRESOLVED",cpe_resolution="UNRESOLVED")
    # NVD top-level configurations are alternative applicability statements. An
    # alternative with no target product CPE cannot establish this claim and is
    # excluded; unknown leaves inside a target-bearing Boolean tree still flow
    # through tri-state AND/OR evaluation.
    traces=[]; branch_values=[]
    for ci,cfg in enumerate(configs):
        for ni,node in enumerate(cfg.get("nodes",[])):
            if not _contains_claimed_product(node,claim):
                traces.append({"configuration":ci,"node":ni,"relevance":"IRRELEVANT_NO_TARGET_CPE","evaluation":"ignored"})
                continue
            val,trace=_node(node,claim); traces.append({"configuration":ci,"node":ni,"trace":trace}); branch_values.append(val)
    if not branch_values:
        return Resolution("UNVERIFIABLE",None,[c for _,c in matches],[c for _,c in matches],traces,"APPLICABILITY_AMBIGUOUS","RESOLVED")
    affected=True if any(v is True for v in branch_values) else (False if all(v is False for v in branch_values) else None)
    if affected is None:
        return Resolution("UNVERIFIABLE",None,[c for _,c in matches],[c for _,c in matches],traces,"APPLICABILITY_AMBIGUOUS","RESOLVED")
    return Resolution("RESOLVED",affected,[c for _,c in matches],[c for _,c in matches],traces,None,"RESOLVED")
