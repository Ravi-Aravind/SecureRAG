from phase2.verifier.verdicts import decide
from phase2.verifier.schemas import result_record
from phase2.knowledge_base.resolver import resolve_applicability

def verify(claim, snapshot, manifest_ref="config/kb_snapshot_manifest.json"):
    rec=snapshot.get(claim.cve) if claim.cve else None
    if rec is None:
        from phase2.knowledge_base.resolver import Resolution
        resolution=Resolution("UNVERIFIABLE",reason="AUTHORITATIVE_RECORD_MISSING")
    else:
        resolution=resolve_applicability(claim,rec)
    verdict,reason=decide(claim,resolution)
    return result_record(claim,resolution,verdict,reason,manifest_ref,snapshot.manifest.get("snapshot_id"))
