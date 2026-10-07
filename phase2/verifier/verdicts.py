SUPPORTED="SUPPORTED"
CONTRADICTED="CONTRADICTED"
UNVERIFIABLE="UNVERIFIABLE"

def decide(claim, resolution):
    if claim.extraction_status != "EXTRACTED": return UNVERIFIABLE,"CLAIM_"+claim.extraction_status
    if resolution.state != "RESOLVED": return UNVERIFIABLE,resolution.reason or resolution.state
    expected="affected" if resolution.affected else "not_affected"
    return (SUPPORTED,"AUTHORITATIVE_MATCH") if claim.predicted_status==expected else (CONTRADICTED,"AUTHORITATIVE_CONTRADICTION")
