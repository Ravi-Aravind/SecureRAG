from dataclasses import asdict

IMPLEMENTATION_VERSION="claimguard-1.0.0"

def result_record(claim,resolution,verdict,reason,manifest_ref,snapshot_id):
    return {"claim":asdict(claim),"provenance":{"kb_name":"NVD","snapshot_id":snapshot_id,
      "snapshot_manifest_reference":manifest_ref,"cve":claim.cve,"cpe_match_criteria":resolution.cpe_match_criteria,
      "matched_cpe":resolution.matched_cpe,"cpe_resolution":resolution.cpe_resolution,
      "applicability_state":resolution.state,"applicability_branch":resolution.branch_trace,
      "version_resolver":"numeric-dot-v1","version_comparison":resolution.branch_trace,"implementation_version":IMPLEMENTATION_VERSION,
      "verdict":verdict,"reason":reason}}
