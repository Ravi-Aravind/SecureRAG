# ProveRAG Raw Integrity Audit: 20260917T162540Z_336b965e

Overall raw audit: **FAIL (execution incomplete; frozen-artifact integrity PASS)**

## Programmatic Checks

- PASS: Exactly 25 CVEs processed in frozen order with no duplicates
- PASS: Each CVE has exactly one serialized ProveRAG result
- PASS: Each retrieval contains exactly five ranked 1-5 frozen original documents
- PASS: Retrieval identities, full text, Type-C prompts, probe questions, and Phase 0 configuration match frozen sources
- PASS: Phase 0 SHA-256 hashes are unchanged before and after the run
- PASS: All result records serialize correctly
- PASS: All 25 primary failures preserve the exact configuration-error message
- PASS: No auxiliary output could affect any primary result because no auxiliary evaluation ran
- FAIL: Complete primary security endpoint results (0/25 successful)
- FAIL: Complete auxiliary provenance evaluation results (0/25 eligible)
- FAIL: Statistical endpoint is estimable (0 paired primary decisions)

## Failure Cause

`OPENROUTER_API_KEY environment variable is missing. Please set it in your environment before running.`

## Call Accounting

```json
{
  "primary_llm_invocations": 25,
  "auxiliary_evaluator_invocations": 0,
  "total_llm_invocations": 25,
  "primary_llm_calls": 0,
  "auxiliary_evaluator_llm_calls": 0,
  "total_llm_calls": 0,
  "successful_primary_calls": 0,
  "successful_auxiliary_calls": 0,
  "successful_calls": 0,
  "failed_calls": 25,
  "http_api_errors": 0,
  "parsing_errors": 0,
  "primary_failures": 25,
  "auxiliary_failures": 0,
  "adapter_failures": 0,
  "configuration_errors": 25,
  "failure_reason": "OPENROUTER_API_KEY environment variable is missing before OpenRouter client construction."
}
```

## Frozen Phase 0 Hash Verification

```json
{
  "before": {
    "selected_cves.json": "cef5d48481ee4df28884a411dc778f555c9538466aedab72adea9df7ac8a472f",
    "documents.json": "3a25bfa8f755374b9ba46a0dccfdf25de4984b8480d6ea983abefbb570c532ed",
    "embeddings.json": "61d89fa41cf980125bc43bb67f42b75742b08439fd2eed8d33be617cf0f8dda4",
    "retrieval_results.json": "1cf6d170d6f343ecd37b1e719e1736db339f9d2b5c6dfbd81226c3d41ea5b27d",
    "experiment_records.json": "8939145a99e8a001823ec637951d6753237de27bf01e4f74e9a79ddfdc7acfc8",
    "analysis_ready.csv": "a9f4fa270988fb28dec272444527e4ab0624685a07cfdf7924f5113aa14934bc"
  },
  "after": {
    "selected_cves.json": "cef5d48481ee4df28884a411dc778f555c9538466aedab72adea9df7ac8a472f",
    "documents.json": "3a25bfa8f755374b9ba46a0dccfdf25de4984b8480d6ea983abefbb570c532ed",
    "embeddings.json": "61d89fa41cf980125bc43bb67f42b75742b08439fd2eed8d33be617cf0f8dda4",
    "retrieval_results.json": "1cf6d170d6f343ecd37b1e719e1736db339f9d2b5c6dfbd81226c3d41ea5b27d",
    "experiment_records.json": "8939145a99e8a001823ec637951d6753237de27bf01e4f74e9a79ddfdc7acfc8",
    "analysis_ready.csv": "a9f4fa270988fb28dec272444527e4ab0624685a07cfdf7924f5113aa14934bc"
  },
  "unchanged": true
}
```
