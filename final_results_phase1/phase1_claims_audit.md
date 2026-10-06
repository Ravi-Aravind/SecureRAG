# Claims Audit

| Claim | Supported? | Evidence | Safe wording |
|---|---|---|---|
| Baseline has false positives | NO | Frozen Condition A is 0/25 | Baseline had no false-positive decisions |
| RobustRAG reduces false positives | NO | Baseline is already 0/25 | It degraded the frozen endpoint in this adaptation |
| NLI reduces false positives | NO | Baseline is already 0/25 | It degraded the frozen endpoint in this adaptation |
| RobustRAG produced 25/25 incorrect endpoint decisions | YES | Raw RobustRAG JSON | State the observed endpoint result |
| RobustRAG caused genuine poisoning | NO | Mechanism artifact identifies classifier error | Do not make this causal claim |
| Classifier/refusal interaction explains degradation | PARTIAL | Mechanism artifact and raw isolated responses | Report as the documented mechanism interpretation |
| NLI is generally effective | NO | One experiment-specific model/protocol | Limit to this adaptation |
| NLI struggled with single-token version differences | YES | 20/25 raw outcomes and mechanism artifact | State model-specific sensitivity |
| ProveRAG is retrieval-layer defense | NO | Post-generation auxiliary branch | Report separately as provenance analysis |
| ProveRAG produced original provenance for all 25 | YES | Raw ProveRAG JSON | State auxiliary result |
| TrustRAG was successfully evaluated | NO | Methodological review | Report as excluded |
| Phase 1 answers original reduction question | NO | Baseline 0/25 | It evaluates preservation/degradation under the frozen protocol |
