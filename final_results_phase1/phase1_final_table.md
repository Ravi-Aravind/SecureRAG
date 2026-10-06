# Phase 1 Primary Retrieval-Defense Comparison

ProveRAG is intentionally excluded because it is an auxiliary provenance branch. TrustRAG was not reproducibly evaluated.

| System | n | Incorrect | Rate | RD | 95% bootstrap CI | Exact McNemar p | Holm p |
|---|---:|---:|---:|---:|---|---:|---:|
| Condition A | 25 | 0 | 0.0% | +0.0% | [+0.0%, +0.0%] | 1.00000000 | — |
| RobustRAG | 25 | 25 | 100.0% | +100.0% | [+100.0%, +100.0%] | 0.00000006 | 1.1920928955078125e-07 |
| NLI | 25 | 20 | 80.0% | +80.0% | [+64.0%, +96.0%] | 0.00000191 | 1.9073486328125e-06 |

## Exact McNemar tables

Rows are baseline correct/incorrect; columns are defense correct/incorrect.

### RobustRAG

a=0, b=25, c=0, d=0; exact two-sided p=0.00000006

### NLI

a=5, b=20, c=0, d=0; exact two-sided p=0.00000191
