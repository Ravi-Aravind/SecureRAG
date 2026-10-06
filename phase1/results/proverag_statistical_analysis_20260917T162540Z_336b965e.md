# ProveRAG Phase 1 Statistical Analysis: 20260917T162540Z_336b965e

Status: **NOT ESTIMABLE**. No cross-defense Holm correction was performed.

## Execution Outcome

All 25 production-entry-point invocations failed before an OpenRouter client was constructed because `OPENROUTER_API_KEY` is missing. Therefore: 0 primary LLM API calls, 0 auxiliary evaluator API calls, 0 raw primary answers, and 0 classifier decisions exist. These execution failures are not treated as correct decisions, incorrect decisions, or citation outcomes.

## Frozen Baseline

The approved protocol baseline is retained unchanged: Condition A 12/25 = 48.0%. No baseline values were changed.

## Raw Analysis

- Intended n: 25
- Evaluable primary decisions: 0
- Primary execution failures: 25
- Incorrect decisions: not estimable
- Incorrect-decision rate: not estimable
- Risk difference vs frozen Condition A baseline: not estimable
- 95% paired bootstrap CI (10,000 resamples, seed 42): not estimable
- Exact two-sided McNemar test: not estimable
- Paired 2x2 contingency table: not estimable

## Parametric-Confound-Excluded Analysis

- Intended n after frozen exclusions: 22
- Evaluable primary decisions: 0
- All requested metrics: not estimable for the same pre-call configuration failure.

## Citation Outcomes

No auxiliary evaluations were eligible to run. The serialized per-record `absent_or_invalid` values are default placeholders following primary failure and are not observed citation outcomes.

## Mechanisms

All 25 records are `unresolved` execution failures. No semantic false-positive mechanism was inferred.
