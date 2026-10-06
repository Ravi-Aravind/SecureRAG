# What the Results Mean — Phase 2 Design Rationale

## FieldPoison + ClaimGuard

This document interprets the empirical findings obtained so far and identifies what can reasonably be inferred from them for the design of Phase 2, ClaimGuard.

The purpose of this document is not to claim that a particular defense is universally effective or ineffective.

Instead, it answers:

1. What did the experiments actually demonstrate?
2. What failure mechanisms were observed?
3. What can we infer from those mechanisms?
4. What remains unresolved after retrieval-layer defenses?
5. Why does Phase 2 need an external knowledge-base verification layer?
6. What should ClaimGuard test?
7. What should ClaimGuard explicitly NOT claim?

---

# 1. Executive Summary

The experiments demonstrate a specific weakness in cybersecurity RAG systems:

> A one-token change to a security-critical version boundary can remain almost indistinguishable from the original document in dense embedding space while changing the security decision associated with a specific software version.

The evaluated CVE corpus contained 25 selected records from 15,141 candidates. The mutated document was constructed by incrementing the patch component of an exclusive version boundary by one patch version.

For example:

    Original:
    versions before 2.4.2 are affected

    Mutated:
    versions before 2.4.3 are affected

The probe version is `2.4.2`.

Under the authoritative original:

    2.4.2 is NOT affected.

Under the mutated document:

    2.4.2 IS affected.

The conflict condition produced a reported false-positive security-decision rate of:

    12 / 25 = 48%

The clean baseline produced:

    0 / 25 = 0%

with a reported risk difference of:

    0.48

and 95% bootstrap confidence interval:

    [0.28, 0.68]

The reported McNemar exact test was:

    p = 0.000488

The original and mutated documents were co-retrieved in:

    25 / 25 = 100%

with a mean cosine-similarity gap of:

    5.84 × 10^-4

These results establish that the mutation can survive dense retrieval and that the presence of the mutation can be associated with incorrect security decisions.

However, the results do NOT establish that every false-positive decision was caused by direct poisoning.

The mechanism analysis is therefore the most important result for Phase 2.

---

# 2. The Central Finding

The central finding is not simply:

> "RAG can be poisoned."

The more precise finding is:

> A security-critical field can be changed by a minimal textual mutation that is difficult to distinguish from the original using dense semantic retrieval, while the mutation changes the downstream security decision.

This distinction matters because the attack operates at two different levels.

## Retrieval level

The original and mutated documents remain extremely similar.

The reported mean cosine-similarity gap is only:

    5.84 × 10^-4

and both documents were retrieved together in every conflict case.

Therefore, dense retrieval does not reliably distinguish:

    authoritative document

from:

    minimally mutated document

when both are semantically almost identical.

## Reasoning level

Once the documents reach the LLM, the model must correctly interpret the version boundary.

The model can therefore fail even when the authoritative document is present.

This creates an important distinction:

    Retrieval contamination
            vs.
    Evidence interpretation error

Phase 2 should be designed around this distinction.

---

# 3. What We Can Infer From the Retrieval Results

## 3.1 The mutation is retrieval-preserving

The mutation changes a single security-critical version field.

Nevertheless, the document remains sufficiently similar to its source that the mutated and original versions can both appear in the Top-5 retrieved context.

This means that semantic retrieval should not be treated as a correctness mechanism.

A document can be:

    highly relevant
    semantically similar
    correctly retrieved

and still contain an incorrect security fact.

Therefore:

> Retrieval relevance is not equivalent to factual validity.

This is one of the strongest motivations for Phase 2.

---

# 4. What We Can Infer From the False Positives

The conflict condition produced:

    12 / 25 = 48% false-positive security decisions

while the clean baseline produced:

    0 / 25

This demonstrates that introducing the mutated document into the retrieval environment is associated with a substantial change in security-decision behavior under the evaluated conditions.

However, this number should NOT be interpreted as:

    48% direct poisoning success rate

without mechanism decomposition.

The experiment itself identifies multiple possible pathways to an incorrect decision.

---

# 5. Mechanism Decomposition

The reported analysis identifies three major mechanisms:

1. Inclusive-boundary semantic misreading
2. Genuine mutated-boundary poisoning
3. Parametric knowledge override

The paper also reports one corrected classifier error.

The paper currently reports the following mechanism counts:

    Inclusive-boundary misreading:       8
    Genuine mutated-boundary poisoning:  2
    Parametric override:                 2
    Corrected classifier error:           1

IMPORTANT:

These numbers require reconciliation before publication because:

    8 + 2 + 2 + 1 = 13

while the reported total false-positive count is:

    12 / 25

The raw experiment records should therefore be treated as the authoritative source for the final mechanism counts.

Do NOT resolve this discrepancy by manually changing the numbers.

---

# 6. Mechanism 1 — Inclusive-Boundary Misreading

This is the most important observation for Phase 2.

Consider:

    prior to 2.4.2

The intended interpretation is:

    v < 2.4.2

Therefore:

    2.4.1 -> affected
    2.4.2 -> not affected

A model can instead implicitly interpret the phrase as:

    v <= 2.4.2

which produces:

    2.4.2 -> affected

This is a semantic reasoning error.

The critical point is:

> The authoritative document itself can contain the correct fact, yet the generated security decision can still be incorrect.

This means a defense that only asks:

    "Which document should I retrieve?"

may not solve the complete problem.

---

# 7. Why This Matters for ClaimGuard

This observation directly motivates post-generation verification.

Suppose the RAG system produces:

    Claim:
    "Version 2.4.2 is affected by CVE-XXXX."

The system may have:

    retrieved the correct CVE,
    cited the correct CVE,
    and generated a fluent answer,

while still producing an incorrect security claim.

The error is therefore not necessarily detectable through:

    retrieval relevance
    document provenance
    citation presence
    semantic similarity

alone.

A separate verification step can instead evaluate the final claim against an authoritative structured knowledge source.

---

# 8. Mechanism 2 — Genuine Mutated-Boundary Poisoning

A smaller subset of cases was attributed to genuine mutated-boundary poisoning.

This represents the more conventional poisoning pathway.

Conceptually:

    Original document
           +
    Mutated document
           ↓
    RAG context
           ↓
    LLM
           ↓
    Mutated boundary influences answer

This mechanism is important because it demonstrates that the mutation can influence generation directly.

However, the results suggest that it should not be treated as synonymous with all observed failures.

This distinction is important for Phase 2:

> ClaimGuard should be evaluated against both direct poisoned claims and reasoning-derived incorrect claims.

---

# 9. Mechanism 3 — Parametric Knowledge Override

Some cases were attributed to the model overriding the supplied context with information apparently coming from its learned knowledge.

This matters because the system prompt explicitly instructed the model:

    "Answer questions using ONLY the provided context documents.
    Do not use external knowledge."

Nevertheless, the experiment identified cases classified as parametric override.

This means that:

> Even an explicit instruction to remain grounded in retrieved context does not necessarily guarantee that the final answer is determined exclusively by that context.

This creates another motivation for post-generation verification.

ClaimGuard should not assume:

    LLM + retrieved evidence = verified fact

Instead:

    LLM claim -> external verification

should be treated as a separate stage.

---

# 10. The Most Important Inference

The results suggest that there are at least three distinct trust boundaries:

    1. Knowledge-base integrity
    2. Retrieval integrity
    3. Generated-claim correctness

A clean document can fail at the third layer.

A poisoned document can fail at the first and second layers.

Therefore, protecting only the retrieval pipeline does not necessarily guarantee correctness of the final security claim.

This is the conceptual bridge to ClaimGuard.

---

# 11. What Phase 1 Can and Cannot Establish

Phase 1 was designed to investigate whether retrieval/evidence defenses reduce the observed errors.

The important interpretation should therefore be:

### If a retrieval defense removes the mutated document and the error disappears

This supports the interpretation that the error was dependent on poisoned evidence.

### If a retrieval defense removes the mutated document but the error remains

This suggests that the remaining error occurs downstream of retrieval.

### If a defense increases conflict/refusal responses

This may reduce false-positive decisions without necessarily increasing correct decisions.

Therefore:

    fewer false positives

does NOT automatically mean:

    more correct answers.

Phase 2 should measure these outcomes separately.

---

# 12. Why ClaimGuard Should Operate After Generation

The experimental evidence motivates the following architecture:

    User Query
        |
        v
    RAG Retrieval
        |
        v
    Defense Layer
        |
        v
    LLM Generation
        |
        v
    Extract Security Claims
        |
        v
    ClaimGuard
        |
        +----------------------+
        |                      |
        v                      v
    Authoritative KB       Claim Status
                              |
                +-------------+-------------+
                |             |             |
                v             v             v
            SUPPORTED     CONTRADICTED   UNVERIFIABLE
                |
                v
           Final Output
```

The key change is that ClaimGuard does not attempt to determine whether a document is semantically similar to the query.

It verifies the factual security claim produced by the system.

---

# 13. Phase 2 Research Question

The Phase 2 research question should be:

> Can post-generation verification against authoritative external cybersecurity knowledge bases detect incorrect security claims produced by a RAG system under field-level poisoning, including errors that remain after retrieval-layer defenses?

This question follows directly from the observed Phase 0 mechanisms.

It does not assume that ClaimGuard will succeed.

---

# 14. Phase 2 Hypothesis

A suitable hypothesis is:

> Post-generation verification against authoritative external knowledge bases will identify a substantial fraction of incorrect security claims that remain after retrieval-layer processing, including claims caused by minimally mutated evidence and boundary-semantic reasoning errors.

The hypothesis should be tested rather than built into the evaluation criteria.

---

# 15. What ClaimGuard Must Verify

Phase 2 should not verify only:

```
"Does this CVE exist?"
```

That would be too weak.

The important claim is structured.

For example:

```
CVE:
    CVE-XXXX-XXXX

Product:
    ExampleProduct

Claim:
    version 2.4.2 is affected
```

The verifier should transform this into a typed claim such as:

```
{
    "cve": "CVE-XXXX-XXXX",
    "product": "ExampleProduct",
    "claim_type": "affected_version",
    "version": "2.4.2",
    "predicted_status": "affected"
}
```

The external KB can then determine whether the claim is:

```
SUPPORTED
CONTRADICTED
UNVERIFIABLE
```

---

# 16. Why Structured Claims Matter

The Phase 0 attack changes a single field:

```
2.4.2
    →
2.4.3
```

The generated answer may contain only one incorrect field.

Therefore, document-level verification is unnecessarily coarse.

ClaimGuard should operate at the claim/field level.

Conceptually:

```
Document-level verification:

"Is this CVE document trustworthy?"
```

versus:

```
Claim-level verification:

"Does the authoritative KB support the statement
 that version 2.4.2 is affected by CVE-XXXX?"
```

The second question is much closer to the actual security failure measured in Phase 0.

---

# 17. Phase 2 Verification Sources

The verification source should be independent from the poisoned retrieval corpus wherever possible.

For CVE version claims, a natural authoritative source is structured vulnerability information such as:

```
NVD structured vulnerability data
```

Potential additional sources can be considered for later claim types.

The key principle is:

> The verifier should not simply re-read the same potentially poisoned text that generated the answer.

Otherwise, ClaimGuard would reproduce the same trust failure.

---

# 18. The Independence Requirement

This is critical.

Bad design:

```
Poisoned CVE document
        ↓
    RAG answer
        ↓
    ClaimGuard
        ↓
same poisoned CVE text
```

This does not provide meaningful independent verification.

Preferred design:

```
RAG corpus
    |
    v
LLM answer
    |
    v
Structured claim
    |
    v
Independent authoritative KB
    |
    v
Verification result
```

This creates a separate evidence channel.

---

# 19. Phase 2 Core Evaluation

The central evaluation should compare:

```
RAG answer
```

against:

```
authoritative KB verdict
```

For each generated security claim:

```
Ground truth = authoritative KB

ClaimGuard output =
    SUPPORTED
    CONTRADICTED
    UNVERIFIABLE
```

The most important case is:

```
Generated claim = incorrect
KB verdict = CONTRADICTED
```

This represents a successful detection of an incorrect security claim.

---

# 20. Phase 2 Confusion Matrix

Phase 2 should explicitly measure:

| Generated Claim | KB Verdict   | Interpretation                             |
| --------------- | ------------ | ------------------------------------------ |
| Correct         | SUPPORTED    | Correctly supported                        |
| Correct         | CONTRADICTED | Verification error                         |
| Correct         | UNVERIFIABLE | Abstention / KB coverage issue             |
| Incorrect       | SUPPORTED    | Dangerous verification failure             |
| Incorrect       | CONTRADICTED | Successful detection                       |
| Incorrect       | UNVERIFIABLE | Safe abstention but incomplete KB evidence |

This is more informative than reporting a single verification accuracy number.

---

# 21. The Most Important Security Metric

A useful primary Phase 2 outcome is:

> Detection rate of incorrect security claims.

For incorrect generated claims:

```
Detection Rate =
incorrectly generated claims classified as CONTRADICTED
------------------------------------------------------
total incorrect generated claims that are verifiable
```

This should be supplemented with:

* false verification rate;
* abstention rate;
* supported-claim precision;
* contradicted-claim recall;
* unverifiable rate;
* KB coverage.

---

# 22. Why UNVERIFIABLE Is Necessary

A major danger in Phase 2 would be forcing every claim into:

```
SUPPORTED
or
CONTRADICTED
```

Real knowledge bases may be incomplete.

For example:

```
Generated claim:
"Product X version 1.2.3 is affected."
```

If the authoritative KB has no sufficient information to determine the status, the correct result should be:

```
UNVERIFIABLE
```

rather than:

```
SUPPORTED
```

or:

```
CONTRADICTED
```

This prevents the verifier from converting missing evidence into false certainty.

---

# 23. Phase 2 Should Separate Detection From KB Coverage

A verifier can appear weak because the external KB is incomplete.

Therefore, two questions must be separated:

### Verification capability

Can ClaimGuard correctly identify claims when the KB contains the necessary information?

### KB coverage

Does the external KB actually contain sufficient information to verify the claim?

These are different properties.

Phase 2 should report both.

---

# 24. Recommended Phase 2 Conditions

The initial Phase 2 experiment should preserve the Phase 0/Phase 1 setup.

For example:

```
Condition A:
Clean corpus

Condition C:
Original + mutated corpus

Condition D:
Phase 1 defense + ClaimGuard
```

Potentially:

```
Condition E:
Baseline RAG + ClaimGuard
```

This allows the experiment to answer:

```
Does ClaimGuard help?
```

and:

```
Does ClaimGuard provide additional protection after
retrieval-layer defenses?
```

---

# 25. Important Ablation for Phase 2

The most informative ablation is likely:

```
RAG only
    vs
RAG + ClaimGuard
```

and, where Phase 1 results are available:

```
Phase 1 defense
    vs
Phase 1 defense + ClaimGuard
```

This tests whether ClaimGuard provides incremental protection.

The objective should not be to show that ClaimGuard replaces retrieval defenses.

The intended architecture is layered:

```
Retrieval defense
       +
Claim verification
```

---

# 26. Mechanism-Specific Phase 2 Evaluation

Phase 2 should evaluate the mechanisms separately.

## Genuine poisoning

Question:

> Can ClaimGuard detect a claim derived from the mutated document?

Expected verification path:

```
incorrect claim
    ↓
authoritative KB
    ↓
CONTRADICTED
```

---

## Inclusive-boundary misreading

Question:

> Can ClaimGuard detect a claim that is wrong even though the model used the authoritative original document?

This is particularly important.

Example:

```
Original:
before 2.4.2

Generated:
2.4.2 is affected

KB:
2.4.2 is NOT affected
```

ClaimGuard should detect the contradiction.

This is the strongest argument for Phase 2.

---

## Parametric override

Question:

> Can ClaimGuard catch a model-generated security claim that does not agree with the authoritative KB even when the retrieved evidence itself was not poisoned?

Again:

```
Generated claim
      ↓
independent KB
      ↓
CONTRADICTED
```

---

# 27. What We Should NOT Infer

The current results do NOT establish:

### 1. That all RAG systems are vulnerable

The experiment evaluates a specific configuration.

### 2. That all LLMs will behave identically

The experiment uses a specific model configuration.

### 3. That dense retrieval can never distinguish the documents

The experiment demonstrates indistinguishability under the evaluated setup, not a universal impossibility result.

### 4. That retrieval defenses are useless

They may address the genuine poisoning component even if they do not solve boundary reasoning.

### 5. That ClaimGuard will solve the problem

ClaimGuard remains a hypothesis to be evaluated.

### 6. That the 48% value is a universal attack success rate

It is an observed rate for the evaluated 25-CVE conflict experiment.

### 7. That provenance guarantees correctness

The experiment motivates testing this assumption rather than accepting it.

---

# 28. What the Results Suggest About the Research Contribution

The emerging contribution is therefore not simply:

```
"We invented another RAG defense."
```

The more defensible research story is:

```
FieldPoison
    ↓
Demonstrates field-level security corruption
    ↓
Mechanism decomposition
    ↓
Shows multiple pathways to incorrect claims
    ↓
Phase 1
    ↓
Tests retrieval/evidence defenses
    ↓
Residual claim-level errors
    ↓
ClaimGuard
    ↓
Independent KB verification
```

This positions ClaimGuard as a complementary verification layer.

---

# 29. Phase 2 Design Principle

The central design principle should be:

> Verify the claim, not merely the document.

A document can be:

```
relevant
authoritative-looking
correctly retrieved
correctly cited
```

while the final claim can still be wrong.

ClaimGuard therefore receives the generated security claim as its primary input.

---

# 30. Recommended ClaimGuard Pipeline

```text
                    RAG SYSTEM
                        |
                        v
                  Generated Answer
                        |
                        v
                 Claim Extraction
                        |
                        v
              Typed Security Claims
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
        CVE          Product        Version
          |             |             |
          +-------------+-------------+
                        |
                        v
              External Authoritative KB
                        |
                        v
                KB Resolution Engine
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
      SUPPORTED    CONTRADICTED   UNVERIFIABLE
          |             |             |
          +-------------+-------------+
                        |
                        v
                 Final Verification
```

---

# 31. Phase 2 Success Criteria

Do not define success as:

```
"ClaimGuard achieves X% accuracy"
```

before seeing the results.

Instead, define measurable questions:

1. What fraction of incorrect claims are detected?
2. What fraction of correct claims are incorrectly rejected?
3. How often does the verifier abstain?
4. How often does it incorrectly mark a false claim as supported?
5. How much additional protection does ClaimGuard provide beyond Phase 1 defenses?
6. Does performance differ by failure mechanism?
7. How much does KB incompleteness affect verification?

These questions can be answered empirically.

---

# 32. The Most Important Experiment for Phase 2

The single most informative test is:

```text
Original + Mutated RAG
          |
          v
       LLM answer
          |
          v
    Claim extraction
          |
          v
    ClaimGuard
          |
          v
   Independent KB
          |
          v
 Verification verdict
```

Then compare:

```
RAG security-decision error
```

against:

```
RAG + ClaimGuard security-decision error
```

The key outcome is whether incorrect claims that survive retrieval and generation are subsequently detected by independent KB verification.

---

# 33. Phase 2 and the FieldPoison Threat Model

FieldPoison demonstrates:

```
minimal textual change
        ↓
semantic security change
        ↓
retrieval preservation
        ↓
possible incorrect claim
```

ClaimGuard addresses the final stage:

```
incorrect claim
        ↓
external verification
        ↓
detection / abstention
```

This creates a complete experimental chain:

```
Attack
  ↓
Retrieval
  ↓
Generation
  ↓
Claim
  ↓
Verification
```

---

# 34. Current Research Decision

Based on the results available so far, Phase 2 should NOT be designed as another retrieval defense.

The strongest unresolved problem is:

> How can a system independently determine whether a generated cybersecurity claim is factually supported when the retrieved evidence may be contradictory, minimally poisoned, or correctly retrieved but incorrectly interpreted?

This is the problem ClaimGuard should address.

---

# 35. Immediate Next Steps

Before implementing Phase 2:

1. Recover the authoritative Phase 1 result files.
2. Reconcile the Phase 0 mechanism-count discrepancy.
3. Determine exactly which failure mechanisms survived each Phase 1 defense.
4. Select the authoritative external KB for each claim type.
5. Define the typed claim schema.
6. Define the KB resolution rules.
7. Define `SUPPORTED`, `CONTRADICTED`, and `UNVERIFIABLE` before evaluation.
8. Freeze the Phase 2 dataset and claims.
9. Define the primary detection metric.
10. Run ClaimGuard without tuning on the evaluation results.
11. Perform mechanism-specific analysis.
12. Perform a KB-incompleteness/abstention analysis.

---

# 36. Bottom Line

The experiments provide evidence for a layered security problem.

The mutation can survive retrieval.

The generated answer can therefore be wrong even when relevant evidence is present.

The observed errors are not homogeneous:

```
some involve poisoned evidence,
some involve boundary interpretation,
some involve parametric knowledge,
and some require careful classification.
```

This means that a single retrieval-layer control should not be assumed to solve the complete problem.

The strongest implication for Phase 2 is therefore:

> The final security claim should be independently checked against an authoritative knowledge source after generation.

ClaimGuard should be evaluated as this independent verification layer.

The objective is not to prove that ClaimGuard always produces the correct answer.

The objective is to measure whether independent KB resolution can detect incorrect security claims that survive retrieval and generation, while explicitly accounting for cases where the external KB is incomplete and the correct response is `UNVERIFIABLE`.

```

### What I would use this for

This README gives you the **research bridge**:

**Phase 0:** We demonstrated the vulnerability and discovered that the error is not one single phenomenon.

**Phase 1:** We test whether retrieval/evidence defenses address those mechanisms.

**Phase 2:** We stop trying to make retrieval itself the final authority and ask whether the **generated claim can be independently resolved against an authoritative KB**.

That is a much cleaner justification for ClaimGuard than simply saying, “Phase 1 defenses didn't work, so we made another defense.”

One thing should happen **before coding Phase 2**: resolve the `12/25` versus `8 + 2 + 2 + 1 = 13` inconsistency from `experiment_records.json`. The paper currently contains both pieces of information, so the raw records need to determine the final mechanism table rather than us choosing one. :contentReference[oaicite:1]{index=1}
