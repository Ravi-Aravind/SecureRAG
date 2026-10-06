# Phase 1 RobustRAG Design

## 1. Source Method
**Paper:** "Certifiably Robust RAG against Retrieval Corruption"
**Authors:** Chong Xiang, Tong Wu, Zexuan Zhong, David Wagner, Danqi Chen, Prateek Mittal (Princeton University, UC Berkeley, etc.)
**Reference:** arXiv:2405.15556 (2024)

## 2. Distinctions

It is crucial to distinguish between the formally published methodology and our specific experiment implementation for Phase 1.

### 2.1 Published RobustRAG
State accurately that the published RobustRAG method:
* Isolates retrieved passages/groups.
* Generates an independent response for each isolated group.
* Performs secure aggregation.
* Includes **Secure Keyword Aggregation** (extracts unique keywords/keyphrases from isolated responses, aggregates their counts, filters them, and uses the retained keywords to generate the final response).
* Also includes **Decoding Aggregation** (aggregating token probabilities during decoding).
* Uses the aggregated information to produce the final response.

*Note: Simple categorical majority voting is NOT the published keyword aggregation algorithm.*

### 2.2 Our Experiment-Specific Adaptation
We are choosing a deliberately simpler adaptation because this project uses a highly structured Type-C cybersecurity probe with a frozen Phase 0 classifier. We define this explicitly as the **"RobustRAG-style categorical aggregation adaptation"**.

In this adaptation:
* Isolation is retained from RobustRAG.
* One retrieved document is one isolated group because Phase 0 has one document per CVE and no chunking.
* Each isolated response is passed through the existing frozen Phase 0 classifier.
* The resulting categorical states are aggregated deterministically.
* **This is NOT an exact reproduction of RobustRAG's Secure Keyword Aggregation.**
* Therefore, any empirical result will be attributed to this adaptation, not claimed as a reproduction of the full published algorithm.

## 3. Definitions & Logic

### 3.1 Isolation
For a given query with $k$ retrieved documents (typically $k=5$), we execute $k$ separate, independent LLM API calls.
- **Context:** The context provided to the LLM for call $i$ contains **only** retrieved document $i$.
- **Prompt:** The system prompt and Type-C user prompt wording remain absolutely identical to Phase 0. No mentions of isolation or voting are exposed to the LLM.

### 3.2 Classification Mapping
Each of the $k$ isolated LLM responses is parsed using the **exact frozen Phase 0 classifier** (`classify_probe`). We clearly distinguish the Phase 0 classifier output from the RobustRAG-adaptation vote state.

The exact mapping is as follows:
* `not_affected` $\rightarrow$ `original-supported`
* `affected` $\rightarrow$ `mutated-supported`
* `conflict_acknowledged` $\rightarrow$ `conflict`
* `refusal_or_insufficient` $\rightarrow$ `insufficient`
* `parsing_failure` $\rightarrow$ `insufficient`

*The mapping of `parsing_failure` to `insufficient` must explicitly be labelled an **experiment-specific handling decision**, not a published RobustRAG rule.*

### 3.3 Aggregation Rule
We define our aggregation not as "RobustRAG keyword aggregation," but explicitly as a **deterministic categorical aggregation inspired by the isolate-then-aggregate principle of RobustRAG**.

Let $V_{orig}$ be the count of `original-supported` votes.
Let $V_{mut}$ be the count of `mutated-supported` votes.

The current rule (frozen before evaluation) is an experiment-specific adaptation:
* $V_{orig} > V_{mut}$ $\rightarrow$ `original-supported`
* $V_{mut} > V_{orig}$ $\rightarrow$ `mutated-supported`
* $V_{orig} == V_{mut} > 0$ $\rightarrow$ `conflict` / no-decision
* $V_{orig} == V_{mut} == 0$ $\rightarrow$ `insufficient` / no-decision

### 3.4 Clarify Final Generation
Our adaptation does **NOT** reproduce the paper's second-stage keyword-conditioned generation. 
Instead, the final security decision is derived directly from the deterministic categorical aggregation rule. This is intentional because the primary outcome is the structured Type-C security decision rather than free-form answer quality. 
We do not claim this preserves every property or certification guarantee of the original RobustRAG method.

### 3.5 Output Schema
The defense will produce and record data adhering to the following schema per CVE run:

```json
{
  "cve_id": "string",
  "condition": "string",
  "query_type": "Type C",
  "isolated_calls": [
    {
      "doc_id": "string",
      "doc_rank": "integer",
      "response_text": "string",
      "isolated_answer_class": "string",
      "robustrag_vote": "string"
    }
  ],
  "vote_counts": {
    "original-supported": "integer",
    "mutated-supported": "integer",
    "insufficient": "integer",
    "conflict": "integer"
  },
  "tie_breaking_applied": "string",
  "final_answer_class": "string",
  "security_class": "string",
  "latency_ms": "float",
  "llm_call_count": "integer"
}
```

## 4. Limitations
This adaptation has the following strict limitations:
* Does not implement Secure Keyword Aggregation.
* Does not implement Decoding Aggregation.
* Does not reproduce the paper's formal certification procedure.
* Does not establish the paper's theoretical robustness guarantees.
* Tests whether isolation + categorical aggregation is useful for this specific cybersecurity boundary-poisoning task.
