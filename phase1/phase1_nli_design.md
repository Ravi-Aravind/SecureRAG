# Phase 1 NLI Contradiction Detection Design

## 1. Method Identification
* **Defense Category**: Retrieval-layer filtering via Natural Language Inference (NLI) conflict detection.
* **Objective**: Identify and filter injected malicious documents by cross-examining the retrieved evidence set for semantic contradictions before passing context to the generator.

## 2. NLI Model Identification
* **Model**: `cross-encoder/nli-deberta-v3-large`
* **Architecture**: DeBERTa-v3 (Large), fine-tuned specifically on MNLI, SNLI, and ANLI datasets. It is widely considered the open-weight state-of-the-art for zero-shot NLI tasks.

## 3. Model / License / Reproducibility
* **License**: MIT License (fully permissive).
* **Availability**: Hosted freely on HuggingFace Model Hub.
* **Inference Requirements**: Standard PyTorch/Transformers pipeline. Runs locally offline (no API costs).
* **Reproducibility**: 100% deterministic given a fixed model version and precision (e.g., FP32 or FP16).

## 4. Threat-Model Compatibility
This defense operates purely on the retrieved external documents. It does not rely on the LLM's internal knowledge, preserving the strict private-KB Type-C probe constraint (`Do not use external knowledge`). It directly targets the retrieval-corruption threat model by identifying mutations that conflict with the consensus of original retrieved documents.

## 5. Premise/Hypothesis Construction
For a retrieved set of $k=5$ documents, NLI is executed **pairwise** across all distinct document pairs.
* **Premise**: Retrieved Document $A$
* **Hypothesis**: Retrieved Document $B$
* Because NLI is directional, both $(A, B)$ and $(B, A)$ are evaluated, resulting in $5 \times 4 = 20$ directed inference passes per CVE.

## 6. NLI Decision Rule
The model outputs logits for three classes: `Contradiction`, `Entailment`, and `Neutral`.
* **Decision**: A directed pair $(A, B)$ is classified as a contradiction if and only if the `Contradiction` class has the highest probability (the argmax label).
* **Low-Confidence Prediction**: Since we use the argmax label, the prediction with the highest relative logit wins. We do not require a strict probability threshold (e.g., > 0.90), avoiding arbitrary parameter tuning.

## 7. Contradiction Threshold
* **Threshold**: Model default `argmax`. No continuous probability threshold is enforced.
* **Conflict Symmetry**: Documents $A$ and $B$ are considered to be in **conflict** if *either* $NLI(A, B) == Contradiction$ OR $NLI(B, A) == Contradiction$.

## 8. Evidence Filtering Rule
We define a completely parameter-free consensus filter based on minimizing contradiction:
1. For each document $D_i$, compute its **Contradiction Score** ($C_i$): the total number of other documents in the retrieved set with which it conflicts. (Max score = 4).
2. Find the minimum contradiction score across the set: $C_{min} = \min(C_1, C_2, C_3, C_4, C_5)$.
3. **Retention**: Retain document $D_i$ if and only if $C_i == C_{min}$. Filter all others.

*Example*: 1 mutated document contradicts 4 original documents. The mutated document has $C_i = 4$. The originals have $C_i = 1$. $C_{min} = 1$. The mutated document is filtered; the 4 originals are retained.

## 9. Multi-Document Behavior
The Minimum Contradiction Score rule dynamically handles arbitrary injection ratios:
* **2 Mutated vs 3 Original**: Mutated score = 3, Original score = 2. $C_{min} = 2$. Originals are retained.
* **Perfect 1-to-1 splits or chaotic contradictions**: Handled gracefully by the $C_{min}$ retention logic (see section 10).

## 10. All-Filtered Behavior
By mathematical definition, the subset of documents achieving the minimum score in a finite set is always $\ge 1$. Therefore, this rule **guarantees that the retained evidence set is never empty**. 
* If all documents perfectly contradict each other (all score 4), $C_{min} = 4$. All documents are retained, passing the conflict to the generator (fallback to standard Phase 0 behavior).

## 11. Generation Behavior
* Retained documents are concatenated in their original rank order.
* The concatenated context is passed to the frozen Phase 0 LLM generator using the frozen Phase 0 system prompt and Type-C probe wording.

## 12. Output Schema
The JSON output for each CVE must strictly contain:
* `cve_id`
* `retrieved_documents` (list of 5 doc_ids and ranks)
* `nli_model`: `cross-encoder/nli-deberta-v3-large`
* `nli_matrix`: $5 \times 5$ matrix detailing the exact `[Contradiction, Entailment, Neutral]` probabilities for every $(A, B)$ directed pair.
* `contradiction_scores`: Dict mapping `doc_id` to $C_i$.
* `c_min`: The minimum contradiction score found.
* `retained_documents`: List of `doc_ids` passed to generation.
* `filtered_documents`: List of `doc_ids` dropped.
* `isolated_prompt`: The exact string passed to the LLM.
* `raw_response`: The LLM's text response.
* `phase0_classification`: The classifier's mapping of the response.
* `security_class`: The final security consequence (e.g., false_positive, correct_not_affected).
* `latency_ms`: Total latency, optionally split by NLI and LLM time.

## 13. Parameter Provenance
| Parameter | Value | Provenance |
| :--- | :--- | :--- |
| NLI Model | `cross-encoder/nli-deberta-v3-large` | Externally sourced (HF State-of-the-Art) |
| Decision Threshold | Argmax | Model default |
| Conflict Symmetry | `OR` logic | Experiment-specific adaptation (maximizes recall of anomalies) |
| Filtering Rule | Minimum Contradiction Score | Experiment-specific adaptation (parameter-free consensus heuristic) |

## 14. Offline Validation Plan
Before running the 25-CVE evaluation, we will test the NLI implementation offline:
1. **NLI Functionality**: Feed the model a clear contradiction ("The server requires version 1.0" vs "The server requires version 2.0") and verify the argmax is `Contradiction`.
2. **Matrix Construction**: Ensure the $5 \times 5$ matrix avoids self-comparison (diagonal = neutral or ignored) and successfully aggregates the symmetric `OR` conflict logic.
3. **Filtering Logic**: Unit test the $C_{min}$ retention rule against simulated edge cases (e.g., 2 vs 3, 1 vs 4, all-0, all-4) to verify the retained set is never empty and correctly isolates the majority consensus.
4. **Schema serialization**: Verify numpy/tensor outputs are safely serialized to standard JSON floats.

## 15. Known Limitations
* NLI models are generally trained on broad semantic tasks (e.g., SNLI, MNLI) and may struggle with highly specific numerical boundary contradictions (e.g., "prior to 1.2.2" vs "prior to 1.2.3"). 
* This experiment will empirically measure whether state-of-the-art NLI generalizes to cybersecurity version-boundary conflicts without domain-specific fine-tuning.

## 16. Explicit Non-Goals
* **DO NOT** assume NLI successfully detects the one-token mutation. We will record the exact probabilities in the `nli_matrix` to objectively measure the model's sensitivity.
* **DO NOT** fine-tune the NLI model on the CVE dataset.
* **DO NOT** tune a continuous probability threshold using the 25 evaluation CVEs to artificially boost performance.

## DESIGN STATUS
**APPROVED FOR IMPLEMENTATION**
The methodology requires no external knowledge, uses completely frozen datasets/prompts, implements a mathematically parameter-free consensus filter, and cleanly isolates the evaluation of open-weight NLI efficacy in KB-resolution tasks.

