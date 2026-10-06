# Phase 1 TrustRAG Design & Verification Gate

## 1. Method Identification
* **Paper Title**: TrustRAG: Enhancing Robustness and Trustworthiness in Retrieval-Augmented Generation
* **Authors**: Huichi Zhou et al.
* **Publication**: arXiv:2501.00879 (Jan 2025)

## 2. Published TrustRAG Method
TrustRAG is a plug-and-play, training-free framework designed to defend against corpus poisoning attacks. It operates in two stages:
* **Stage 1 (Clean Retrieval)**: Employs K-means clustering ($k=2$) on retrieved document embeddings. It uses ROUGE-L scores and cosine similarity to evaluate document content and isolate suspicious items, targeting both multi-injection and single-injection attacks.
* **Stage 2 (Self-Assessment)**: Leverages the LLM's own reasoning to resolve discrepancies between the filtered external retrieved context and the LLM's internal knowledge.

## 3. Threat-Model Comparison
* **TrustRAG Threat Model**: Assumes attackers inject one or more malicious documents into the corpus. Assumes the LLM's internal knowledge is clean and can be used to vet external context.
* **Phase 0 Threat Model**: Identical in attack vector (mutated document injection). However, fundamentally conflicts on Stage 2: Phase 0 uses a strict private-KB Type-C probe where the LLM is explicitly forbidden from using internal knowledge (`Do not use external knowledge`).

## 4. Reproducibility Assessment
The exact published method **cannot** be directly reproduced with the frozen Phase 0 corpus due to structural conflicts, specifically the reliance on Stage 2 internal-knowledge self-assessment, which violates our experiment's constraints. 

## 5. Critical Methodological Assumption Audit

**Does TrustRAG equate the tightest cluster with maliciousness?**
No. While multi-injection attacks may form tight clusters, single-injection attacks do not. TrustRAG does not blindly filter the "tightest" cluster; it uses ROUGE-L and Stage-2 LLM self-assessment to evaluate actual content anomalies. Forcing a rule that "tighter cluster = attack" is an unprincipled assumption.

**Does it assume one malicious cluster?**
No. TrustRAG evaluates clusters dynamically. It does not implicitly assume every retrieval contains an attack.

**How does it use ROUGE-L?**
ROUGE-L is utilized alongside cosine similarity to detect content overlap anomalies, specifically targeting single-injection attacks which evade simple density-based K-means detection.

**What happens when all retrieved documents are legitimate?**
In the published method, if documents pass anomaly thresholds and align with the LLM's internal knowledge (Stage 2), they are retained. There is no forced filtering of clean documents.

**What happens when there is only one anomalous document?**
Single-injection attacks are handled via the ROUGE-L structural checks and Stage-2 self-assessment, as they do not form a dense attack cluster in K-means.

**What happens when there are multiple clusters?**
K-means ($k=2$) splits the space, but actual filtering is contingent on anomaly thresholds and Stage-2 verification, not an unconditional rejection of one cluster.

**What information is required to identify a cluster as suspicious?**
1. Un-tuned, data-dependent anomaly thresholds (for similarity/ROUGE-L).
2. The Stage-2 LLM consistency check against internal knowledge.

**Which parts can be reproduced under our frozen experiment?**
Only the naive K-means partitioning of embeddings. The actual filtering decision logic **cannot** be reproduced. We cannot use Stage-2 (violates Phase 0 system prompt), and we cannot establish similarity thresholds because we are forbidden from tuning parameters on the 25 evaluation CVEs. 

## 6. Parameter Provenance
* **Clustering Algorithm (K-means, k=2)**: Published-method parameter.
* **Similarity/ROUGE-L anomaly thresholds**: Unknown / cannot be defined without prohibited tuning.
* **Filtering Rule (Tighter cluster = filter)**: Rejected experiment-specific adaptation (invalidated by this audit).
* **Stage 2 LLM Vetting**: Published-method parameter (Cannot be used due to experimental constraints).

## 7. Known Limitations & Explicit Non-Reproduction
**WE ARE EXPLICITLY NOT REPRODUCING:**
* The Stage 2 Self-Assessment mechanism (due to the strict "No external/internal knowledge" constraint of the Phase 0 prompt).
* The actual decision boundary for filtering, which requires internal knowledge and untuned thresholds.

## DESIGN STATUS
**NOT APPROVED — unresolved methodological issue.**

*Reasoning*: The adaptation previously proposed an arbitrary rule ("filter the tighter cluster") that lacked support in the published TrustRAG method. TrustRAG relies heavily on LLM internal-knowledge self-assessment (Stage 2) and tuned ROUGE-L thresholds to identify anomalies, neither of which are permitted under the frozen Phase 0 constraints. Without Stage 2 and without tuning thresholds, the framework would be forced to blindly discard documents in clean (Condition A) scenarios, severely misrepresenting the published defense and guaranteeing artificially degraded performance.
