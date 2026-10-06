# NLI Contradiction-Filtering Adaptation: Implementation Details

## Methodology Distinction
This module implements the **NLI-based contradiction-filtering adaptation**. It does *not* represent a specific end-to-end published framework (such as ClaimGuard or MAC) in its entirety. Instead, it adapts the widely recognized core principle of NLI consensus filtering to the strict constraints of the Phase 0 frozen experiment (specifically the isolation from internal knowledge and strict zero-shot evaluation).

## Exact Implementation
The implementation (`phase1/nli/`) comprises a deterministic offline pipeline:
1. **Model Loader**: `nli_model.py` loads `cross-encoder/nli-deberta-v3-large` via HuggingFace `transformers` in evaluation mode.
2. **Pairwise Inference**: `pairwise.py` generates all 20 directed $(A, B)$ combinations for the 5 retrieved documents per CVE, explicitly extracting `[Contradiction, Entailment, Neutral]` probabilities and the argmax label.
3. **Filtering**: `filtering.py` implements the parameter-free **Minimum Contradiction Consensus Rule**:
   * Conflict is defined as an `OR` threshold over the argmax `Contradiction` label across directed pairs.
   * Documents achieving the minimum conflict score are retained.
   * Total ties fall back safely to retaining all documents.
4. **Generator Handoff**: `runner.py` preserves the strictly formatted Type-C probe and passes only the filtered subset to the frozen `openai/gpt-4o-mini` generation settings.

## Parameters and Provenance
| Parameter | Value | Provenance |
| :--- | :--- | :--- |
| NLI Model | `cross-encoder/nli-deberta-v3-large` | Externally sourced (State of the art HF MNLI) |
| Device | `cuda:0` / `cpu` | Hardware dependent |
| Probability threshold | Argmax label | Model default |
| Filtering Selection | $C_{min}$ retention | Experiment-specific adaptation |
| Tie-breaking | Retain all | Experiment-specific adaptation (fails safe) |

## Dependencies
* `transformers`
* `torch`
(If unavailable, `runner.py` explicitly traps the `ImportError` and raises an execution blocker rather than silently substituting a different model).

## Reproducibility Considerations
* **Determinism**: Inference uses `model.eval()`, sorts document matrices explicitly by original rank, and avoids stochastic pipeline sampling (`top_k=None`). 
* **Float precision**: Minor variations in floating-point outputs ($\sim 1e^{-5}$) may occur across different hardware (e.g., CPU vs GPU tensor cores), but the discrete `argmax` labels controlling the decision boundary remain highly stable.

## Limitations
* No continuous thresholding is applied (e.g., rejecting weak entailments).
* Relies on a general-purpose NLI model applied zero-shot to highly specific cybersecurity version boundary contexts.

