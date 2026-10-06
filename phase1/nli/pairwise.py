from typing import List, Dict, Any, Callable
from .schemas import DirectedPair

def map_labels(prediction: List[Dict[str, float]]) -> Dict[str, float]:
    """
    Standardize the HF pipeline output. DeBERTa-v3 MNLI typically uses:
    LABEL_0: entailment
    LABEL_1: neutral
    LABEL_2: contradiction
    But pipeline output has 'label' and 'score'.
    We will map 'contradiction', 'entailment', 'neutral' explicitly.
    """
    out = {"contradiction": 0.0, "entailment": 0.0, "neutral": 0.0}
    for item in prediction:
        label = item["label"].lower()
        if "contradiction" in label:
            out["contradiction"] = float(item["score"])
        elif "entailment" in label:
            out["entailment"] = float(item["score"])
        elif "neutral" in label:
            out["neutral"] = float(item["score"])
        else:
            # Fallback if mapped to LABEL_0/1/2
            if label == "label_0":
                out["entailment"] = float(item["score"])
            elif label == "label_1":
                out["neutral"] = float(item["score"])
            elif label == "label_2":
                out["contradiction"] = float(item["score"])
    return out

def get_argmax(probs: Dict[str, float]) -> str:
    # Deterministic max
    # Sorted items to guarantee deterministic tie-breaking (alphabetical) if exactly equal
    return max(sorted(probs.items()), key=lambda x: x[1])[0]

def execute_pairwise_nli(documents: List[Dict[str, Any]], predict_fn: Callable) -> List[DirectedPair]:
    """
    Given k documents, computes the k*(k-1) directed NLI pairs.
    """
    results = []
    
    # Pre-sort documents by rank to guarantee deterministic iteration order
    sorted_docs = sorted(documents, key=lambda x: x["rank"])
    
    for src in sorted_docs:
        for tgt in sorted_docs:
            if src["doc_id"] == tgt["doc_id"]:
                continue # No self-pairs
                
            premise = src["text"]
            hypothesis = tgt["text"]
            
            # Predict
            # HF Pipeline expects {"text": premise, "text_pair": hypothesis}
            raw_pred = predict_fn({"text": premise, "text_pair": hypothesis})
            
            # Extract standard probabilities
            if isinstance(raw_pred, list) and isinstance(raw_pred[0], list):
                raw_pred = raw_pred[0] # pipeline returns [[{label: score}, ...]]
                
            probs = map_labels(raw_pred)
            argmax_label = get_argmax(probs)
            
            results.append(DirectedPair(
                source_doc_id=src["doc_id"],
                source_rank=src["rank"],
                target_doc_id=tgt["doc_id"],
                target_rank=tgt["rank"],
                premise=premise,
                hypothesis=hypothesis,
                p_contradiction=probs["contradiction"],
                p_entailment=probs["entailment"],
                p_neutral=probs["neutral"],
                argmax_label=argmax_label.capitalize()
            ))
            
    return results

