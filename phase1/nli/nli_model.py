import os
from .config import NLI_MODEL_NAME

def load_nli_model():
    """
    Attempts to load the HuggingFace NLI model deterministically.
    If dependencies or weights are unavailable, returns None, error_msg
    rather than silently substituting.
    """
    try:
        import torch
        from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    except ImportError as e:
        return None, None, f"Dependency missing: {str(e)}"

    try:
        device = 0 if torch.cuda.is_available() else -1
        
        # Explicit deterministic load
        tokenizer = AutoTokenizer.from_pretrained(NLI_MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(NLI_MODEL_NAME)
        
        # Disable stochastic sampling, purely deterministic argmax pipeline
        model.eval()
        
        pipe = pipeline(
            "text-classification", 
            model=model, 
            tokenizer=tokenizer,
            device=device,
            top_k=None # returns all scores
        )
        
        metadata = {
            "model_identifier": NLI_MODEL_NAME,
            "device": "cuda:0" if device == 0 else "cpu",
            "transformers_version": __import__('transformers').__version__,
            "torch_version": torch.__version__
        }
        
        return pipe, metadata, None
        
    except Exception as e:
        return None, None, f"Failed to load weights for {NLI_MODEL_NAME}: {str(e)}"

