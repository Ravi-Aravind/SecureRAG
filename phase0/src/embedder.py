"""
embedder.py

Step 8: Embedding generation for RAG poisoning experiment.

This module loads formatted documents from data/documents.json, generates
L2-normalized embeddings using sentence-transformers/all-MiniLM-L6-v2,
verifies embedding dimensions and normalization, computes near-duplicate
cosine similarities, and saves the output to data/embeddings.json.

Usage:
    python src/embedder.py
"""

import json
import logging
import sys
from pathlib import Path
import numpy as np
from sentence_transformers import SentenceTransformer

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
EXPECTED_DIM = 384
NORM_TOLERANCE = 1e-5


def l2_normalize(vector: np.ndarray) -> np.ndarray:
    """
    L2-normalizes a 1D or 2D numpy array.
    """
    norm = np.linalg.norm(vector, axis=-1, keepdims=True)
    if np.any(norm == 0):
        raise ValueError("Zero norm encountered during L2 normalization.")
    return vector / norm


def verify_embedding_vector(vector: np.ndarray, label: str = "Embedding"):
    """
    Verifies vector dimension and L2 normalization (norm == 1.0 within tolerance).

    Raises:
        ValueError if dimension is not EXPECTED_DIM or norm differs from 1.0.
    """
    if vector.shape[-1] != EXPECTED_DIM:
        raise ValueError(
            f"{label} dimension mismatch: expected {EXPECTED_DIM}, got {vector.shape[-1]}"
        )

    norm = float(np.linalg.norm(vector))
    if abs(norm - 1.0) > NORM_TOLERANCE:
        raise ValueError(
            f"{label} L2 norm verification failed: norm is {norm:.7f}, expected 1.0 (+/- {NORM_TOLERANCE})"
        )


def generate_embeddings(
    input_path: Path,
    output_path: Path,
    model_name: str = MODEL_NAME,
) -> list[dict]:
    """
    Generates and verifies L2-normalized embeddings for original and mutated docs.

    Raises:
        FileExistsError: If output_path already exists.
        FileNotFoundError: If input_path does not exist.
        ValueError: If embedding dimension or norm checks fail.
    """
    if output_path.exists():
        raise FileExistsError(
            f"Target output file '{output_path}' already exists. Overwriting is prohibited."
        )

    if not input_path.exists():
        raise FileNotFoundError(f"Input file '{input_path}' does not exist.")

    with open(input_path, "r", encoding="utf-8") as f:
        documents = json.load(f)

    logger.info("Loaded %d document records from %s", len(documents), input_path)
    logger.info("Loading embedding model '%s'...", model_name)
    model = SentenceTransformer(model_name)

    results = []
    similarities = []

    for doc in documents:
        cve_id = doc["cve_id"]
        original_doc = doc["original_doc"]
        mutated_doc = doc["mutated_doc"]

        # Encode documents
        raw_orig_emb = model.encode(original_doc, convert_to_numpy=True)
        raw_mut_emb = model.encode(mutated_doc, convert_to_numpy=True)

        # L2-normalize vectors
        orig_emb = l2_normalize(raw_orig_emb)
        mut_emb = l2_normalize(raw_mut_emb)

        # Verify dimension and L2 norm
        verify_embedding_vector(orig_emb, f"CVE {cve_id} original embedding")
        verify_embedding_vector(mut_emb, f"CVE {cve_id} mutated embedding")

        # Compute cosine similarity (inner product on normalized vectors)
        cosine_sim = float(np.dot(orig_emb, mut_emb))
        similarities.append(cosine_sim)

        logger.info(
            "CVE %s | original-mutated cosine similarity: %.6f",
            cve_id,
            cosine_sim,
        )

        results.append(
            {
                "cve_id": cve_id,
                "original_embedding": orig_emb.tolist(),
                "mutated_embedding": mut_emb.tolist(),
                "original_mutated_similarity": cosine_sim,
            }
        )

    # Save output to json
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    logger.info("Saved %d embedding records to %s", len(results), output_path)

    min_sim = float(np.min(similarities))
    max_sim = float(np.max(similarities))
    mean_sim = float(np.mean(similarities))

    print("\n=== Embedding Generation & Verification Summary ===")
    print(f"Total CVEs processed        : {len(documents)}")
    print(f"Embedding Model             : {model_name}")
    print(f"Embedding Dimension         : {EXPECTED_DIM} (Verified)")
    print(f"L2 Normalization Check      : PASSED (Norm = 1.0 +/- {NORM_TOLERANCE})")
    print(f"Original-Mutated Similarities:")
    print(f"  - Min  : {min_sim:.6f}")
    print(f"  - Max  : {max_sim:.6f}")
    print(f"  - Mean : {mean_sim:.6f}")

    return results


def main():
    input_path = PROJECT_ROOT / "data" / "documents.json"
    output_path = PROJECT_ROOT / "data" / "embeddings.json"
    generate_embeddings(input_path, output_path)


if __name__ == "__main__":
    main()
