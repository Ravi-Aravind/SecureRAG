"""
retriever.py

Step 9: FAISS retrieval for RAG poisoning experiment.

Loads data/documents.json and data/embeddings.json, builds FAISS IndexFlatIP
indexes for three experimental conditions per CVE (Condition A: clean,
Condition B: mutated-only, Condition C: conflict), evaluates retrieval metrics,
and saves detailed results to data/retrieval_results.json.

Usage:
    python src/retriever.py
"""

import json
import logging
import sys
from pathlib import Path
import numpy as np
import faiss

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def build_index(doc_embeddings: list, doc_ids: list) -> faiss.IndexFlatIP:
    """
    Builds and returns an exact Inner Product (IP) FAISS index.
    For L2-normalized vectors, exact IP corresponds to exact Cosine Similarity.
    """
    if not doc_embeddings:
        raise ValueError("doc_embeddings list cannot be empty.")
    if len(doc_embeddings) != len(doc_ids):
        raise ValueError("Length of doc_embeddings and doc_ids must match.")

    embeddings_array = np.array(doc_embeddings, dtype=np.float32)
    dim = embeddings_array.shape[1]

    index = faiss.IndexFlatIP(dim)
    index.add(embeddings_array)
    return index


def retrieve(
    index: faiss.IndexFlatIP,
    query_embedding: list | np.ndarray,
    doc_ids: list,
    doc_texts: list,
    k: int = 5,
) -> list[dict]:
    """
    Retrieves top-k documents for a query embedding from the FAISS index.

    Returns:
        list of dicts, each containing:
        - rank (int, 1-indexed)
        - doc_id (str)
        - similarity (float)
        - text_preview (str, first 80 characters)
    """
    query_array = np.array([query_embedding], dtype=np.float32)
    k_actual = min(k, index.ntotal)

    distances, indices = index.search(query_array, k_actual)

    results = []
    for idx in range(k_actual):
        doc_idx = int(indices[0][idx])
        sim_score = float(distances[0][idx])
        doc_id = doc_ids[doc_idx]
        text = doc_texts[doc_idx]
        text_preview = text[:80]

        results.append(
            {
                "rank": idx + 1,
                "doc_id": doc_id,
                "similarity": sim_score,
                "text_preview": text_preview,
            }
        )

    return results


def run_retrieval_experiment(
    documents_path: Path,
    embeddings_path: Path,
    output_path: Path,
) -> list[dict]:
    """
    Executes Step 9 retrieval evaluation across Conditions A, B, and C for 25 CVEs.
    """
    if output_path.exists():
        raise FileExistsError(
            f"Target output file '{output_path}' already exists. Overwriting is prohibited."
        )

    if not documents_path.exists():
        raise FileNotFoundError(f"Input documents file '{documents_path}' does not exist.")

    if not embeddings_path.exists():
        raise FileNotFoundError(f"Input embeddings file '{embeddings_path}' does not exist.")

    with open(documents_path, "r", encoding="utf-8") as f:
        documents = json.load(f)

    with open(embeddings_path, "r", encoding="utf-8") as f:
        embeddings = json.load(f)

    logger.info("Loaded %d documents from %s", len(documents), documents_path)
    logger.info("Loaded %d embeddings from %s", len(embeddings), embeddings_path)

    doc_map = {doc["cve_id"]: doc for doc in documents}
    emb_map = {emb["cve_id"]: emb for emb in embeddings}
    cve_ids = [doc["cve_id"] for doc in documents]

    all_results = []

    cond_a_rank1_count = 0
    cond_b_rank1_count = 0
    cond_c_both_in_top5_count = 0
    cond_c_sim_gaps = []

    print("\n--- FAISS Retrieval Co-retrieval Verification (Condition C) ---")

    for target_cve in cve_ids:
        query_emb = emb_map[target_cve]["original_embedding"]
        target_orig_id = f"{target_cve}_orig"
        target_mut_id = f"{target_cve}_mutated"

        # --- Condition A (clean: 25 original docs) ---
        doc_ids_A = [f"{cid}_orig" for cid in cve_ids]
        doc_texts_A = [doc_map[cid]["original_doc"] for cid in cve_ids]
        doc_embs_A = [emb_map[cid]["original_embedding"] for cid in cve_ids]

        index_A = build_index(doc_embs_A, doc_ids_A)
        retrieved_A = retrieve(index_A, query_emb, doc_ids_A, doc_texts_A, k=5)

        orig_rank_A = next(
            (r["rank"] for r in retrieved_A if r["doc_id"] == target_orig_id), None
        )
        orig_sim_A = next(
            (r["similarity"] for r in retrieved_A if r["doc_id"] == target_orig_id), None
        )

        if orig_rank_A == 1:
            cond_a_rank1_count += 1

        all_results.append(
            {
                "cve_id": target_cve,
                "condition": "Condition A",
                "query_cve_id": target_cve,
                "original_rank": orig_rank_A,
                "mutated_rank": "N/A",
                "original_similarity": orig_sim_A,
                "mutated_similarity": None,
                "similarity_gap": None,
                "both_in_top5": False,
                "co_retrieval_confirmed": False,
                "results": retrieved_A,
            }
        )

        # --- Condition B (mutated-only: 24 original + 1 mutated target doc) ---
        doc_ids_B = []
        doc_texts_B = []
        doc_embs_B = []
        for cid in cve_ids:
            if cid != target_cve:
                doc_ids_B.append(f"{cid}_orig")
                doc_texts_B.append(doc_map[cid]["original_doc"])
                doc_embs_B.append(emb_map[cid]["original_embedding"])
            else:
                doc_ids_B.append(f"{cid}_mutated")
                doc_texts_B.append(doc_map[cid]["mutated_doc"])
                doc_embs_B.append(emb_map[cid]["mutated_embedding"])

        index_B = build_index(doc_embs_B, doc_ids_B)
        retrieved_B = retrieve(index_B, query_emb, doc_ids_B, doc_texts_B, k=5)

        mut_rank_B = next(
            (r["rank"] for r in retrieved_B if r["doc_id"] == target_mut_id), None
        )
        mut_sim_B = next(
            (r["similarity"] for r in retrieved_B if r["doc_id"] == target_mut_id), None
        )

        if mut_rank_B == 1:
            cond_b_rank1_count += 1

        all_results.append(
            {
                "cve_id": target_cve,
                "condition": "Condition B",
                "query_cve_id": target_cve,
                "original_rank": None,
                "mutated_rank": mut_rank_B,
                "original_similarity": None,
                "mutated_similarity": mut_sim_B,
                "similarity_gap": None,
                "both_in_top5": False,
                "co_retrieval_confirmed": False,
                "results": retrieved_B,
            }
        )

        # --- Condition C (conflict: 25 original + 1 mutated target doc = 26 docs) ---
        doc_ids_C = [f"{cid}_orig" for cid in cve_ids] + [target_mut_id]
        doc_texts_C = [doc_map[cid]["original_doc"] for cid in cve_ids] + [
            doc_map[target_cve]["mutated_doc"]
        ]
        doc_embs_C = [emb_map[cid]["original_embedding"] for cid in cve_ids] + [
            emb_map[target_cve]["mutated_embedding"]
        ]

        index_C = build_index(doc_embs_C, doc_ids_C)
        retrieved_C = retrieve(index_C, query_emb, doc_ids_C, doc_texts_C, k=5)

        orig_rank_C = next(
            (r["rank"] for r in retrieved_C if r["doc_id"] == target_orig_id), None
        )
        orig_sim_C = next(
            (r["similarity"] for r in retrieved_C if r["doc_id"] == target_orig_id), None
        )

        mut_rank_C = next(
            (r["rank"] for r in retrieved_C if r["doc_id"] == target_mut_id), None
        )
        mut_sim_C = next(
            (r["similarity"] for r in retrieved_C if r["doc_id"] == target_mut_id), None
        )

        both_in_top5_C = (orig_rank_C is not None) and (mut_rank_C is not None)
        if both_in_top5_C:
            cond_c_both_in_top5_count += 1
            print(f"{target_cve}: BOTH RETRIEVED")
        else:
            print(f"{target_cve}: ONLY ONE RETRIEVED")

        sim_gap_C = None
        if orig_sim_C is not None and mut_sim_C is not None:
            sim_gap_C = orig_sim_C - mut_sim_C
            cond_c_sim_gaps.append(sim_gap_C)

        all_results.append(
            {
                "cve_id": target_cve,
                "condition": "Condition C",
                "query_cve_id": target_cve,
                "original_rank": orig_rank_C,
                "mutated_rank": mut_rank_C,
                "original_similarity": orig_sim_C,
                "mutated_similarity": mut_sim_C,
                "similarity_gap": sim_gap_C,
                "both_in_top5": both_in_top5_C,
                "co_retrieval_confirmed": both_in_top5_C,
                "results": retrieved_C,
            }
        )

    # Save to file
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    logger.info("Saved %d retrieval result objects to %s", len(all_results), output_path)

    mean_sim_gap_C = float(np.mean(cond_c_sim_gaps)) if cond_c_sim_gaps else 0.0

    print("\n=== Final Retrieval Summary ===")
    print(f"Condition A: {cond_a_rank1_count} / {len(cve_ids)} CVEs have original doc at rank 1")
    print(f"Condition B: {cond_b_rank1_count} / {len(cve_ids)} CVEs have mutated doc at rank 1")
    print(f"Condition C: {cond_c_both_in_top5_count} / {len(cve_ids)} CVEs have both docs in top-5")
    print(f"Mean similarity gap in Condition C: {mean_sim_gap_C:.6f}")

    return all_results


def main():
    documents_path = PROJECT_ROOT / "data" / "documents.json"
    embeddings_path = PROJECT_ROOT / "data" / "embeddings.json"
    output_path = PROJECT_ROOT / "data" / "retrieval_results.json"

    run_retrieval_experiment(documents_path, embeddings_path, output_path)


if __name__ == "__main__":
    main()
