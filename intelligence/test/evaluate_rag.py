#!/usr/bin/env python3
"""
evaluate_rag.py — Evaluate RAG retrieval accuracy using a small benchmark dataset.
Now automatically ignores agent:: documents during scoring.
"""
import sys, pathlib
sys.path.append(str(pathlib.Path(__file__).resolve().parent.parent)) 
import json
import logging
import numpy as np
from pathlib import Path
from llm.rag import RAGSystem

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Locate dataset
dataset_path = Path(__file__).resolve().parent / "rag_eval_dataset.json"

# Load dataset
def load_dataset():
    with open(dataset_path, "r", encoding="utf-8") as f:
        return json.load(f)

def cosine_similarity(a, b):
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-8)

def evaluate_retrieval(rag: RAGSystem, top_k: int = 3):
    dataset = load_dataset()
    recalls, precisions, mrrs, similarities = [], [], [], []

    print("\n=== 🧩 RAG RETRIEVAL EVALUATION ===")

    for item in dataset:
        query = item["query"]
        expected_sources = set(item["expected_sources"])

        # Retrieve results
        results = rag.retrieve(query=query, top_k=top_k)

        # ✅ Filter out agent documents
        filtered_results = [r for r in results if not r["source"].startswith("agent::")]

        retrieved_sources = [r["source"] for r in filtered_results]
        retrieved_texts = [r["text"] for r in filtered_results]

        hits = sum(1 for src in retrieved_sources if src in expected_sources)
        recall = hits / len(expected_sources)
        precision = hits / len(retrieved_sources) if retrieved_sources else 0

        # Compute MRR
        reciprocal_rank = 0
        for rank, src in enumerate(retrieved_sources, start=1):
            if src in expected_sources:
                reciprocal_rank = 1 / rank
                break

        # Semantic similarity
        try:
            emb_q = rag.embeddings.embed_query(query)
            emb_docs = [rag.embeddings.embed_query(text) for text in retrieved_texts]
            sem_sim = np.mean([cosine_similarity(emb_q, d) for d in emb_docs]) if emb_docs else 0
        except Exception:
            sem_sim = 0

        recalls.append(recall)
        precisions.append(precision)
        mrrs.append(reciprocal_rank)
        similarities.append(sem_sim)

        print(f" - {query}: hits={hits}, recall={recall:.2f}, precision={precision:.2f}, mrr={reciprocal_rank:.2f}, sem={sem_sim:.2f}")
        print(f"   expected={list(expected_sources)}")
        print(f"   retrieved={retrieved_sources}\n")

    print(f"Avg Recall@{top_k}: {np.mean(recalls):.3f}")
    print(f"Avg Precision@{top_k}: {np.mean(precisions):.3f}")
    print(f"Mean Reciprocal Rank (MRR): {np.mean(mrrs):.3f}")
    print(f"Avg Semantic Similarity: {np.mean(similarities):.3f}")

# --------------------------------------------------------
# Step 5 – Re-initialize KB (optional safety)
# --------------------------------------------------------
def ensure_kb_initialized():
    """
    Optional step to ensure the KB is ready before evaluation.
    Only initializes if collection is empty.
    """
    print("[INIT] Loading RAG system...")
    rag = RAGSystem()

    # Quick sanity check
    results = rag.langchain_milvus.similarity_search("SQL injection prevention", k=1)
    if not results or all(r.metadata.get("source", "").startswith("agent::") for r in results):
        print("[INFO] KB may be empty or agent-only. Consider re-running initialize_kb.py first.")
    else:
        print("[INFO] KB detected with security documents.")
    return rag

if __name__ == "__main__":
    rag = ensure_kb_initialized()
    evaluate_retrieval(rag)
