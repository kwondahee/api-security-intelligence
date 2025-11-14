"""
LangChain RAG System
Implements RAG with LangChain, Qdrant, and Foundation-Sec-8B
Now includes agent source indexing + security KB ingestion.
"""

import logging
import time
import ast
import pathlib
from typing import List, Dict, Any, Optional

# Embeddings & vector DB
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Qdrant

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams
from langchain_core.documents import Document

from llm.cache import RAGCache
from llm.queries import QueryGenerator

logger = logging.getLogger(__name__)


class RAGSystem:
    """
    LangChain-based RAG system with Qdrant vector store.
    """

    def __init__(
        self,
        qdrant_host: str = "localhost",
        qdrant_port: int = 6333,
        collection_name: str = "security_knowledge_base"
    ):
        self.collection_name = collection_name
        self.qdrant_host = qdrant_host
        self.qdrant_port = qdrant_port
        self.cache = RAGCache()
        self.query_generator = QueryGenerator()

        logger.info("Initializing LangChain RAG System (Qdrant)...")

        # ---------------------------------------------------------
        # Embeddings
        # ---------------------------------------------------------
        self.embeddings = HuggingFaceEmbeddings(
            model_name="BAAI/bge-large-en-v1.5",
            model_kwargs={'device': 'cuda' if self._has_cuda() else 'cpu'},
            encode_kwargs={'normalize_embeddings': True},
        )

        dim = len(self.embeddings.embed_query("test"))

        # ---------------------------------------------------------
        # Qdrant client
        # ---------------------------------------------------------
        self.client = QdrantClient(url=f"http://{qdrant_host}:{qdrant_port}")

        # Ensure collection exists
        try:
            self.client.get_collection(collection_name)
            logger.info(f"[QDRANT] Using existing collection: {collection_name}")
        except Exception:
            logger.warning(f"[QDRANT] Creating new collection: {collection_name}")
            self.client.recreate_collection(
                collection_name=collection_name,
                vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
            )

        # ---------------------------------------------------------
        # LangChain wrapper
        # ---------------------------------------------------------
        self.vectorstore = Qdrant(
            client=self.client,
            collection_name=collection_name,
            embeddings=self.embeddings,
        )

        logger.info("RAG System initialized ✔")

        # ---------------------------------------------------------
        # Index agent source files
        # ---------------------------------------------------------
        try:
            self.add_agent_sources()
        except Exception as e:
            logger.warning(f"[RAG] Agent indexing failed: {e}")

        # ---------------------------------------------------------
        # Index security knowledge base documents
        # ---------------------------------------------------------
        try:
            self.load_security_docs()
        except Exception as e:
            logger.warning(f"[RAG] Security KB indexing failed: {e}")

    # ---------------------------------------------------------
    # Utilities
    # ---------------------------------------------------------
    def _has_cuda(self) -> bool:
        try:
            import torch
            return torch.cuda.is_available()
        except Exception:
            return False

    def _deduplicate_results(self, documents):
        seen = {}
        for doc in documents:
            key = f"{doc.get('source','Unknown')}:{doc.get('text','')[:100]}"
            if key not in seen:
                seen[key] = doc
        return list(seen.values())

    # ---------------------------------------------------------
    # Retrieval
    # ---------------------------------------------------------
    def retrieve(self, query=None, severity='MEDIUM', agent_name=None, finding=None, top_k=5):
        start = time.time()

        if agent_name and finding:
            query = self.query_generator.generate(agent_name, finding)

        if not query:
            logger.warning("No query passed to RAG.retrieve()")
            return []

        cached = self.cache.get(query, severity)
        if cached:
            logger.info(f"[RAG] Cache hit")
            return cached

        try:
            results = self.vectorstore.similarity_search_with_score(query, k=top_k * 2)

            docs = [
                {
                    "text": doc.page_content,
                    "metadata": doc.metadata,
                    "source": doc.metadata.get("source", "Unknown"),
                    "score": float(score)
                }
                for doc, score in results
            ]

            docs = self._deduplicate_results(docs)[:top_k]

            self.cache.set(query, docs, severity)

            logger.info(f"[RAG] Retrieved {len(docs)} docs in {(time.time()-start)*1000:.1f}ms")
            return docs

        except Exception as e:
            logger.error(f"[RAG] Retrieval failed: {e}")
            return []

    # ---------------------------------------------------------
    # Add documents
    # ---------------------------------------------------------
    def add_documents(self, documents, skip_cache_invalidation=False):
        langchain_docs = [
            Document(page_content=doc["text"], metadata=doc.get("metadata", {}))
            for doc in documents
        ]
        try:
            self.vectorstore.add_documents(langchain_docs)
            if not skip_cache_invalidation:
                self.cache.on_kb_update()
        except Exception as e:
            logger.error(f"[RAG] Failed to add docs: {e}")

    # ---------------------------------------------------------
    # Security KB ingestion
    # ---------------------------------------------------------
    def load_security_docs(self, kb_dir=None):
        if kb_dir is None:
            kb_dir = pathlib.Path(__file__).resolve().parent / "security_kb"

        documents = []

        for ext in ("*.md", "*.txt"):
            for file in pathlib.Path(kb_dir).glob(ext):
                try:
                    text = file.read_text()
                    documents.append({
                        "text": text,
                        "source": f"kb::{file.name}",
                        "metadata": {"file": str(file)}
                    })
                except Exception as e:
                    logger.warning(f"[RAG] Could not read {file.name}: {e}")

        if documents:
            self.add_documents(documents)
            logger.info(f"[RAG] Indexed {len(documents)} security KB documents.")
        else:
            logger.warning("[RAG] No security KB documents found.")

    # ---------------------------------------------------------
    # Agent source indexing
    # ---------------------------------------------------------
    def add_agent_sources(self, agents_dir=None):
        if agents_dir is None:
            agents_dir = str(pathlib.Path(__file__).resolve().parent.parent / "agents")

        documents = []
        for path in pathlib.Path(agents_dir).glob("*.py"):
            try:
                src = path.read_text()
                tree = ast.parse(src)
                doc = ast.get_docstring(tree)
                name = path.stem.replace("_agent", "").capitalize() + "Agent"

                content = f"{name} source summary:\n{doc or src[:800]}"

                documents.append({
                    "text": content,
                    "source": f"agent::{name}",
                    "metadata": {"file": str(path)},
                })

            except Exception as e:
                logger.warning(f"[RAG] Could not parse {path.name}: {e}")

        if documents:
            self.add_documents(documents, skip_cache_invalidation=True)
            logger.info(f"[RAG] Indexed {len(documents)} agent files.")

    def get_cache_stats(self):
        """
        Returns simple cache statistics for debugging KB initialization.
        This prevents initialize_kb.py from crashing if cache methods
        are not fully implemented.
        """
        stats = {}

        # Check if cache exists
        if hasattr(self, "cache") and isinstance(self.cache, dict):
            stats["cache_enabled"] = True
            stats["cache_entries"] = len(self.cache)
        else:
            stats["cache_enabled"] = False
            stats["cache_entries"] = 0

        # Optional: KB version tracking
        if hasattr(self, "kb_version"):
            stats["kb_version"] = self.kb_version

        return stats
