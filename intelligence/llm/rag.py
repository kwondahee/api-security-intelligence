# rag/rag.py
"""
LangChain RAG System
Implements RAG with LangChain, Milvus, and Foundation-Sec-8B
Now includes agent source indexing to improve LLM reasoning accuracy.
"""

import logging
import time
import ast
import pathlib
from typing import List, Dict, Any, Optional

# Use the new langchain-huggingface package
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_milvus import Milvus
from langchain_core.documents import Document

from llm.cache import RAGCache
from llm.queries import QueryGenerator

logger = logging.getLogger(__name__)

class RAGSystem:
    """
    LangChain-based RAG system with Milvus vector store.

    Features:
    - Milvus vector database (IVF_FLAT index)
    - BGE-Large-en-v1.5 embeddings
    - Severity-based caching
    - Query optimization
    - Agent source embedding for context-aware reasoning
    """

    def __init__(
        self,
        milvus_host: str = "localhost",
        milvus_port: int = 19530,
        collection_name: str = "security_knowledge_base"
    ):
        self.collection_name = collection_name
        self.milvus_host = milvus_host
        self.milvus_port = milvus_port
        self.cache = RAGCache()
        self.query_generator = QueryGenerator()

        logger.info("Initializing LangChain RAG System...")

        # Initialize embeddings (BGE-Large-en-v1.5)
        self.embeddings = HuggingFaceEmbeddings(
            model_name="BAAI/bge-large-en-v1.5",
            model_kwargs={'device': 'cuda' if self._has_cuda() else 'cpu'},
            encode_kwargs={'normalize_embeddings': True}
        )

        # Initialize Milvus vector store
        try:
            self.langchain_milvus = Milvus(
                embedding_function=self.embeddings,
                collection_name=collection_name,
                connection_args={"host": milvus_host, "port": milvus_port},
                drop_old=False,
                auto_id=True
            )
            logger.info("RAG System initialized successfully")
        except Exception as e:
            logger.warning(f"Collection may need to be recreated: {e}")
            logger.info("Attempting to recreate collection with correct schema...")
            self.langchain_milvus = Milvus(
                embedding_function=self.embeddings,
                collection_name=collection_name,
                connection_args={"host": milvus_host, "port": milvus_port},
                drop_old=True,
                auto_id=True
            )
            logger.info("RAG System initialized successfully (collection recreated)")

        # Automatically index agent files for reasoning context
        try:
            self.add_agent_sources()
            logger.info("[RAG] Agent source files successfully indexed for LLM reasoning.")
        except Exception as e:
            logger.warning(f"[RAG] Failed to index agent files into Milvus: {e}")

    # -----------------------------------------------------
    # UTILITIES
    # -----------------------------------------------------

    def _has_cuda(self) -> bool:
        """Check if CUDA is available."""
        try:
            import torch
            return torch.cuda.is_available()
        except Exception:
            return False

    def _deduplicate_results(self, documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate results based on source and text content."""
        seen = {}
        for doc in documents:
            source = doc.get('source', 'Unknown')
            text_preview = doc.get('text', '')[:100]
            key = f"{source}:{text_preview}"

            if key not in seen or doc.get('score', 0) > seen[key].get('score', 0):
                seen[key] = doc
        return list(seen.values())

    # -----------------------------------------------------
    # CORE METHODS
    # -----------------------------------------------------

    def retrieve(
        self,
        query: Optional[str] = None,
        severity: str = 'MEDIUM',
        agent_name: Optional[str] = None,
        finding: Optional[Dict[str, Any]] = None,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant documents using LangChain + Milvus.

        Args:
            query: Search query or generated reasoning string
            severity: Finding severity for cache TTL
            agent_name: Name of requesting agent
            finding: Full finding dict for contextual search
            top_k: Number of documents to retrieve

        Returns:
            List of relevant documents (deduplicated)
        """
        start_time = time.time()

        # Generate optimized query if agent + finding context given
        if agent_name and finding:
            query = self.query_generator.generate(agent_name, finding)
            logger.info(f"Generated query for {agent_name}: {query[:100]}...")

        if not query:
            logger.warning("No query provided to RAG retrieval.")
            return []

        # Check RAG cache first
        cached = self.cache.get(query, severity)
        if cached is not None:
            latency = (time.time() - start_time) * 1000
            logger.info(f"[RAG-CACHE] HIT - {len(cached)} docs (latency: {latency:.1f}ms)")
            return cached

        try:
            fetch_k = top_k * 2
            results_with_scores = self.langchain_milvus.similarity_search_with_score(query=query, k=fetch_k)

            documents = [
                {
                    'text': doc.page_content,
                    'source': doc.metadata.get('source', 'Unknown'),
                    'metadata': doc.metadata,
                    'score': float(score)
                }
                for doc, score in results_with_scores
            ]

            documents = self._deduplicate_results(documents)
            documents = documents[:top_k]
            self.cache.set(query, documents, severity)

            latency = (time.time() - start_time) * 1000
            phase = agent_name or "LLM"
            count = len(documents)
            logger.info(f"[RAG-REASONING] {phase} retrieved {count} relevant document{'s' if count != 1 else ''} in {latency:.1f}ms")
            #logger.info(f"[RAG-REASONING] {agent_name or 'None'} retrieved {len(documents)} docs in {latency:.1f}ms")
            return documents

        except Exception as e:
            logger.error(f"[RAG] Retrieval failed: {e}")
            return []

    def add_documents(self, documents: List[Dict[str, Any]], skip_cache_invalidation: bool = False):
        """Add documents to vector store."""
        langchain_docs = [
            Document(
                page_content=doc['text'],
                metadata={'source': doc.get('source', 'unknown'), **doc.get('metadata', {})}
            )
            for doc in documents
        ]

        try:
            self.langchain_milvus.add_documents(langchain_docs)
            if not skip_cache_invalidation:
                self.cache.on_kb_update()
            logger.info(f"[RAG] Added {len(documents)} documents to vector store.")
        except Exception as e:
            logger.error(f"[RAG] Failed to add documents: {e}")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()

    # -----------------------------------------------------
    # AGENT SOURCE INDEXING
    # -----------------------------------------------------

    def add_agent_sources(self, agents_dir: str = None):
        """
        Index all agent .py files into Milvus so the LLM can reason about their capabilities.
        Each file’s docstring or top 800 chars are embedded into the KB.
        """
        if agents_dir is None:
            agents_dir = str(pathlib.Path(__file__).resolve().parent.parent / "agents")

        documents = []
        for path in pathlib.Path(agents_dir).glob("*.py"):
            try:
                src = path.read_text(encoding="utf-8")
                tree = ast.parse(src)
                doc = ast.get_docstring(tree)
                name = path.stem.replace("_agent", "").capitalize() + "Agent"

                content = f"{name} source summary:\n{doc or src[:800]}"
                documents.append({
                    "text": content,
                    "source": f"agent::{name}",
                    "metadata": {"file": str(path)}
                })
                logger.debug(f"[RAG] Prepared agent document for {name}")

            except Exception as e:
                logger.warning(f"[RAG] Failed to parse {path.name}: {e}")

        if documents:
            self.add_documents(documents, skip_cache_invalidation=True)
            logger.info(f"[RAG] Indexed {len(documents)} agent files into Milvus for LLM reasoning.")
        else:
            logger.warning("[RAG] No agent files found to index.")
