# rag/rag.py
"""
LangChain RAG System
Implements RAG with LangChain, Milvus, and Foundation-Sec-8B
"""

import logging
import time
from typing import List, Dict, Any, Optional

# Use the new langchain-huggingface package
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_milvus import Milvus

# this version is old so changed to langchain_core
# from langchain.schema import Document

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
    - Result deduplication
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
        
        # Initialize LangChain Milvus wrapper
        try:
            self.langchain_milvus = Milvus(
                embedding_function=self.embeddings,
                collection_name=collection_name,
                connection_args={"host": milvus_host, "port": milvus_port},
                drop_old=False,  # Don't drop existing collection
                auto_id=True     # Fix auto_id warning
            )
            logger.info("RAG System initialized successfully")
        except Exception as e:
            logger.warning(f"Collection may need to be recreated: {e}")
            # Try dropping and recreating
            logger.info("Attempting to recreate collection with correct schema...")
            self.langchain_milvus = Milvus(
                embedding_function=self.embeddings,
                collection_name=collection_name,
                connection_args={"host": milvus_host, "port": milvus_port},
                drop_old=True,   # Drop and recreate
                auto_id=True     # Fix auto_id warning
            )
            logger.info("RAG System initialized successfully (collection recreated)")
    
    def _has_cuda(self) -> bool:
        """Check if CUDA is available."""
        try:
            import torch
            return torch.cuda.is_available()
        except:
            return False
    
    def _deduplicate_results(self, documents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate results based on source and text content.
        Keep the result with the highest score for duplicates.
        """
        seen = {}
        
        for doc in documents:
            source = doc.get('source', 'Unknown')
            text_preview = doc.get('text', '')[:100]  # First 100 chars as key
            key = f"{source}:{text_preview}"
            
            if key not in seen:
                seen[key] = doc
            else:
                # Keep the one with higher score
                if doc.get('score', 0) > seen[key].get('score', 0):
                    seen[key] = doc
        
        return list(seen.values())
    
    def retrieve(
        self,
        query: str = None,
        severity: str = 'MEDIUM',
        agent_name: Optional[str] = None,
        finding: Optional[Dict[str, Any]] = None,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant documents using LangChain + Milvus.
        
        Args:
            query: Search query
            severity: Finding severity for cache TTL
            agent_name: Name of requesting agent
            finding: Full finding dict
            top_k: Number of documents to retrieve
            
        Returns:
            List of relevant documents (deduplicated)
        """
        start_time = time.time()
        
        # Generate optimized query if agent context provided
        if agent_name and finding:
            query = self.query_generator.generate(agent_name, finding)
            logger.info(f"Generated query for {agent_name}: {query[:80]}...")
        
        if not query:
            logger.warning("No query provided")
            return []
        
        # Check cache
        cached = self.cache.get(query, severity)
        if cached is not None:
            latency = (time.time() - start_time) * 1000
            logger.info(f"Cache HIT - {len(cached)} docs (latency: {latency:.1f}ms)")
            return cached
        
        # Perform retrieval using LangChain with similarity scores
        try:
            # Retrieve more than needed to account for deduplication
            fetch_k = top_k * 2
            
            # Use similarity_search_with_score to get scores
            results_with_scores = self.langchain_milvus.similarity_search_with_score(
                query=query,
                k=fetch_k
            )
            
            # Convert LangChain Documents to dict format
            documents = []
            for doc, score in results_with_scores:
                documents.append({
                    'text': doc.page_content,
                    'source': doc.metadata.get('source', 'Unknown'),
                    'metadata': doc.metadata,
                    'score': float(score)  # Include the actual score
                })
            
            # Deduplicate results
            documents = self._deduplicate_results(documents)
            
            # Trim to requested top_k after deduplication
            documents = documents[:top_k]
            
            # Cache results
            self.cache.set(query, documents, severity)
            
            latency = (time.time() - start_time) * 1000
            logger.info(f"Retrieved {len(documents)} docs (latency: {latency:.1f}ms)")
            
            return documents
            
        except Exception as e:
            logger.error(f"Retrieval failed: {e}")
            return []
    
    def add_documents(self, documents: List[Dict[str, Any]], skip_cache_invalidation: bool = False):
        """
        Add documents to vector store.
        
        Args:
            documents: List of dicts with 'text', 'source', 'metadata'
            skip_cache_invalidation: Skip cache invalidation (useful during initialization)
        """
        # Convert to LangChain Document format
        langchain_docs = []
        for doc in documents:
            langchain_docs.append(Document(
                page_content=doc['text'],
                metadata={
                    'source': doc.get('source', 'unknown'),
                    **doc.get('metadata', {})
                }
            ))
        
        # Add to vector store
        self.langchain_milvus.add_documents(langchain_docs)
        
        # Trigger cache invalidation only if not skipped
        if not skip_cache_invalidation:
            self.cache.on_kb_update()
        
        logger.info(f"Added {len(documents)} documents to vector store")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()
