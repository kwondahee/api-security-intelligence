# rag/rag.py
"""
LangChain RAG System
Implements RAG with LangChain, Milvus, and Foundation-Sec-8B
From midterm report Section 2.2-2.6
"""

import logging
import time
from typing import List, Dict, Any, Optional

# Updated imports - use langchain_community instead of langchain
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_milvus import Milvus
from langchain.schema import Document

from rag.cache import RAGCache
from rag.queries import QueryGenerator
from rag.vectorstore import MilvusVectorStore

logger = logging.getLogger(__name__)

class RAGSystem:
    """
    LangChain-based RAG system with Milvus vector store.
    
    Features:
    - Milvus vector database (IVF_FLAT index)
    - BGE-Large-en-v1.5 embeddings
    - Severity-based caching
    - Query optimization
    """
    
    def __init__(
        self,
        milvus_host: str = "localhost",
        milvus_port: int = 19530,
        collection_name: str = "security_knowledge_base"
    ):
        self.collection_name = collection_name
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
        self.vectorstore = MilvusVectorStore(
            collection_name=collection_name,
            host=milvus_host,
            port=milvus_port
        )
        
        # Initialize LangChain Milvus wrapper
        self.langchain_milvus = Milvus(
            embedding_function=self.embeddings,
            collection_name=collection_name,
            connection_args={"host": milvus_host, "port": milvus_port}
        )
        
        logger.info("RAG System initialized successfully")
    
    def _has_cuda(self) -> bool:
        """Check if CUDA is available."""
        try:
            import torch
            return torch.cuda.is_available()
        except:
            return False
    
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
            List of relevant documents
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
        
        # Perform retrieval using LangChain
        try:
            results = self.langchain_milvus.similarity_search(
                query=query,
                k=top_k
            )
            
            # Convert LangChain Documents to dict format
            documents = []
            for doc in results:
                documents.append({
                    'text': doc.page_content,
                    'source': doc.metadata.get('source', 'Unknown'),
                    'metadata': doc.metadata,
                    'score': doc.metadata.get('score', 0.0)
                })
            
            # Cache results
            self.cache.set(query, documents, severity)
            
            latency = (time.time() - start_time) * 1000
            logger.info(f"Retrieved {len(documents)} docs (latency: {latency:.1f}ms)")
            
            return documents
            
        except Exception as e:
            logger.error(f"Retrieval failed: {e}")
            return []
    
    def add_documents(self, documents: List[Dict[str, Any]]):
        """
        Add documents to vector store.
        
        Args:
            documents: List of dicts with 'text', 'source', 'metadata'
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
        
        # Trigger cache invalidation
        self.cache.on_kb_update()
        
        logger.info(f"Added {len(documents)} documents to vector store")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()
