# rag/vectorstore.py
"""
Milvus Vector Store Integration
Implements vector database from midterm report Section 2.3
"""

import logging
from typing import List, Dict, Any, Optional
from pymilvus import (
    connections, Collection, CollectionSchema, 
    FieldSchema, DataType, utility
)
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

class MilvusVectorStore:
    """
    Milvus vector database for security knowledge base.
    Uses IVF_FLAT index with nlist=2048, nprobe=16 (from midterm report).
    """
    
    def __init__(
        self,
        collection_name: str = "security_knowledge_base",
        host: str = "localhost",
        port: int = 19530,
        embedding_model: str = "BAAI/bge-large-en-v1.5"
    ):
        self.collection_name = collection_name
        self.host = host
        self.port = port
        self.collection = None
        
        # Load embedding model (BGE-Large-en-v1.5 from midterm report)
        logger.info(f"Loading embedding model: {embedding_model}")
        self.embedding_model = SentenceTransformer(embedding_model)
        self.dimension = 768  # BGE-Large dimension
        
        self._connect()
        self._setup_collection()
    
    def _connect(self):
        """Connect to Milvus."""
        try:
            connections.connect(
                alias="default",
                host=self.host,
                port=self.port
            )
            logger.info(f"Connected to Milvus at {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to connect to Milvus: {e}")
            raise
    
    def _setup_collection(self):
        """Create or load Milvus collection with optimized schema."""
        if utility.has_collection(self.collection_name):
            self.collection = Collection(self.collection_name)
            logger.info(f"Loaded existing collection: {self.collection_name}")
            return
        
        # Define schema
        fields = [
            FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
            FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=65535),
            FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=self.dimension),
            FieldSchema(name="source", dtype=DataType.VARCHAR, max_length=512),
            FieldSchema(name="metadata", dtype=DataType.JSON),
        ]
        
        schema = CollectionSchema(
            fields=fields,
            description="Security knowledge base for RAG"
        )
        
        # Create collection
        self.collection = Collection(
            name=self.collection_name,
            schema=schema
        )
        
        # Create IVF_FLAT index (from midterm report: nlist=2048)
        index_params = {
            "metric_type": "IP",  # Inner Product (cosine similarity)
            "index_type": "IVF_FLAT",
            "params": {"nlist": 2048}
        }
        
        self.collection.create_index(
            field_name="embedding",
            index_params=index_params
        )
        
        logger.info(f"Created collection: {self.collection_name} with IVF_FLAT index")
    
    def add_documents(self, documents: List[Dict[str, Any]]):
        """
        Add documents to vector store.
        
        Args:
            documents: List of dicts with 'text', 'source', 'metadata'
        """
        if not documents:
            return
        
        logger.info(f"Adding {len(documents)} documents to Milvus...")
        
        # Extract texts
        texts = [doc['text'] for doc in documents]
        
        # Generate embeddings in batches
        embeddings = self.embedding_model.encode(
            texts,
            batch_size=32,
            show_progress_bar=True,
            normalize_embeddings=True
        )
        
        # Prepare data for insertion
        data = {
            'text': [doc['text'] for doc in documents],
            'embedding': embeddings.tolist(),
            'source': [doc.get('source', 'unknown') for doc in documents],
            'metadata': [doc.get('metadata', {}) for doc in documents],
        }
        
        # Insert into Milvus
        self.collection.insert(data)
        self.collection.flush()
        
        logger.info(f"Successfully added {len(documents)} documents")
    
    def similarity_search(
        self, 
        query: str, 
        top_k: int = 5,
        nprobe: int = 16
    ) -> List[Dict[str, Any]]:
        """
        Perform similarity search.
        
        Args:
            query: Search query
            top_k: Number of results to return
            nprobe: Search parameter (from midterm report: 16)
            
        Returns:
            List of documents with scores
        """
        # Generate query embedding
        query_embedding = self.embedding_model.encode(
            query,
            normalize_embeddings=True
        ).tolist()
        
        # Load collection
        self.collection.load()
        
        # Search parameters
        search_params = {
            "metric_type": "IP",
            "params": {"nprobe": nprobe}
        }
        
        # Perform search
        results = self.collection.search(
            data=[query_embedding],
            anns_field="embedding",
            param=search_params,
            limit=top_k,
            output_fields=["text", "source", "metadata"]
        )
        
        # Format results
        documents = []
        for hit in results[0]:
            documents.append({
                'text': hit.entity.get('text', ''),
                'source': hit.entity.get('source', ''),
                'metadata': hit.entity.get('metadata', {}),
                'score': float(hit.score)
            })
        
        return documents
    
    def delete_collection(self):
        """Delete the collection (use with caution)."""
        if utility.has_collection(self.collection_name):
            utility.drop_collection(self.collection_name)
            logger.warning(f"Deleted collection: {self.collection_name}")
