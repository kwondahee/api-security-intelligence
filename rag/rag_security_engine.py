"""
RAG-Integrated Foundation Model System for API Security Intelligence
"""

import os
import json
import logging
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import pickle

# Core LangChain imports
from langchain.llms import LlamaCpp, Ollama
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import FAISS
from langchain.document_loaders import (
    TextLoader, PDFLoader, JSONLoader, 
    DirectoryLoader, UnstructuredMarkdownLoader,
    CSVLoader, UnstructuredAPIFileLoader
)
from langchain.schema import Document
from langchain.chains import RetrievalQA, ConversationalRetrievalChain
from langchain.memory import ConversationSummaryBufferMemory, VectorStoreRetrieverMemory
from langchain.prompts import PromptTemplate
from langchain.retrievers import (
    BM25Retriever, EnsembleRetriever, 
    ContextualCompressionRetriever, MultiQueryRetriever
)
from langchain.retrievers.document_compressors import LLMChainExtractor, EmbeddingsFilter
from langchain.chains.query_constructor.base import AttributeInfo
from langchain.retrievers.self_query.base import SelfQueryRetriever
from langchain.callbacks import StreamingStdOutCallbackHandler

# For async operations
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class RAGSystemConfig:
    """Complete configuration for the RAG system"""
    
    # Model Configuration
    model_type: str = "ollama"  # ollama, llamacpp
    model_name: str = "codellama:13b-instruct"
    model_path: str = "./models/codellama-13b-instruct.gguf"
    temperature: float = 0.1
    max_tokens: int = 4096
    context_window: int = 8192
    
    # Embedding Configuration
    embedding_model: str = "BAAI/bge-large-en-v1.5"  # Better model
    embedding_device: str = "cuda"  # Use GPU if available
    embedding_batch_size: int = 32
    
    # Vector Store Configuration
    vector_store_path: str = "./security_knowledge_base"
    collection_name: str = "api_security_vectors"
    index_type: str = "IVF"  # IVF, Flat, HNSW
    n_lists: int = 100  # For IVF index
    
    # Retrieval Configuration
    retrieval_k: int = 10  # Number of documents to retrieve
    rerank_k: int = 5  # Number after reranking
    use_mmr: bool = True  # Maximum Marginal Relevance
    mmr_diversity: float = 0.3
    use_compression: bool = True
    compression_threshold: float = 0.5
    
    # Chunking Configuration
    chunk_size: int = 1500
    chunk_overlap: int = 300
    
    # Security Knowledge Categories
    security_categories: List[str] = field(default_factory=lambda: [
        "authentication", "authorization", "injection", "cryptography",
        "session_management", "data_validation", "api_abuse", "configuration",
        "owasp_top10", "cwe", "csrf", "xxe", "ssrf", "idor"
    ])
    
    # System Configuration
    use_gpu: bool = True
    n_gpu_layers: int = 35
    n_threads: int = 8
    batch_processing: bool = True
    cache_responses: bool = True
    
class SecurityKnowledgeBase:
    """Manages the security knowledge base with advanced retrieval"""
    
    def __init__(self, config: RAGSystemConfig):
        self.config = config
        self.embeddings = self._initialize_embeddings()
        self.text_splitter = self._initialize_splitter()
        self.vector_store = self._initialize_vector_store()
        self.metadata_fields = self._define_metadata_fields()
        self.document_cache = {}
        
    def _initialize_embeddings(self):
        """Initialize high-quality embeddings"""
        logger.info(f"Initializing embeddings: {self.config.embedding_model}")
        
        return HuggingFaceEmbeddings(
            model_name=self.config.embedding_model,
            model_kwargs={
                'device': self.config.embedding_device,
                'trust_remote_code': True
            },
            encode_kwargs={
                'normalize_embeddings': True,
                'batch_size': self.config.embedding_batch_size
            }
        )
    
    def _initialize_splitter(self):
        """Initialize intelligent text splitter"""
        return RecursiveCharacterTextSplitter(
            chunk_size=self.config.chunk_size,
            chunk_overlap=self.config.chunk_overlap,
            separators=["\n\n", "\n", ". ", " ", ""],
            keep_separator=True
        )
    
    def _initialize_vector_store(self):
        """Initialize or load FAISS vector store"""
        vector_path = Path(self.config.vector_store_path)
        
        if vector_path.exists():
            logger.info(f"Loading existing vector store from {vector_path}")
            return FAISS.load_local(
                str(vector_path), 
                self.embeddings,
                allow_dangerous_deserialization=True
            )
        else:
            logger.info("Creating new vector store")
            # Create with initial document
            initial_doc = Document(
                page_content="API Security Knowledge Base initialized",
                metadata={"source": "system", "category": "initialization"}
            )
            vector_store = FAISS.from_documents([initial_doc], self.embeddings)
            
            # Configure index for better performance
            if self.config.index_type == "IVF":
                vector_store.index.nprobe = 10  # Number of clusters to search
            
            return vector_store
    
    def _define_metadata_fields(self):
        """Define metadata fields for self-querying retriever"""
        return [
            AttributeInfo(
                name="category",
                description="Security category (authentication, injection, etc.)",
                type="string"
            ),
            AttributeInfo(
                name="severity",
                description="Vulnerability severity (critical, high, medium, low)",
                type="string"
            ),
            AttributeInfo(
                name="framework",
                description="Security framework (OWASP, CWE, NIST)",
                type="string"
            ),
            AttributeInfo(
                name="source",
                description="Document source",
                type="string"
            )
        ]
    
    def process_security_document(self, content: str, metadata: Dict) -> List[Document]:
        """Process document with security-aware chunking"""
        
        # Smart chunking based on content type
        if metadata.get("type") == "api_specification":
            chunks = self._chunk_api_spec(content)
        elif metadata.get("type") == "vulnerability_report":
            chunks = self._chunk_vulnerability_report(content)
        else:
            chunks = self.text_splitter.split_text(content)
        
        documents = []
        for i, chunk in enumerate(chunks):
            # Enrich metadata
            enriched_metadata = {
                **metadata,
                "chunk_id": f"{metadata.get('source', 'unknown')}_{i}",
                "chunk_index": i,
                "total_chunks": len(chunks),
                "category": self._identify_category(chunk),
                "severity": self._assess_severity(chunk),
                "timestamp": datetime.now().isoformat(),
                "embedding_model": self.config.embedding_model
            }
            
            doc = Document(
                page_content=chunk,
                metadata=enriched_metadata
            )
            documents.append(doc)
        
        return documents
    
    def _chunk_api_spec(self, content: str) -> List[str]:
        """Special chunking for API specifications"""
        # Split by endpoints while preserving context
        chunks = []
        lines = content.split('\n')
        current_chunk = []
        current_size = 0
        
        for line in lines:
            # Check if this is an endpoint definition
            if any(method in line for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']):
                if current_chunk and current_size > 500:
                    chunks.append('\n'.join(current_chunk))
                    current_chunk = [line]
                    current_size = len(line)
                else:
                    current_chunk.append(line)
                    current_size += len(line)
            else:
                current_chunk.append(line)
                current_size += len(line)
                
                if current_size > self.config.chunk_size:
                    chunks.append('\n'.join(current_chunk))
                    current_chunk = []
                    current_size = 0
        
        if current_chunk:
            chunks.append('\n'.join(current_chunk))
        
        return chunks
    
    def _chunk_vulnerability_report(self, content: str) -> List[str]:
        """Special chunking for vulnerability reports"""
        # Keep vulnerability descriptions together
        chunks = []
        sections = content.split('\n\n')
        current_chunk = []
        current_size = 0
        
        for section in sections:
            if 'CVE-' in section or 'CWE-' in section:
                # Keep CVE/CWE sections intact
                if current_chunk:
                    chunks.append('\n\n'.join(current_chunk))
                chunks.append(section)
                current_chunk = []
                current_size = 0
            else:
                current_chunk.append(section)
                current_size += len(section)
                
                if current_size > self.config.chunk_size:
                    chunks.append('\n\n'.join(current_chunk))
                    current_chunk = []
                    current_size = 0
        
        if current_chunk:
            chunks.append('\n\n'.join(current_chunk))
        
        return chunks
    
    def _identify_category(self, text: str) -> str:
        """Identify security category using keyword matching"""
        text_lower = text.lower()
        
        category_patterns = {
            "authentication": ["auth", "login", "credential", "password", "jwt", "oauth", "saml"],
            "injection": ["injection", "sql", "xss", "xxe", "ldap", "nosql", "command"],
            "authorization": ["authz", "permission", "rbac", "acl", "privilege", "access control"],
            "cryptography": ["encrypt", "decrypt", "hash", "crypto", "tls", "ssl", "certificate"],
            "session_management": ["session", "cookie", "csrf", "fixation", "timeout"],
            "api_abuse": ["rate limit", "throttl", "dos", "ddos", "brute force", "enumeration"],
            "data_validation": ["validat", "sanitiz", "input", "output encoding", "whitelist"],
            "configuration": ["config", "misconfig", "header", "cors", "security header"]
        }
        
        scores = {}
        for category, keywords in category_patterns.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            if score > 0:
                scores[category] = score
        
        if scores:
            return max(scores, key=scores.get)
        return "general"
    
    def _assess_severity(self, text: str) -> str:
        """Assess vulnerability severity from text"""
        text_lower = text.lower()
        
        if any(word in text_lower for word in ["critical", "rce", "remote code execution", "authentication bypass"]):
            return "critical"
        elif any(word in text_lower for word in ["high", "sql injection", "xss", "privilege escalation"]):
            return "high"
        elif any(word in text_lower for word in ["medium", "csrf", "session", "information disclosure"]):
            return "medium"
        else:
            return "low"
    
    def add_documents(self, documents: List[Document], batch_size: int = 100):
        """Add documents to vector store in batches"""
        logger.info(f"Adding {len(documents)} documents to knowledge base")
        
        # Process in batches for better performance
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            
            # Generate embeddings and add to store
            texts = [doc.page_content for doc in batch]
            metadatas = [doc.metadata for doc in batch]
            
            self.vector_store.add_texts(texts, metadatas)
            logger.info(f"Added batch {i//batch_size + 1}/{(len(documents) + batch_size - 1)//batch_size}")
        
        # Save vector store
        self.save()
        logger.info("Documents successfully added and saved")
    
    def save(self):
        """Save vector store to disk"""
        self.vector_store.save_local(self.config.vector_store_path)
        logger.info(f"Vector store saved to {self.config.vector_store_path}")
    
    def load_security_corpus(self, corpus_path: str):
        """Load complete security corpus from directory"""
        all_documents = []
        
        # Load different file types with appropriate loaders
        loaders = {
            "*.txt": TextLoader,
            "*.md": UnstructuredMarkdownLoader,
            "*.pdf": PDFLoader,
            "*.json": JSONLoader,
            "*.csv": CSVLoader
        }
        
        for pattern, loader_class in loaders.items():
            loader = DirectoryLoader(
                corpus_path,
                glob=pattern,
                loader_cls=loader_class,
                show_progress=True
            )
            
            try:
                raw_docs = loader.load()
                
                # Process each document
                for doc in raw_docs:
                    processed = self.process_security_document(
                        doc.page_content,
                        {
                            **doc.metadata,
                            "type": pattern.replace("*.", ""),
                            "source": doc.metadata.get("source", corpus_path)
                        }
                    )
                    all_documents.extend(processed)
                    
            except Exception as e:
                logger.warning(f"Failed to load {pattern}: {e}")
        
        # Add all documents
        if all_documents:
            self.add_documents(all_documents)
            logger.info(f"Loaded {len(all_documents)} document chunks from corpus")
        
        return len(all_documents)

class AdvancedRetriever:
    """Advanced retrieval system with multiple strategies"""
    
    def __init__(self, knowledge_base: SecurityKnowledgeBase, llm):
        self.kb = knowledge_base
        self.llm = llm
        self.retrievers = self._initialize_retrievers()
        
    def _initialize_retrievers(self):
        """Initialize multiple retrieval strategies"""
        retrievers = {}
        
        # 1. Standard similarity retriever
        retrievers["similarity"] = self.kb.vector_store.as_retriever(
            search_kwargs={
                "k": self.kb.config.retrieval_k
            }
        )
        
        # 2. MMR retriever for diversity
        retrievers["mmr"] = self.kb.vector_store.as_retriever(
            search_type="mmr",
            search_kwargs={
                "k": self.kb.config.retrieval_k,
                "fetch_k": self.kb.config.retrieval_k * 2,
                "lambda_mult": self.kb.config.mmr_diversity
            }
        )
        
        # 3. Self-querying retriever with metadata filtering
        retrievers["self_query"] = SelfQueryRetriever.from_llm(
            llm=self.llm,
            vectorstore=self.kb.vector_store,
            document_contents="API security knowledge",
            metadata_field_info=self.kb.metadata_fields,
            verbose=True
        )
        
        # 4. Multi-query retriever for query expansion
        retrievers["multi_query"] = MultiQueryRetriever.from_llm(
            retriever=retrievers["similarity"],
            llm=self.llm
        )
        
        # 5. Contextual compression retriever
        compressor = LLMChainExtractor.from_llm(self.llm)
        retrievers["compressed"] = ContextualCompressionRetriever(
            base_compressor=compressor,
            base_retriever=retrievers["mmr"]
        )
        
        # 6. Ensemble retriever combining multiple strategies
        retrievers["ensemble"] = EnsembleRetriever(
            retrievers=[
                retrievers["similarity"],
                retrievers["mmr"]
            ],
            weights=[0.5, 0.5]
        )
        
        return retrievers
    
    def retrieve(self, query: str, strategy: str = "ensemble", filters: Dict = None) -> List[Document]:
        """Retrieve documents using specified strategy"""
        
        # Apply filters if provided
        if filters and strategy == "self_query":
            filter_str = " AND ".join([f"{k}='{v}'" for k, v in filters.items()])
            enhanced_query = f"{query} WHERE {filter_str}"
        else:
            enhanced_query = query
        
        # Get retriever
        retriever = self.retrievers.get(strategy, self.retrievers["ensemble"])
        
        # Retrieve documents
        docs = retriever.get_relevant_documents(enhanced_query)
        
        # Post-process if needed
        if self.kb.config.use_compression and strategy != "compressed":
            docs = self._compress_results(docs, query)
        
        return docs[:self.kb.config.rerank_k]
    
    def _compress_results(self, docs: List[Document], query: str) -> List[Document]:
        """Compress/filter results based on relevance"""
        # Calculate relevance scores
        embeddings_filter = EmbeddingsFilter(
            embeddings=self.kb.embeddings,
            similarity_threshold=self.kb.config.compression_threshold
        )
        
        return embeddings_filter.compress_documents(docs, query)
    
    def adaptive_retrieve(self, query: str, context: Dict = None) -> List[Document]:
        """Adaptively choose retrieval strategy based on query type"""
        query_lower = query.lower()
        
        # Determine best strategy
        if "specific" in query_lower or "exact" in query_lower:
            strategy = "similarity"
        elif "diverse" in query_lower or "various" in query_lower:
            strategy = "mmr"
        elif any(cat in query_lower for cat in self.kb.config.security_categories):
            strategy = "self_query"
        elif "?" in query and len(query.split()) > 10:
            strategy = "multi_query"
        else:
            strategy = "ensemble"
        
        logger.info(f"Using {strategy} retrieval strategy for query")
        
        return self.retrieve(query, strategy)

class RAGSecurityExpert:
    """Main RAG-powered security expert system"""
    
    def __init__(self, config: RAGSystemConfig):
        self.config = config
        
        # Initialize components
        logger.info("Initializing RAG Security Expert System")
        self.llm = self._initialize_llm()
        self.knowledge_base = SecurityKnowledgeBase(config)
        self.retriever = AdvancedRetriever(self.knowledge_base, self.llm)
        self.memory = self._initialize_memory()
        self.chains = self._initialize_chains()
        
        # Performance tracking
        self.metrics = {
            "queries_processed": 0,
            "avg_response_time": 0,
            "cache_hits": 0,
            "vulnerabilities_found": 0
        }
        
        logger.info("RAG Security Expert System initialized successfully")
    
    def _initialize_llm(self):
        """Initialize foundation model"""
        logger.info(f"Initializing {self.config.model_type} model")
        
        if self.config.model_type == "ollama":
            return Ollama(
                model=self.config.model_name,
                temperature=self.config.temperature,
                num_predict=self.config.max_tokens,
                num_ctx=self.config.context_window,
                num_gpu=self.config.n_gpu_layers if self.config.use_gpu else 0,
                num_thread=self.config.n_threads,
                callback_manager=[StreamingStdOutCallbackHandler()]
            )
        elif self.config.model_type == "llamacpp":
            return LlamaCpp(
                model_path=self.config.model_path,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                n_ctx=self.config.context_window,
                n_gpu_layers=self.config.n_gpu_layers if self.config.use_gpu else 0,
                n_threads=self.config.n_threads,
                callback_manager=[StreamingStdOutCallbackHandler()],
                verbose=True
            )
    
    def _initialize_memory(self):
        """Initialize conversation memory with RAG"""
        # Vector memory for long-term recall
        vector_memory = VectorStoreRetrieverMemory(
            retriever=self.knowledge_base.vector_store.as_retriever(
                search_kwargs={"k": 3}
            ),
            memory_key="relevant_history",
            return_docs=True
        )
        
        # Summary memory for conversation
        summary_memory = ConversationSummaryBufferMemory(
            llm=self.llm,
            max_token_limit=2000,
            memory_key="chat_history",
            return_messages=True
        )
        
        return {
            "vector": vector_memory,
            "summary": summary_memory
        }
    
    def _initialize_chains(self):
        """Initialize various RAG chains"""
        chains = {}
        
        # Security Analysis Chain
        security_prompt = PromptTemplate(
            template="""You are an elite API security expert with comprehensive knowledge of OWASP, CWE, and modern attack vectors.

Context from security knowledge base:
{context}

Relevant conversation history:
{
