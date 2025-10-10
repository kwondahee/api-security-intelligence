"""
Complete RAG Implementation with Foundation-Sec-8B-Instruct
CS480 - API Security Intelligence Framework
Mandatory RAG with fdtn-ai/Foundation-Sec-8B-Instruct Model
"""

import os
import json
import torch
import logging
import asyncio
import warnings
from typing import List, Dict, Any, Optional, Tuple, Union
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from collections import defaultdict

# Core imports
import transformers
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    pipeline,
    TextStreamer
)

# LangChain imports
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Milvus
from langchain.text_splitter import RecursiveCharacterTextSplitter, Language
from langchain.document_loaders import (
    TextLoader,
    PDFLoader,
    JSONLoader,
    DirectoryLoader,
    UnstructuredMarkdownLoader,
    GitLoader,
    PythonLoader,
    CSVLoader
)
from langchain.schema import Document, BaseRetriever
from langchain.callbacks.manager import CallbackManager
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler
from langchain.chains import RetrievalQA, ConversationalRetrievalChain
from langchain.memory import ConversationBufferWindowMemory, VectorStoreRetrieverMemory
from langchain.prompts import PromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate
from langchain.retrievers import (
    ContextualCompressionRetriever,
    EnsembleRetriever,
    MultiQueryRetriever,
    BM25Retriever
)
from langchain.retrievers.document_compressors import (
    EmbeddingsFilter,
    DocumentCompressorPipeline,
    LLMChainFilter
)
from langchain.llms.base import LLM
from langchain.chains.summarize import load_summarize_chain

# Milvus imports
from pymilvus import (
    connections,
    Collection,
    FieldSchema,
    CollectionSchema,
    DataType,
    utility,
    MilvusException
)

# Additional imports
import faiss
import pickle
from sentence_transformers import CrossEncoder

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)

@dataclass
class FoundationSecConfig:
    """Configuration for Foundation-Sec-8B-Instruct RAG System"""
    
    # Model Configuration
    model_name: str = "fdtn-ai/Foundation-Sec-8B-Instruct"
    model_cache_dir: str = "./models"
    use_4bit: bool = True  # 4-bit quantization for efficiency
    use_flash_attention: bool = True
    max_new_tokens: int = 2048
    temperature: float = 0.1
    top_p: float = 0.95
    repetition_penalty: float = 1.15
    
    # Milvus Configuration
    milvus_host: str = os.getenv("MILVUS_HOST", "localhost")
    milvus_port: str = os.getenv("MILVUS_PORT", "19530")
    collection_name: str = "api_security_intel_v2"
    vector_dim: int = 768
    index_type: str = "IVF_FLAT"
    metric_type: str = "IP"
    nlist: int = 2048
    nprobe: int = 16
    
    # Embedding Configuration
    embedding_model: str = "BAAI/bge-large-en-v1.5"  # Better than all-mpnet
    embedding_device: str = "cuda" if torch.cuda.is_available() else "cpu"
    embedding_batch_size: int = 32
    normalize_embeddings: bool = True
    
    # Cross-Encoder for Reranking
    cross_encoder_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"
    use_cross_encoder: bool = True
    
    # Chunking Configuration
    chunk_size: int = 1500
    chunk_overlap: int = 300
    
    # RAG Configuration
    k_retrieval: int = 15  # Retrieve more for reranking
    k_final: int = 5  # Final top-k after reranking
    use_mmr: bool = True
    mmr_lambda: float = 0.7
    use_bm25: bool = True  # Hybrid retrieval
    bm25_weight: float = 0.3
    
    # Security Categories
    security_frameworks: List[str] = field(default_factory=lambda: [
        "OWASP", "CWE", "MITRE_ATT&CK", "NIST", "ISO27001", "PCI_DSS"
    ])
    
    vulnerability_categories: List[str] = field(default_factory=lambda: [
        "injection", "authentication", "authorization", "cryptography",
        "session_management", "validation", "configuration", "api_abuse",
        "supply_chain", "zero_day", "container", "cloud", "iam"
    ])
    
    severity_levels: List[str] = field(default_factory=lambda: [
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    ])
    
    # Performance Settings
    enable_caching: bool = True
    cache_ttl: int = 3600  # 1 hour
    max_workers: int = 4
    batch_processing: bool = True

class FoundationSecLLM(LLM):
    """Custom LangChain wrapper for Foundation-Sec-8B-Instruct"""
    
    model: Any = None
    tokenizer: Any = None
    config: FoundationSecConfig = None
    device: str = None
    
    def __init__(self, config: FoundationSecConfig):
        super().__init__()
        self.config = config
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize Foundation-Sec-8B-Instruct with optimal settings"""
        logger.info(f"Loading Foundation-Sec-8B-Instruct from {self.config.model_name}")
        
        # Quantization config for memory efficiency
        bnb_config = None
        if self.config.use_4bit:
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True
            )
        
        # Load tokenizer with special tokens
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.config.model_name,
            cache_dir=self.config.model_cache_dir,
            trust_remote_code=True,
            padding_side="left",
            use_fast=True
        )
        
        # Set special tokens if not already set
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # Model loading arguments
        model_kwargs = {
            "cache_dir": self.config.model_cache_dir,
            "trust_remote_code": True,
            "device_map": "auto",
            "torch_dtype": torch.float16,
            "low_cpu_mem_usage": True
        }
        
        # Add quantization config if enabled
        if bnb_config:
            model_kwargs["quantization_config"] = bnb_config
        
        # Add flash attention if available
        if self.config.use_flash_attention and torch.cuda.is_available():
            model_kwargs["use_flash_attention_2"] = True
        
        # Load model
        self.model = AutoModelForCausalLM.from_pretrained(
            self.config.model_name,
            **model_kwargs
        )
        
        # Enable gradient checkpointing for memory efficiency
        if hasattr(self.model, "gradient_checkpointing_enable"):
            self.model.gradient_checkpointing_enable()
        
        logger.info("Foundation-Sec-8B-Instruct loaded successfully")
    
    @property
    def _llm_type(self) -> str:
        return "foundation-sec-8b-instruct"
    
    def _call(self, prompt: str, stop: Optional[List[str]] = None) -> str:
        """Generate security-focused response"""
        
        # Format prompt for Foundation-Sec-8B-Instruct
        formatted_prompt = self._format_security_prompt(prompt)
        
        # Tokenize
        inputs = self.tokenizer(
            formatted_prompt,
            return_tensors="pt",
            max_length=2048,
            truncation=True,
            padding=True
        ).to(self.device)
        
        # Generate with security-optimized parameters
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=self.config.max_new_tokens,
                temperature=self.config.temperature,
                top_p=self.config.top_p,
                repetition_penalty=self.config.repetition_penalty,
                do_sample=True,
                num_beams=1,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id
            )
        
        # Decode response
        response = self.tokenizer.decode(
            outputs[0][inputs['input_ids'].shape[1]:],
            skip_special_tokens=True,
            clean_up_tokenization_spaces=True
        )
        
        # Apply stop sequences
        if stop:
            for stop_seq in stop:
                if stop_seq in response:
                    response = response.split(stop_seq)[0]
        
        return response.strip()
    
    def _format_security_prompt(self, prompt: str) -> str:
        """Format prompt with security-specific instructions"""
        return f"""<s>[INST] <<SYS>>
You are Foundation-Sec-8B-Instruct, a specialized AI security analyst trained on cybersecurity best practices.
Provide accurate, detailed security analysis based on OWASP, CWE, MITRE ATT&CK, and industry standards.
Focus on practical, actionable security recommendations.
<</SYS>>

{prompt} [/INST]"""

class SecurityKnowledgeProcessor:
    """Process and enrich security documents with metadata"""
    
    def __init__(self, config: FoundationSecConfig):
        self.config = config
        self.cwe_patterns = self._compile_cwe_patterns()
        self.owasp_patterns = self._compile_owasp_patterns()
        self.severity_patterns = self._compile_severity_patterns()
        
    def _compile_cwe_patterns(self) -> Dict[str, re.Pattern]:
        """Compile CWE detection patterns"""
        patterns = {
            "CWE-20": re.compile(r"(input validation|improper input|untrusted data)", re.I),
            "CWE-79": re.compile(r"(cross[- ]?site scripting|xss|script injection)", re.I),
            "CWE-89": re.compile(r"(sql injection|sqli|database query)", re.I),
            "CWE-200": re.compile(r"(information (exposure|disclosure)|data leak)", re.I),
            "CWE-287": re.compile(r"(authentication|improper auth|auth bypass)", re.I),
            "CWE-352": re.compile(r"(csrf|cross[- ]?site request forgery)", re.I),
            "CWE-611": re.compile(r"(xxe|xml external entity)", re.I),
            "CWE-918": re.compile(r"(ssrf|server[- ]?side request forgery)", re.I),
            "CWE-94": re.compile(r"(code injection|eval|dynamic execution)", re.I),
            "CWE-798": re.compile(r"(hardcoded|hard[- ]?coded|embedded (credential|password))", re.I)
        }
        return patterns
    
    def _compile_owasp_patterns(self) -> Dict[str, re.Pattern]:
        """Compile OWASP Top 10 patterns"""
        patterns = {
            "A01:2021": re.compile(r"(broken access control|authorization flaw)", re.I),
            "A02:2021": re.compile(r"(cryptographic failure|weak crypto|encryption)", re.I),
            "A03:2021": re.compile(r"(injection|command injection|ldap injection)", re.I),
            "A04:2021": re.compile(r"(insecure design|design flaw|threat modeling)", re.I),
            "A05:2021": re.compile(r"(security misconfiguration|misconfig|default setting)", re.I),
            "A06:2021": re.compile(r"(vulnerable (component|dependency)|outdated library)", re.I),
            "A07:2021": re.compile(r"(authentication failure|identity|credential)", re.I),
            "A08:2021": re.compile(r"(software.*integrity|data integrity|ci/cd)", re.I),
            "A09:2021": re.compile(r"(security logging|monitoring failure|audit)", re.I),
            "A10:2021": re.compile(r"(ssrf|server[- ]?side request)", re.I)
        }
        return patterns
    
    def _compile_severity_patterns(self) -> Dict[str, List[str]]:
        """Compile severity detection keywords"""
        return {
            "CRITICAL": ["critical", "emergency", "severe", "zero-day", "actively exploited"],
            "HIGH": ["high", "important", "significant", "major"],
            "MEDIUM": ["medium", "moderate", "intermediate"],
            "LOW": ["low", "minor", "informational"],
            "INFO": ["info", "note", "tip", "best practice"]
        }
    
    def process_document(self, doc: Document) -> Document:
        """Enrich document with security metadata"""
        content = doc.page_content.lower()
        
        # Detect CWE IDs
        cwe_ids = []
        for cwe_id, pattern in self.cwe_patterns.items():
            if pattern.search(content):
                cwe_ids.append(cwe_id)
        
        # Detect OWASP categories
        owasp_categories = []
        for owasp_id, pattern in self.owasp_patterns.items():
            if pattern.search(content):
                owasp_categories.append(owasp_id)
        
        # Detect severity
        severity = self._detect_severity(content)
        
        # Detect vulnerability category
        category = self._detect_category(content)
        
        # Detect MITRE ATT&CK techniques
        mitre_techniques = self._detect_mitre_techniques(content)
        
        # Update metadata
        doc.metadata.update({
            "cwe_ids": cwe_ids,
            "owasp_categories": owasp_categories,
            "severity": severity,
            "security_category": category,
            "mitre_techniques": mitre_techniques,
            "processing_timestamp": datetime.now().isoformat(),
            "model_compatible": "foundation-sec-8b"
        })
        
        return doc
    
    def _detect_severity(self, text: str) -> str:
        """Detect severity level from text"""
        for level, keywords in self.severity_patterns.items():
            if any(keyword in text for keyword in keywords):
                return level
        return "INFO"
    
    def _detect_category(self, text: str) -> str:
        """Detect primary security category"""
        category_keywords = {
            "injection": ["injection", "sqli", "xss", "xxe", "ldapi", "command injection"],
            "authentication": ["auth", "login", "password", "credential", "identity", "sso"],
            "authorization": ["authz", "permission", "rbac", "acl", "privilege"],
            "cryptography": ["crypto", "encryption", "hash", "tls", "ssl", "certificate"],
            "session_management": ["session", "cookie", "token", "jwt", "state"],
            "validation": ["validation", "sanitization", "input", "filtering"],
            "configuration": ["config", "misconfiguration", "default", "hardening"],
            "api_abuse": ["rate limit", "throttle", "dos", "brute force"],
            "supply_chain": ["dependency", "third-party", "library", "package"],
            "container": ["docker", "kubernetes", "container", "k8s", "pod"],
            "cloud": ["aws", "azure", "gcp", "cloud", "s3", "lambda"],
            "iam": ["iam", "identity", "access management", "role", "policy"]
        }
        
        scores = defaultdict(int)
        for category, keywords in category_keywords.items():
            for keyword in keywords:
                if keyword in text:
                    scores[category] += 1
        
        if scores:
            return max(scores, key=scores.get)
        return "general"
    
    def _detect_mitre_techniques(self, text: str) -> List[str]:
        """Detect MITRE ATT&CK techniques"""
        techniques = []
        mitre_patterns = {
            "T1190": "exploit public facing",
            "T1055": "process injection",
            "T1059": "command.*script",
            "T1078": "valid accounts",
            "T1110": "brute force"
        }
        
        for technique, pattern in mitre_patterns.items():
            if re.search(pattern, text, re.I):
                techniques.append(technique)
        
        return techniques

class HybridRetriever(BaseRetriever):
    """Advanced hybrid retriever combining dense and sparse retrieval"""
    
    def __init__(self, 
                 vectorstore: Milvus,
                 documents: List[Document],
                 config: FoundationSecConfig):
        self.vectorstore = vectorstore
        self.config = config
        self.documents = documents
        
        # Initialize BM25 for sparse retrieval
        if config.use_bm25:
            self.bm25_retriever = BM25Retriever.from_documents(
                documents,
                k=config.k_retrieval
            )
        
        # Initialize cross-encoder for reranking
        if config.use_cross_encoder:
            self.cross_encoder = CrossEncoder(config.cross_encoder_model)
        
        # Cache for performance
        self.cache = {} if config.enable_caching else None
    
    def get_relevant_documents(self, query: str) -> List[Document]:
        """Retrieve documents using hybrid approach"""
        
        # Check cache
        if self.cache is not None and query in self.cache:
            logger.info("Cache hit for query")
            return self.cache[query]
        
        # Dense retrieval with MMR
        if self.config.use_mmr:
            dense_docs = self.vectorstore.max_marginal_relevance_search(
                query,
                k=self.config.k_retrieval,
                lambda_mult=self.config.mmr_lambda
            )
        else:
            dense_docs = self.vectorstore.similarity_search(
                query,
                k=self.config.k_retrieval
            )
        
        # Sparse retrieval with BM25
        sparse_docs = []
        if self.config.use_bm25:
            sparse_docs = self.bm25_retriever.get_relevant_documents(query)
        
        # Combine results
        all_docs = self._combine_results(dense_docs, sparse_docs)
        
        # Rerank with cross-encoder
        if self.config.use_cross_encoder and all_docs:
            reranked_docs = self._rerank_documents(query, all_docs)
        else:
            reranked_docs = all_docs[:self.config.k_final]
        
        # Cache results
        if self.cache is not None:
            self.cache[query] = reranked_docs
        
        return reranked_docs
    
    def _combine_results(self, 
                        dense_docs: List[Document], 
                        sparse_docs: List[Document]) -> List[Document]:
        """Combine dense and sparse retrieval results"""
        
        # Create document scores
        doc_scores = {}
        
        # Score dense results
        for i, doc in enumerate(dense_docs):
            doc_id = doc.page_content[:100]  # Use first 100 chars as ID
            doc_scores[doc_id] = {
                'doc': doc,
                'dense_score': 1.0 - (i / len(dense_docs)),
                'sparse_score': 0.0
            }
        
        # Score sparse results
        for i, doc in enumerate(sparse_docs):
            doc_id = doc.page_content[:100]
            if doc_id in doc_scores:
                doc_scores[doc_id]['sparse_score'] = 1.0 - (i / len(sparse_docs))
            else:
                doc_scores[doc_id] = {
                    'doc': doc,
                    'dense_score': 0.0,
                    'sparse_score': 1.0 - (i / len(sparse_docs))
                }
        
        # Combine scores with weights
        for doc_id in doc_scores:
            dense_weight = 1.0 - self.config.bm25_weight
            sparse_weight = self.config.bm25_weight
            
            doc_scores[doc_id]['final_score'] = (
                dense_weight * doc_scores[doc_id]['dense_score'] +
                sparse_weight * doc_scores[doc_id]['sparse_score']
            )
        
        # Sort by final score
        sorted_docs = sorted(
            doc_scores.values(),
            key=lambda x: x['final_score'],
            reverse=True
        )
        
        return [item['doc'] for item in sorted_docs]
    
    def _rerank_documents(self, query: str, documents: List[Document]) -> List[Document]:
        """Rerank documents using cross-encoder"""
        
        # Prepare pairs for cross-encoder
        pairs = [[query, doc.page_content] for doc in documents]
        
        # Get scores from cross-encoder
        scores = self.cross_encoder.predict(pairs)
        
        # Sort documents by score
        doc_scores = list(zip(documents, scores))
        doc_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Return top-k documents
        return [doc for doc, _ in doc_scores[:self.config.k_final]]
    
    async def aget_relevant_documents(self, query: str) -> List[Document]:
        """Async version for better performance"""
        return self.get_relevant_documents(query)

class FoundationSecRAGSystem:
    """Main RAG system with Foundation-Sec-8B-Instruct"""
    
    def __init__(self, config: FoundationSecConfig = None):
        self.config = config or FoundationSecConfig()
        self.llm = None
        self.embeddings = None
        self.vectorstore = None
        self.retriever = None
        self.qa_chain = None
        self.conversation_chain = None
        self.processor = SecurityKnowledgeProcessor(self.config)
        self.documents = []
        
        # Performance monitoring
        self.metrics = {
            "queries_processed": 0,
            "avg_response_time": 0.0,
            "cache_hits": 0,
            "documents_processed": 0
        }
        
        # Initialize system
        self._initialize_system()
    
    def _initialize_system(self):
        """Initialize all components"""
        logger.info("Initializing Foundation-Sec-8B-Instruct RAG System")
        
        try:
            # Initialize in order
            self._initialize_embeddings()
            self._initialize_milvus()
            self._initialize_llm()
            self._initialize_retrieval_chains()
            
            logger.info("System initialization complete")
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            raise
    
    def _initialize_embeddings(self):
        """Initialize BGE embeddings"""
        logger.info(f"Loading embeddings: {self.config.embedding_model}")
        
        self.embeddings = HuggingFaceEmbeddings(
            model_name=self.config.embedding_model,
            model_kwargs={'device': self.config.embedding_device},
            encode_kwargs={
                'normalize_embeddings': self.config.normalize_embeddings,
                'batch_size': self.config.embedding_batch_size,
                'show_progress_bar': True
            }
        )
        
        logger.info("Embeddings loaded successfully")
    
    def _initialize_milvus(self):
        """Initialize Milvus vector database"""
        logger.info(f"Connecting to Milvus at {self.config.milvus_host}:{self.config.milvus_port}")
        
        # Connect to Milvus
        connections.connect(
            alias="default",
            host=self.config.milvus_host,
            port=self.config.milvus_port,
            timeout=30
        )
        
        # Create collection if needed
        if not utility.has_collection(self.config.collection_name):
            self._create_milvus_collection()
        
        # Initialize vectorstore
        self.vectorstore = Milvus(
            embedding_function=self.embeddings,
            collection_name=self.config.collection_name,
            connection_args={
                "host": self.config.milvus_host,
                "port": self.config.milvus_port
            },
            index_params={
                "metric_type": self.config.metric_type,
                "index_type": self.config.index_type,
                "params": {
                    "nlist": self.config.nlist,
                    "nprobe": self.config.nprobe
                }
            }
        )
        
        logger.info("Milvus vectorstore ready")
    
    def _create_milvus_collection(self):
        """Create optimized Milvus collection"""
        logger.info(f"Creating collection: {self.config.collection_name}")
        
        # Define schema
        fields = [
            FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
            FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=self.config.vector_dim),
            FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=65535),
            FieldSchema(name="metadata", dtype=DataType.JSON)
        ]
        
        schema = CollectionSchema(
            fields=fields,
            description="Foundation-Sec-8B API Security Knowledge Base"
        )
        
        # Create collection with optimized parameters
        collection = Collection(
            name=self.config.collection_name,
            schema=schema,
            consistency_level="Strong",
            shards_num=2
        )
        
        # Create index
        index_params = {
            "metric_type": self.config.metric_type,
            "index_type": self.config.index_type,
            "params": {"nlist": self.config.nlist}
        }
        
        collection.create_index(
            field_name="embedding",
            index_params=index_params
        )
        
        # Load collection
        collection.load()
        
        logger.info("Collection created and indexed")
    
    def _initialize_llm(self):
        """Initialize Foundation-Sec-8B-Instruct LLM"""
        self.llm = FoundationSecLLM(self.config)
    
    def _initialize_retrieval_chains(self):
        """Initialize retrieval and QA chains"""
        logger.info("Setting up retrieval chains")
        
        # Initialize hybrid retriever (will be updated after document ingestion)
        self.retriever = None  # Will be set after documents are loaded
        
        # Security-focused prompts
        self.qa_prompt = PromptTemplate(
            template="""<s>[INST] You are analyzing security documentation to answer questions about API vulnerabilities.

Context from security knowledge base:
{context}

Security Question: {question}

Provide a comprehensive security analysis that includes:
1. Direct answer with specific details
2. Identified vulnerabilities and their CWE/OWASP classifications
3. Risk assessment and severity rating
4. Concrete remediation steps with code examples
5. Prevention best practices
6. Relevant compliance standards (PCI-DSS, ISO27001, etc.)

Format your response with clear sections and include specific technical details. [/INST]""",
            input_variables=["context", "question"]
        )
        
        # Conversation prompt for interactive sessions
        self.conversation_prompt = PromptTemplate(
            template="""<s>[INST] You are Foundation-Sec-8B, providing ongoing security consultation.

Current conversation context:
{chat_history}

Retrieved security information:
{context}

Current question: {question}

Continue the security analysis, referencing previous discussions where relevant. [/INST]""",
            input_variables=["chat_history", "context", "question"]
        )
        
        logger.info("Retrieval chains configured")
    
    def ingest_documents(self, docs_path: str) -> Dict[str, Any]:
        """Ingest and process security documents"""
        logger.info(f"Ingesting documents from {docs_path}")
        
        stats = {
            "total_documents": 0,
            "total_chunks": 0,
            "categories": defaultdict(int),
            "processing_time": 0
        }
        
        start_time = datetime.now()
        
        # Load different document types
        loaders = {
            "*.txt": TextLoader,
            "*.md": UnstructuredMarkdownLoader,
            "*.pdf": PDFLoader,
            "*.json": JSONLoader,
            "*.py": PythonLoader,
            "*.csv": CSVLoader
        }
        
        all_documents = []
        
        for pattern, loader_class in loaders.items():
            loader = DirectoryLoader(
                docs_path,
                glob=pattern,
                loader_cls=loader_class,
                show_progress=True
            )
            
            try:
                docs = loader.load()
                stats["total_documents"] += len(docs)
                
                # Split documents
                text_splitter = RecursiveCharacterTextSplitter(
                    chunk_size=self.config.chunk_size,
                    chunk_overlap=self.config.chunk_overlap,
                    separators=["\n\n", "\n", ".", "!", "?", " ", ""],
                    length_function=len
                )
                
                split_docs = text_splitter.split_documents(docs)
                
                # Process each document
                processed_docs = []
                for doc in split_docs:
                    processed_doc = self.processor.process_document(doc)
                    processed_docs.append(processed_doc)
                    
                    # Update stats
                    category = processed_doc.metadata.get("security_category", "general")
                    stats["categories"][category] += 1
                
                all_documents.extend(processed_docs)
                
            except Exception as e:
                logger.error(f"Failed to load {pattern}: {e}")
        
        # Store documents for retriever
        self.documents = all_documents
        stats["total_chunks"] = len(all_documents)
        
        # Add to vectorstore in batches
        if all_documents:
            logger.info(f"Adding {len(all_documents)} chunks to vectorstore")
            
            batch_size = 100
            for i in range(0, len(all_documents), batch_size):
                batch = all_documents[i:i + batch_size]
                self.vectorstore.add_documents(batch)
                logger.info(f"Processed batch {i//batch_size + 1}/{(len(all_documents) + batch_size - 1)//batch_size}")
            
            # Initialize hybrid retriever with documents
            self.retriever = HybridRetriever(
                vectorstore=self.vectorstore,
                documents=all_documents,
                config=self.config
            )
            
            # Update QA chains with retriever
            self._update_chains_with_retriever()
        
        stats["processing_time"] = (datetime.now() - start_time).total_seconds()
        self.metrics["documents_processed"] += stats["total_chunks"]
        
        logger.info(f"Ingestion complete: {stats}")
        return stats
    
    def _update_chains_with_retriever(self):
        """Update chains after retriever is initialized"""
        
        # Initialize QA chain
        self.qa_chain = RetrievalQA.from_chain_type(
            llm=self.llm,
            chain_type="stuff",
            retriever=self.retriever,
            return_source_documents=True,
            chain_type_kwargs={"prompt": self.qa_prompt}
        )
        
        # Initialize conversation chain
        self.conversation_chain = ConversationalRetrievalChain.from_llm(
            llm=self.llm,
            retriever=self.retriever,
            memory=ConversationBufferWindowMemory(
                k=10,
                memory_key="chat_history",
                return_messages=True,
                output_key="answer"
            ),
            return_source_documents=True,
            combine_docs_chain_kwargs={"prompt": self.conversation_prompt}
        )
        
        logger.info("QA chains updated with retriever")
    
    def analyze_api_endpoint(self, 
                            endpoint_spec: Dict[str, Any],
                            analysis_depth: str = "comprehensive") -> Dict[str, Any]:
        """Analyze API endpoint for security vulnerabilities"""
        
        start_time = datetime.now()
        
        # Construct detailed query
        query = self._construct_security_query(endpoint_spec, analysis_depth)
        
        # Get analysis from RAG
        if not self.qa_chain:
            raise ValueError("QA chain not initialized. Please ingest documents first.")
        
        result = self.qa_chain({"query": query})
        
        # Parse and structure the analysis
        analysis = self._parse_security_analysis(result['result'])
        
        # Extract relevant sources
        sources = [
            {
                "content_preview": doc.page_content[:300],
                "metadata": doc.metadata
            }
            for doc in result.get('source_documents', [])[:5]
        ]
        
        # Calculate metrics
        response_time = (datetime.now() - start_time).total_seconds()
        self.metrics["queries_processed"] += 1
        self.metrics["avg_response_time"] = (
            (self.metrics["avg_response_time"] * (self.metrics["queries_processed"] - 1) + response_time) /
            self.metrics["queries_processed"]
        )
        
        return {
            "endpoint": endpoint_spec,
            "analysis": analysis,
            "raw_response": result['result'],
            "sources": sources,
            "response_time": response_time,
            "timestamp": datetime.now().isoformat()
        }
    
    def _construct_security_query(self, endpoint_spec: Dict, depth: str) -> str:
        """Construct detailed security analysis query"""
        
        base_query = f"""
Perform a {depth} security analysis of this API endpoint:

Endpoint: {endpoint_spec.get('path', 'Unknown')}
Method: {endpoint_spec.get('method', 'Unknown')}
Authentication: {endpoint_spec.get('auth_type', 'None specified')}
        """
        
        if 'parameters' in endpoint_spec:
            base_query += f"\nParameters: {json.dumps(endpoint_spec['parameters'], indent=2)}"
        
        if 'headers' in endpoint_spec:
            base_query += f"\nHeaders: {json.dumps(endpoint_spec['headers'], indent=2)}"
        
        if 'body_schema' in endpoint_spec:
            base_query += f"\nBody Schema: {json.dumps(endpoint_spec['body_schema'], indent=2)}"
        
        if depth == "comprehensive":
            base_query += """

Analyze for:
1. All OWASP Top 10 vulnerabilities
2. Authentication and authorization flaws
3. Input validation issues
4. Rate limiting and DoS vulnerabilities
5. Data exposure risks
6. Configuration security
7. Third-party integration risks
8. Compliance violations (PCI-DSS, GDPR)
"""
        elif depth == "quick":
            base_query += """

Focus on critical vulnerabilities:
1. Injection attacks
2. Broken authentication
3. Sensitive data exposure
"""
        
        return base_query
    
    def _parse_security_analysis(self, analysis_text: str) -> Dict[str, Any]:
        """Parse security analysis into structured format"""
        
        parsed = {
            "vulnerabilities": [],
            "severity_summary": {},
            "recommendations": [],
            "compliance_issues": [],
            "risk_score": 0
        }
        
        # Extract vulnerabilities (simplified - use NLP in production)
        vuln_section = re.search(r"vulnerabilities?:?(.*?)(?:recommendations?|$)", 
                                 analysis_text, re.I | re.S)
        if vuln_section:
            vuln_text = vuln_section.group(1)
            
            # Extract CWE references
            cwe_matches = re.findall(r"CWE-\d+", vuln_text)
            for cwe in cwe_matches:
                parsed["vulnerabilities"].append({
                    "cwe_id": cwe,
                    "type": "Detected from analysis"
                })
        
        # Extract severity counts
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = len(re.findall(f"\\b{severity}\\b", analysis_text, re.I))
            if count > 0:
                parsed["severity_summary"][severity] = count
        
        # Calculate risk score
        risk_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
        total_score = sum(
            parsed["severity_summary"].get(sev, 0) * weight
            for sev, weight in risk_weights.items()
        )
        parsed["risk_score"] = min(100, total_score * 2)  # Normalize to 0-100
        
        return parsed
    
    def get_remediation_plan(self, 
                            vulnerabilities: List[Dict],
                            priority: str = "risk-based") -> Dict[str, Any]:
        """Generate detailed remediation plan"""
        
        # Construct remediation query
        vuln_summary = "\n".join([
            f"- {v.get('type', 'Unknown')}: {v.get('cwe_id', 'N/A')} "
            f"(Severity: {v.get('severity', 'Unknown')})"
            for v in vulnerabilities
        ])
        
        query = f"""
Create a detailed remediation plan for these vulnerabilities:

{vuln_summary}

Priority: {priority}

Include:
1. Step-by-step fixes with code examples
2. Implementation timeline
3. Testing procedures
4. Rollback plans
5. Long-term prevention strategies
"""
        
        result = self.qa_chain({"query": query})
        
        return {
            "vulnerabilities": vulnerabilities,
            "remediation_plan": result['result'],
            "priority": priority,
            "sources": [doc.metadata for doc in result.get('source_documents', [])]
        }
    
    def interactive_session(self, initial_query: str = None):
        """Start interactive security consultation session"""
        
        print("\n" + "="*80)
        print("Foundation-Sec-8B Interactive Security Consultation")
        print("="*80 + "\n")
        
        if initial_query:
            response = self.conversation_chain({"question": initial_query})
            print(f"🔒 Analysis:\n{response['answer']}\n")
        
        while True:
            query = input("\n💬 Your security question (or 'exit'): ").strip()
            
            if query.lower() in ['exit', 'quit', 'bye']:
                print("\n✅ Session ended. Stay secure!")
                break
            
            if query:
                response = self.conversation_chain({"question": query})
                print(f"\n🔒 Foundation-Sec-8B:\n{response['answer']}\n")
                
                if response.get('source_documents'):
                    print(f"📚 Referenced {len(response['source_documents'])} sources")

class MultiAgentOrchestrator:
    """Orchestrate multiple security agents with RAG"""
    
    def __init__(self, rag_system: FoundationSecRAGSystem):
        self.rag = rag_system
        self.agents = {
            "auth": self._analyze_authentication,
            "data": self._analyze_data_handling,
            "config": self._analyze_configuration,
            "crypto": self._analyze_cryptography,
            "owasp": self._analyze_owasp_compliance
        }
    
    async def comprehensive_api_scan(self, api_specs: List[Dict]) -> Dict[str, Any]:
        """Run comprehensive security scan across all agents"""
        
        scan_id = hashlib.sha256(f"{datetime.now()}".encode()).hexdigest()[:16]
        
        results = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "total_endpoints": len(api_specs),
            "findings_by_agent": defaultdict(list),
            "critical_findings": [],
            "summary": {}
        }
        
        # Process each endpoint
        for spec in api_specs:
            endpoint_results = await self._analyze_endpoint(spec)
            
            # Aggregate results by agent
            for agent_name, agent_results in endpoint_results.items():
                results["findings_by_agent"][agent_name].append(agent_results)
                
                # Extract critical findings
                if agent_results.get("risk_score", 0) > 70:
                    results["critical_findings"].append({
                        "endpoint": spec.get("path"),
                        "agent": agent_name,
                        "risk_score": agent_results["risk_score"],
                        "findings": agent_results.get("vulnerabilities", [])
                    })
        
        # Generate summary
        results["summary"] = self._generate_scan_summary(results)
        
        return results
    
    async def _analyze_endpoint(self, spec: Dict) -> Dict[str, Any]:
        """Analyze single endpoint with all agents"""
        
        tasks = {}
        for agent_name, agent_func in self.agents.items():
            tasks[agent_name] = agent_func(spec)
        
        # Run analyses in parallel
        results = {}
        for agent_name, task in tasks.items():
            try:
                results[agent_name] = await task
            except Exception as e:
                logger.error(f"Agent {agent_name} failed: {e}")
                results[agent_name] = {"error": str(e)}
        
        return results
    
    async def _analyze_authentication(self, spec: Dict) -> Dict:
        """AuthAgent analysis"""
        return self.rag.analyze_api_endpoint(
            spec,
            analysis_depth="comprehensive"
        )
    
    async def _analyze_data_handling(self, spec: Dict) -> Dict:
        """DataAgent analysis"""
        return self.rag.analyze_api_endpoint(
            spec,
            analysis_depth="comprehensive"
        )
    
    async def _analyze_configuration(self, spec: Dict) -> Dict:
        """ConfigAgent analysis"""
        return self.rag.analyze_api_endpoint(
            spec,
            analysis_depth="comprehensive"
        )
    
    async def _analyze_cryptography(self, spec: Dict) -> Dict:
        """CryptoAgent analysis"""
        return self.rag.analyze_api_endpoint(
            spec,
            analysis_depth="comprehensive"
        )
    
    async def _analyze_owasp_compliance(self, spec: Dict) -> Dict:
        """OWASPAgent analysis"""
        return self.rag.analyze_api_endpoint(
            spec,
            analysis_depth="comprehensive"
        )
    
    def _generate_scan_summary(self, results: Dict) -> Dict:
        """Generate executive summary of scan results"""
        
        total_findings = sum(
            len(findings) 
            for findings in results["findings_by_agent"].values()
        )
        
        return {
            "total_findings": total_findings,
            "critical_count": len(results["critical_findings"]),
            "endpoints_scanned": results["total_endpoints"],
            "risk_level": "CRITICAL" if results["critical_findings"] else "MODERATE"
        }

# Main execution
def main():
    """Initialize and run Foundation-Sec-8B-Instruct RAG System"""
    
    # Configuration
    config = FoundationSecConfig()
    
    # Initialize system
    logger.info("Starting Foundation-Sec-8B-Instruct RAG System")
    rag_system = FoundationSecRAGSystem(config)
    
    # Ingest documents
    docs_path = "./security_knowledge_base"
    if Path(docs_path).exists():
        stats = rag_system.ingest_documents(docs_path)
        print(f"\n✅ Ingested {stats['total_chunks']} document chunks")
        print(f"📊 Categories: {dict(stats['categories'])}")
    else:
        logger.warning(f"Creating sample documents (path {docs_path} not found)")
        
        # Create sample documents for demonstration
        sample_docs = [
            Document(
                page_content="""
                SQL Injection (CWE-89) is a critical vulnerability in API endpoints.
                Prevention requires parameterized queries and input validation.
                OWASP A03:2021 - Injection remains a top security risk.
                Use prepared statements and stored procedures for database queries.
                """,
                metadata={"source": "security_guide.txt"}
            ),
            Document(
                page_content="""
                JWT authentication vulnerabilities include algorithm confusion attacks.
                Always validate the algorithm header and use strong secret keys.
                Implement token expiration and refresh mechanisms.
                CWE-287: Improper Authentication is a high severity issue.
                """,
                metadata={"source": "auth_best_practices.txt"}
            )
        ]
        
        # Add sample documents
        for doc in sample_docs:
            processed_doc = rag_system.processor.process_document(doc)
            rag_system.documents.append(processed_doc)
        
        rag_system.vectorstore.add_documents(rag_system.documents)
        rag_system.retriever = HybridRetriever(
            vectorstore=rag_system.vectorstore,
            documents=rag_system.documents,
            config=config
        )
        rag_system._update_chains_with_retriever()
    
    # Demo: Analyze sample API endpoint
    sample_endpoint = {
        "path": "/api/v1/users/login",
        "method": "POST",
        "auth_type": "Basic Authentication",
        "parameters": {
            "username": {"type": "string", "required": True},
            "password": {"type": "string", "required": True}
        },
        "headers": {
            "Content-Type": "application/json"
        }
    }
    
    print("\n" + "="*80)
    print("Foundation-Sec-8B-Instruct Security Analysis Demo")
    print("="*80 + "\n")
    
    # Run analysis
    analysis = rag_system.analyze_api_endpoint(sample_endpoint)
    
    print(f"🔍 Analyzing: {sample_endpoint['path']}")
    print(f"📊 Risk Score: {analysis['analysis']['risk_score']}/100")
    print(f"⚠️  Vulnerabilities Found: {len(analysis['analysis']['vulnerabilities'])}")
    
    if analysis['analysis']['vulnerabilities']:
        print("\n🚨 Detected Issues:")
        for vuln in analysis['analysis']['vulnerabilities']:
            print(f"   - {vuln['cwe_id']}: {vuln['type']}")
    
    print(f"\n⏱️  Analysis Time: {analysis['response_time']:.2f} seconds")
    print(f"📚 Sources Referenced: {len(analysis['sources'])}")
    
    # System metrics
    print("\n" + "="*80)
    print("System Metrics")
    print("="*80)
    print(f"Documents Processed: {rag_system.metrics['documents_processed']}")
    print(f"Queries Handled: {rag_system.metrics['queries_processed']}")
    print(f"Avg Response Time: {rag_system.metrics['avg_response_time']:.2f}s")
    
    # Start interactive session
    print("\n" + "="*80)
    rag_system.interactive_session()
    
    return rag_system

if __name__ == "__main__":
    rag_system = main()
