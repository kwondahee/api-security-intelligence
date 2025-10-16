# rag/rag.py
"""
Core RAG System Implementation
Provides document retrieval for security recommendations.
"""

import logging
import time
import json
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from rag.cache import RAGCache
from rag.queries import QueryGenerator

logger = logging.getLogger(__name__)

class RAGSystem:
    """
    RAG System for security knowledge retrieval.
    
    Features:
    - Document-based retrieval from knowledge base
    - Severity-based caching
    - Query optimization for agent findings
    """
    
    def __init__(self, knowledge_base_path: str = "rag_data/knowledge_base.json"):
        self.kb_path = knowledge_base_path
        self.documents = []
        self.cache = RAGCache()
        self.query_generator = QueryGenerator()
        
        logger.info("Initializing RAG System...")
        self._load_knowledge_base()
    
    def _load_knowledge_base(self):
        """Load knowledge base from JSON file."""
        if not os.path.exists(self.kb_path):
            logger.warning(f"Knowledge base not found: {self.kb_path}")
            logger.info("Creating default knowledge base...")
            self._create_default_kb()
        
        try:
            with open(self.kb_path, 'r', encoding='utf-8') as f:
                self.documents = json.load(f)
            logger.info(f"Loaded {len(self.documents)} documents from knowledge base")
        except Exception as e:
            logger.error(f"Failed to load knowledge base: {e}")
            self.documents = []
    
    def _create_default_kb(self):
        """Create default knowledge base with essential security documents."""
        default_docs = [
            {
                "text": "SQL Injection is a code injection technique that exploits security vulnerabilities in an application's database layer. To prevent SQL injection attacks, always use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries. Implement input validation and use stored procedures where appropriate. CWE-89 classifies this vulnerability. OWASP ranks it under A03:2021 Injection.",
                "source": "OWASP_SQL_Injection_Prevention",
                "metadata": {
                    "cwe_ids": ["CWE-89"],
                    "owasp_categories": ["A03"],
                    "severity": "CRITICAL",
                    "keywords": ["sql injection", "parameterized queries", "prepared statements"]
                }
            },
            {
                "text": "Cross-Site Scripting (XSS) attacks occur when an application includes untrusted data in a web page without proper validation or escaping. To prevent XSS, implement output encoding based on context (HTML, JavaScript, URL, CSS). Use Content Security Policy (CSP) headers to restrict script execution. Validate and sanitize all user inputs. CWE-79 defines this vulnerability class.",
                "source": "OWASP_XSS_Prevention",
                "metadata": {
                    "cwe_ids": ["CWE-79"],
                    "owasp_categories": ["A03"],
                    "severity": "HIGH",
                    "keywords": ["xss", "cross-site scripting", "output encoding", "csp"]
                }
            },
            {
                "text": "Broken Object Level Authorization (BOLA) occurs when an application does not properly verify that a user is authorized to access a specific object. Always implement authorization checks at the object level. Verify that the authenticated user has permission to perform the requested action on the specific resource. Use user IDs from trusted sessions rather than request parameters. OWASP API Security Top 10 2023 ranks this as API1:2023.",
                "source": "OWASP_API_Security_BOLA",
                "metadata": {
                    "cwe_ids": ["CWE-639"],
                    "owasp_categories": ["API1"],
                    "severity": "CRITICAL",
                    "keywords": ["bola", "broken object level authorization", "access control"]
                }
            },
            {
                "text": "Broken Function Level Authorization (BFLA) allows attackers to access functions they shouldn't have permission to use. Implement proper role-based access control (RBAC). Verify user permissions before executing any privileged operations. Deny access by default and explicitly grant permissions. Administrative functions should have additional authentication layers. OWASP API5:2023 addresses this vulnerability.",
                "source": "OWASP_API_Security_BFLA",
                "metadata": {
                    "cwe_ids": ["CWE-285"],
                    "owasp_categories": ["API5"],
                    "severity": "CRITICAL",
                    "keywords": ["bfla", "broken function level authorization", "rbac", "privilege escalation"]
                }
            },
            {
                "text": "Missing Authentication vulnerabilities occur when sensitive API endpoints are accessible without any authentication. All endpoints that access sensitive data or perform privileged operations must require authentication. Implement authentication middleware that validates credentials before processing requests. Return 401 Unauthorized for unauthenticated requests. CWE-306 describes this weakness.",
                "source": "OWASP_Authentication_Guide",
                "metadata": {
                    "cwe_ids": ["CWE-306"],
                    "owasp_categories": ["A07"],
                    "severity": "CRITICAL",
                    "keywords": ["missing authentication", "authentication enforcement", "unauthorized access"]
                }
            },
            {
                "text": "JWT (JSON Web Token) security requires careful implementation. Never accept tokens with 'alg: none'. Always validate the signature using a strong secret key (minimum 256 bits). Implement token expiration and refresh mechanisms. Store JWTs securely and never in localStorage for sensitive applications. Validate all claims and check token revocation. CWE-347 covers improper verification of cryptographic signatures.",
                "source": "JWT_Security_Best_Practices",
                "metadata": {
                    "cwe_ids": ["CWE-347"],
                    "owasp_categories": ["A07"],
                    "severity": "HIGH",
                    "keywords": ["jwt", "json web token", "signature validation", "algorithm none"]
                }
            },
            {
                "text": "Rate limiting is essential for preventing abuse and ensuring API availability. Implement rate limiting using algorithms like token bucket or sliding window. Set appropriate limits based on user roles and endpoint sensitivity. Return 429 Too Many Requests when limits are exceeded. Include rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset) in responses. CWE-770 addresses allocation of resources without limits.",
                "source": "API_Rate_Limiting_Guide",
                "metadata": {
                    "cwe_ids": ["CWE-770"],
                    "owasp_categories": ["A04", "API4"],
                    "severity": "MEDIUM",
                    "keywords": ["rate limiting", "token bucket", "resource exhaustion", "dos prevention"]
                }
            },
            {
                "text": "Path Traversal vulnerabilities allow attackers to access files and directories outside the intended directory. Validate and sanitize all file path inputs. Use whitelisting for allowed file names and paths. Implement canonicalization to resolve symbolic links and relative paths. Never construct file paths using user input directly. Use chroot jails or similar OS-level protections. CWE-22 defines this vulnerability.",
                "source": "Path_Traversal_Prevention",
                "metadata": {
                    "cwe_ids": ["CWE-22"],
                    "owasp_categories": ["A03"],
                    "severity": "HIGH",
                    "keywords": ["path traversal", "directory traversal", "file access", "canonicalization"]
                }
            },
            {
                "text": "Authentication bypass vulnerabilities occur when authentication mechanisms can be circumvented. Avoid trusting client-supplied headers like X-Forwarded-For or X-Original-URL for authentication decisions. Implement server-side session management. Use secure session identifiers. Validate all authentication tokens on the server side. Never rely solely on client-side authentication. CWE-287 describes improper authentication.",
                "source": "Authentication_Bypass_Prevention",
                "metadata": {
                    "cwe_ids": ["CWE-287"],
                    "owasp_categories": ["A07"],
                    "severity": "CRITICAL",
                    "keywords": ["authentication bypass", "session management", "header manipulation"]
                }
            },
            {
                "text": "Weak or default credentials pose a significant security risk. Enforce strong password policies requiring minimum length, complexity, and rotation. Prohibit common passwords and default credentials. Implement account lockout after failed login attempts. Use multi-factor authentication for sensitive operations. Never hardcode credentials in source code. CWE-798 addresses use of hard-coded credentials.",
                "source": "Credential_Management_Guide",
                "metadata": {
                    "cwe_ids": ["CWE-798", "CWE-521"],
                    "owasp_categories": ["A07"],
                    "severity": "HIGH",
                    "keywords": ["weak credentials", "default passwords", "password policy", "mfa"]
                }
            },
            {
                "text": "Multi-tenancy security requires strict isolation between tenant data. Always include tenant identifiers in database queries. Validate that the authenticated user's tenant ID matches the requested resource's tenant. Use row-level security in databases. Implement tenant-aware authorization checks at every layer. Never trust client-provided tenant identifiers.",
                "source": "Multi_Tenancy_Security_Guide",
                "metadata": {
                    "cwe_ids": ["CWE-639"],
                    "owasp_categories": ["API1"],
                    "severity": "HIGH",
                    "keywords": ["multi-tenancy", "tenant isolation", "cross-tenant access"]
                }
            },
            {
                "text": "API documentation accuracy is crucial for security. Maintain up-to-date OpenAPI/Swagger specifications. Document all endpoints including authentication requirements. Identify and document shadow APIs (undocumented endpoints). Remove deprecated endpoints or clearly mark them. Implement automated testing to verify documentation matches implementation. Accurate documentation helps security teams identify and protect all API surfaces.",
                "source": "API_Documentation_Best_Practices",
                "metadata": {
                    "cwe_ids": [],
                    "owasp_categories": ["API9"],
                    "severity": "MEDIUM",
                    "keywords": ["api documentation", "openapi", "swagger", "shadow api", "undocumented endpoints"]
                }
            }
        ]
        
        # Create directory if it doesn't exist
        Path(self.kb_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Save default knowledge base
        with open(self.kb_path, 'w', encoding='utf-8') as f:
            json.dump(default_docs, f, indent=2, ensure_ascii=False)
        
        self.documents = default_docs
        logger.info(f"Created default knowledge base with {len(default_docs)} documents")
    
    def retrieve(self, query: str = None, severity: str = 'MEDIUM', 
                 agent_name: Optional[str] = None,
                 finding: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Retrieve relevant documents for a query.
        
        Args:
            query: Search query (optional if agent_name and finding provided)
            severity: Finding severity for cache TTL
            agent_name: Name of requesting agent
            finding: Full finding dict for query generation
            
        Returns:
            List of relevant documents
        """
        start_time = time.time()
        
        # Generate optimized query if agent context provided
        if agent_name and finding:
            query = self.query_generator.generate(agent_name, finding)
            logger.info(f"Generated query for {agent_name}: {query[:80]}...")
        
        if not query:
            logger.warning("No query provided for retrieval")
            return []
        
        # Check cache
        cached = self.cache.get(query, severity)
        if cached is not None:
            latency = (time.time() - start_time) * 1000
            logger.info(f"Cache hit - {len(cached)} docs (latency: {latency:.1f}ms)")
            return cached
        
        # Perform retrieval
        results = self._search_documents(query)
        
        # Cache results
        self.cache.set(query, results, severity)
        
        latency = (time.time() - start_time) * 1000
        logger.info(f"Retrieved {len(results)} docs (latency: {latency:.1f}ms)")
        
        return results
    
    def _search_documents(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search documents using keyword matching.
        Simple but effective approach without external dependencies.
        """
        if not self.documents:
            return []
        
        query_lower = query.lower()
        query_terms = set(query_lower.split())
        
        # Score each document
        scored_docs = []
        for doc in self.documents:
            score = self._calculate_score(doc, query_lower, query_terms)
            if score > 0:
                doc_copy = doc.copy()
                doc_copy['score'] = score
                scored_docs.append(doc_copy)
        
        # Sort by score and return top_k
        scored_docs.sort(key=lambda x: x['score'], reverse=True)
        return scored_docs[:top_k]
    
    def _calculate_score(self, doc: Dict[str, Any], query_lower: str, 
                        query_terms: set) -> float:
        """Calculate relevance score for a document."""
        score = 0.0
        
        text = doc.get('text', '').lower()
        metadata = doc.get('metadata', {})
        keywords = metadata.get('keywords', [])
        
        # Exact phrase match (highest weight)
        if query_lower in text:
            score += 10.0
        
        # Keyword matches
        for keyword in keywords:
            if keyword.lower() in query_lower:
                score += 5.0
        
        # Term frequency
        for term in query_terms:
            if len(term) > 2:  # Skip very short terms
                count = text.count(term)
                score += count * 0.5
        
        # CWE ID match
        cwe_ids = metadata.get('cwe_ids', [])
        for cwe in cwe_ids:
            if cwe.lower() in query_lower:
                score += 8.0
        
        # OWASP category match
        owasp_cats = metadata.get('owasp_categories', [])
        for cat in owasp_cats:
            if cat.lower() in query_lower:
                score += 6.0
        
        return score
    
    def add_documents(self, documents: List[Dict[str, Any]]):
        """Add new documents to knowledge base."""
        self.documents.extend(documents)
        
        # Save to file
        try:
            with open(self.kb_path, 'w', encoding='utf-8') as f:
                json.dump(self.documents, f, indent=2, ensure_ascii=False)
            logger.info(f"Added {len(documents)} documents to knowledge base")
            
            # Trigger cache invalidation
            self.cache.on_kb_update()
        except Exception as e:
            logger.error(f"Failed to save knowledge base: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()
