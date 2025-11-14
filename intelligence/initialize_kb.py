# initialize_kb.py
"""
Initialize Qdrant knowledge base with security documents
"""

# Force UTF-8 encoding for Windows
import sys
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import logging
from llm.rag import RAGSystem

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Initialize knowledge base with default security documents."""
    
    print("=== Initializing Knowledge Base (Qdrant) ===")
    
    # -------------------------------------------------------------
    # Default Knowledge Base Documents
    # -------------------------------------------------------------
    documents = [
        {
            "text": "SQL Injection is a code injection technique ... CWE-89 classifies this vulnerability.",
            "source": "OWASP_SQL_Injection_Prevention",
            "metadata": {
                "cwe_ids": "CWE-89",
                "owasp_categories": "A03",
                "severity": "CRITICAL",
                "keywords": "sql injection, parameterized queries, prepared statements"
            }
        },
        {
            "text": "Cross-Site Scripting (XSS) attacks occur when ... CWE-79 defines this vulnerability class.",
            "source": "OWASP_XSS_Prevention",
            "metadata": {
                "cwe_ids": "CWE-79",
                "owasp_categories": "A03",
                "severity": "HIGH",
                "keywords": "xss, cross-site scripting, output encoding, csp"
            }
        },
        {
            "text": "Broken Object Level Authorization (BOLA) occurs when ... API1:2023.",
            "source": "OWASP_API_Security_BOLA",
            "metadata": {
                "cwe_ids": "CWE-639",
                "owasp_categories": "API1",
                "severity": "CRITICAL",
                "keywords": "bola, authorization, access control"
            }
        },
        {
            "text": "Broken Function Level Authorization (BFLA) allows attackers ... API5:2023.",
            "source": "OWASP_API_Security_BFLA",
            "metadata": {
                "cwe_ids": "CWE-285",
                "owasp_categories": "API5",
                "severity": "CRITICAL",
                "keywords": "bfla, rbac, access control"
            }
        },
        {
            "text": "Missing Authentication vulnerabilities occur when ... CWE-306 describes this weakness.",
            "source": "OWASP_Authentication_Guide",
            "metadata": {
                "cwe_ids": "CWE-306",
                "owasp_categories": "A07",
                "severity": "CRITICAL",
                "keywords": "missing authentication"
            }
        },
        {
            "text": "JWT security requires careful implementation ... CWE-347.",
            "source": "JWT_Security_Best_Practices",
            "metadata": {
                "cwe_ids": "CWE-347",
                "owasp_categories": "A07",
                "severity": "HIGH",
                "keywords": "jwt, token, signature"
            }
        },
        {
            "text": "Rate limiting is essential for preventing abuse ... CWE-770.",
            "source": "API_Rate_Limiting_Guide",
            "metadata": {
                "cwe_ids": "CWE-770",
                "owasp_categories": "A04, API4",
                "severity": "MEDIUM",
                "keywords": "rate limiting, dos prevention"
            }
        },
        {
            "text": "Path Traversal vulnerabilities allow attackers ... CWE-22.",
            "source": "Path_Traversal_Prevention",
            "metadata": {
                "cwe_ids": "CWE-22",
                "owasp_categories": "A03",
                "severity": "HIGH",
                "keywords": "path traversal, directory traversal"
            }
        },
        {
            "text": "Authentication bypass vulnerabilities occur when ... CWE-287.",
            "source": "Authentication_Bypass_Prevention",
            "metadata": {
                "cwe_ids": "CWE-287",
                "owasp_categories": "A07",
                "severity": "CRITICAL",
                "keywords": "authentication bypass, session management"
            }
        },
        {
            "text": "Weak or default credentials pose major risk ... CWE-798, CWE-521.",
            "source": "Credential_Management_Guide",
            "metadata": {
                "cwe_ids": "CWE-798, CWE-521",
                "owasp_categories": "A07",
                "severity": "HIGH",
                "keywords": "weak credentials, default passwords"
            }
        },
        {
            "text": "Multi-tenancy security requires strict isolation ...",
            "source": "Multi_Tenancy_Security_Guide",
            "metadata": {
                "cwe_ids": "CWE-639",
                "owasp_categories": "API1",
                "severity": "HIGH",
                "keywords": "multi-tenancy, tenant isolation"
            }
        },
        {
            "text": "API documentation accuracy is crucial ... API9.",
            "source": "API_Documentation_Best_Practices",
            "metadata": {
                "cwe_ids": "",
                "owasp_categories": "API9",
                "severity": "MEDIUM",
                "keywords": "api documentation, swagger"
            }
        }
    ]

    try:
        # -------------------------------------------------------------
        # Initialize RAGSystem (connects to Qdrant, not Milvus)
        # -------------------------------------------------------------
        print("Connecting to Qdrant...")
        rag = RAGSystem()  # uses localhost:6333

        # -------------------------------------------------------------
        # Insert documents
        # -------------------------------------------------------------
        print(f"Adding {len(documents)} documents to Qdrant...")
        rag.add_documents(documents, skip_cache_invalidation=True)

        print(f"[OK] Successfully initialized KB with {len(documents)} documents")

        # -------------------------------------------------------------
        # Test retrieval
        # -------------------------------------------------------------
        print("\nTesting retrieval: 'SQL injection prevention'...")
        results = rag.retrieve("SQL injection prevention", severity="CRITICAL", top_k=3)
        print(f"[OK] Retrieved {len(results)} documents")

        for i, doc in enumerate(results, 1):
            print(f"  {i}. {doc['source']} (score={doc['score']:.3f})")

        # -------------------------------------------------------------
        # Test retrieval 2
        # -------------------------------------------------------------
        print("\nTesting retrieval: 'BOLA authorization'...")
        results2 = rag.retrieve("BOLA authorization", severity="HIGH", top_k=3)

        for i, doc in enumerate(results2, 1):
            print(f"  {i}. {doc['source']} (score={doc['score']:.3f})")

        # -------------------------------------------------------------
        # Test cache
        # -------------------------------------------------------------
        print("\nTesting cache reuse...")
        cached = rag.retrieve("SQL injection prevention", severity="CRITICAL", top_k=3)
        print(f"[OK] Cache returned {len(cached)} items")

        stats = rag.get_cache_stats()
        print("\nCache Stats:")
        print(stats)

        print("\n===============================================")
        print("[OK] Knowledge Base Initialization Complete!")
        print("===============================================")

    except Exception as e:
        logger.error(f"Failed to initialize KB: {e}")
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
