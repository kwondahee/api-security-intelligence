# initialize_kb.py
"""
Initialize Milvus knowledge base with security documents
"""

import logging
from rag.rag import RAGSystem

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Initialize knowledge base with default security documents."""
    
    print("=== Initializing Knowledge Base ===")
    
    # Default security documents
    documents = [
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
                "keywords": ["bfla", "broken function level authorization", "rbac"]
            }
        },
        {
            "text": "Missing Authentication vulnerabilities occur when sensitive API endpoints are accessible without any authentication. All endpoints that access sensitive data or perform privileged operations must require authentication. Implement authentication middleware that validates credentials before processing requests. Return 401 Unauthorized for unauthenticated requests. CWE-306 describes this weakness.",
            "source": "OWASP_Authentication_Guide",
            "metadata": {
                "cwe_ids": ["CWE-306"],
                "owasp_categories": ["A07"],
                "severity": "CRITICAL",
                "keywords": ["missing authentication", "authentication enforcement"]
            }
        },
        {
            "text": "JWT (JSON Web Token) security requires careful implementation. Never accept tokens with 'alg: none'. Always validate the signature using a strong secret key (minimum 256 bits). Implement token expiration and refresh mechanisms. Store JWTs securely and never in localStorage for sensitive applications. Validate all claims and check token revocation. CWE-347 covers improper verification of cryptographic signatures.",
            "source": "JWT_Security_Best_Practices",
            "metadata": {
                "cwe_ids": ["CWE-347"],
                "owasp_categories": ["A07"],
                "severity": "HIGH",
                "keywords": ["jwt", "json web token", "signature validation"]
            }
        },
        {
            "text": "Rate limiting is essential for preventing abuse and ensuring API availability. Implement rate limiting using algorithms like token bucket or sliding window. Set appropriate limits based on user roles and endpoint sensitivity. Return 429 Too Many Requests when limits are exceeded. Include rate limit headers in responses. CWE-770 addresses allocation of resources without limits.",
            "source": "API_Rate_Limiting_Guide",
            "metadata": {
                "cwe_ids": ["CWE-770"],
                "owasp_categories": ["A04", "API4"],
                "severity": "MEDIUM",
                "keywords": ["rate limiting", "token bucket", "dos prevention"]
            }
        },
        {
            "text": "Path Traversal vulnerabilities allow attackers to access files and directories outside the intended directory. Validate and sanitize all file path inputs. Use whitelisting for allowed file names and paths. Implement canonicalization to resolve symbolic links and relative paths. Never construct file paths using user input directly. CWE-22 defines this vulnerability.",
            "source": "Path_Traversal_Prevention",
            "metadata": {
                "cwe_ids": ["CWE-22"],
                "owasp_categories": ["A03"],
                "severity": "HIGH",
                "keywords": ["path traversal", "directory traversal", "canonicalization"]
            }
        }
    ]
    
    try:
        # Initialize RAG system (will connect to Milvus)
        print("Connecting to Milvus...")
        rag = RAGSystem()
        
        # Add documents
        print(f"Adding {len(documents)} documents to vector store...")
        rag.add_documents(documents)
        
        print(f"✓ Successfully initialized knowledge base with {len(documents)} documents")
        
        # Test retrieval
        print("\nTesting retrieval...")
        results = rag.retrieve("SQL injection prevention", severity="CRITICAL", top_k=3)
        print(f"✓ Retrieved {len(results)} documents for test query")
        
        for i, doc in enumerate(results, 1):
            print(f"  {i}. {doc['source']} (score: {doc['score']:.3f})")
        
    except Exception as e:
        logger.error(f"Failed to initialize knowledge base: {e}")
        print(f"❌ Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
