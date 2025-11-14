# initialize_kb_fixed.py
"""
Initialize Qdrant knowledge base with security documents
Fixed version with proper dependency handling
"""

# Force UTF-8 encoding for Windows
import sys
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import logging

# Check NumPy version before importing anything else
def check_numpy_version():
    """Check and fix NumPy version compatibility."""
    try:
        import numpy as np
        version = np.__version__
        major_version = int(version.split('.')[0])
        
        if major_version >= 2:
            print(f"⚠️  WARNING: NumPy {version} detected (need <2.0 for PyTorch)")
            print("\n🔧 FIXING: Please run the following command:")
            print("   pip install 'numpy<2.0'")
            print("\nOr reinstall all dependencies:")
            print("   pip install -r requirements_fixed.txt")
            return False
        else:
            print(f"✓ NumPy {version} is compatible")
            return True
    except ImportError:
        print("⚠️  NumPy not installed")
        return False

# Run the check
if not check_numpy_version():
    print("\n❌ Cannot proceed with incompatible NumPy version")
    print("   Exiting...")
    sys.exit(1)

# Now safe to import other modules
from llm.rag import RAGSystem

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """Initialize knowledge base with default security documents."""
    
    print("\n" + "="*70)
    print("=== Initializing Knowledge Base (Qdrant) ===")
    print("="*70 + "\n")
    
    # -------------------------------------------------------------
    # Default Knowledge Base Documents
    # -------------------------------------------------------------
    documents = [
        {
            "text": "SQL Injection is a code injection technique that exploits vulnerabilities in database queries. Attackers insert malicious SQL code through user input fields, potentially gaining unauthorized access to sensitive data, modifying database contents, or executing administrative operations. Prevention requires using parameterized queries (prepared statements), input validation, and principle of least privilege for database accounts. CWE-89 classifies this vulnerability.",
            "source": "OWASP_SQL_Injection_Prevention",
            "metadata": {
                "cwe_ids": "CWE-89",
                "owasp_categories": "A03",
                "severity": "CRITICAL",
                "keywords": "sql injection, parameterized queries, prepared statements"
            }
        },
        {
            "text": "Cross-Site Scripting (XSS) attacks occur when untrusted data is included in web pages without proper validation or escaping. There are three main types: Reflected XSS (non-persistent), Stored XSS (persistent), and DOM-based XSS. Prevention includes context-aware output encoding, Content Security Policy (CSP) headers, and input validation. CWE-79 defines this vulnerability class.",
            "source": "OWASP_XSS_Prevention",
            "metadata": {
                "cwe_ids": "CWE-79",
                "owasp_categories": "A03",
                "severity": "HIGH",
                "keywords": "xss, cross-site scripting, output encoding, csp"
            }
        },
        {
            "text": "Broken Object Level Authorization (BOLA) occurs when an API does not properly verify that a user has permission to access a specific object. Attackers can manipulate object IDs in API requests to access data belonging to other users. This is the #1 API security risk. Prevention requires implementing proper authorization checks for every object access. API1:2023.",
            "source": "OWASP_API_Security_BOLA",
            "metadata": {
                "cwe_ids": "CWE-639",
                "owasp_categories": "API1",
                "severity": "CRITICAL",
                "keywords": "bola, authorization, access control, idor"
            }
        },
        {
            "text": "Broken Function Level Authorization (BFLA) allows attackers to access administrative or privileged functions by manipulating API endpoints or parameters. This occurs when APIs don't properly enforce function-level access controls. Attackers might change HTTP methods, modify API paths, or tamper with request parameters to access restricted functionality. Prevention requires deny-by-default authorization and proper role-based access control (RBAC). API5:2023.",
            "source": "OWASP_API_Security_BFLA",
            "metadata": {
                "cwe_ids": "CWE-285",
                "owasp_categories": "API5",
                "severity": "CRITICAL",
                "keywords": "bfla, rbac, access control, privilege escalation"
            }
        },
        {
            "text": "Missing Authentication vulnerabilities occur when API endpoints are accessible without any form of authentication. This allows anonymous users to access sensitive data or functionality that should be protected. Common in APIs that assume all requests come from trusted sources or when developers forget to add authentication middleware. CWE-306 describes this weakness.",
            "source": "OWASP_Authentication_Guide",
            "metadata": {
                "cwe_ids": "CWE-306",
                "owasp_categories": "A07",
                "severity": "CRITICAL",
                "keywords": "missing authentication, unauthenticated access"
            }
        },
        {
            "text": "JWT security requires careful implementation to avoid common vulnerabilities. Issues include: accepting unsigned tokens (alg:none), weak signing keys, token exposure in URLs, missing expiration validation, and accepting tokens after logout. Best practices: always verify signatures, use strong keys, implement token rotation, validate all claims, and store tokens securely. CWE-347.",
            "source": "JWT_Security_Best_Practices",
            "metadata": {
                "cwe_ids": "CWE-347",
                "owasp_categories": "A07",
                "severity": "HIGH",
                "keywords": "jwt, token, signature, authentication"
            }
        },
        {
            "text": "Rate limiting is essential for preventing abuse and DoS attacks against APIs. Without proper rate limits, attackers can overwhelm services, perform credential stuffing, or scrape large amounts of data. Implementation should consider per-user, per-IP, and per-endpoint limits with appropriate thresholds and time windows. CWE-770.",
            "source": "API_Rate_Limiting_Guide",
            "metadata": {
                "cwe_ids": "CWE-770",
                "owasp_categories": "A04, API4",
                "severity": "MEDIUM",
                "keywords": "rate limiting, dos prevention, throttling"
            }
        },
        {
            "text": "Path Traversal vulnerabilities allow attackers to access files and directories outside the intended directory structure. Attackers use sequences like '../' to navigate the file system. This can lead to reading sensitive configuration files, source code, or credentials. Prevention: validate and sanitize file paths, use whitelists, implement proper access controls. CWE-22.",
            "source": "Path_Traversal_Prevention",
            "metadata": {
                "cwe_ids": "CWE-22",
                "owasp_categories": "A03",
                "severity": "HIGH",
                "keywords": "path traversal, directory traversal, file access"
            }
        },
        {
            "text": "Authentication bypass vulnerabilities occur when security controls can be circumvented to gain unauthorized access. Common causes include logic flaws, missing checks in alternative code paths, JWT vulnerabilities, and session management issues. Prevention requires thorough testing, security code review, and defense in depth. CWE-287.",
            "source": "Authentication_Bypass_Prevention",
            "metadata": {
                "cwe_ids": "CWE-287",
                "owasp_categories": "A07",
                "severity": "CRITICAL",
                "keywords": "authentication bypass, session management"
            }
        },
        {
            "text": "Weak or default credentials pose major security risks. Many systems ship with default usernames/passwords (admin/admin, root/password) that are never changed. Weak passwords are easily cracked through brute force or dictionary attacks. Prevention: enforce strong password policies, disable default accounts, implement account lockout, use MFA. CWE-798, CWE-521.",
            "source": "Credential_Management_Guide",
            "metadata": {
                "cwe_ids": "CWE-798, CWE-521",
                "owasp_categories": "A07",
                "severity": "HIGH",
                "keywords": "weak credentials, default passwords, password policy"
            }
        },
        {
            "text": "Multi-tenancy security requires strict isolation between different tenants (customers/organizations) sharing the same application infrastructure. Vulnerabilities can allow one tenant to access another's data. Prevention requires tenant context validation on every request, proper data isolation at the database level, and comprehensive access control testing.",
            "source": "Multi_Tenancy_Security_Guide",
            "metadata": {
                "cwe_ids": "CWE-639",
                "owasp_categories": "API1",
                "severity": "HIGH",
                "keywords": "multi-tenancy, tenant isolation, data segregation"
            }
        },
        {
            "text": "API documentation accuracy is crucial for security. Outdated or incorrect documentation can lead to shadow APIs, undocumented endpoints, or misuse of functionality. Documentation should be automatically generated from code, kept in sync with implementation, and include security considerations for each endpoint. API9:2023.",
            "source": "API_Documentation_Best_Practices",
            "metadata": {
                "cwe_ids": "",
                "owasp_categories": "API9",
                "severity": "MEDIUM",
                "keywords": "api documentation, swagger, openapi"
            }
        },
        {
            "text": "Server-Side Request Forgery (SSRF) allows attackers to make the server perform requests to arbitrary locations, potentially accessing internal services, cloud metadata endpoints, or performing port scanning. Prevention: whitelist allowed destinations, disable unnecessary protocols, validate and sanitize URLs, implement network segmentation. CWE-918.",
            "source": "SSRF_Prevention_Guide",
            "metadata": {
                "cwe_ids": "CWE-918",
                "owasp_categories": "A10",
                "severity": "HIGH",
                "keywords": "ssrf, server-side request forgery, internal access"
            }
        },
        {
            "text": "Information disclosure vulnerabilities expose sensitive data through error messages, debug endpoints, verbose logs, or API responses. This can reveal system architecture, database structure, credentials, or user data. Prevention: implement proper error handling, disable debug mode in production, sanitize API responses, audit logging practices. CWE-200.",
            "source": "Information_Disclosure_Prevention",
            "metadata": {
                "cwe_ids": "CWE-200",
                "owasp_categories": "A01",
                "severity": "MEDIUM",
                "keywords": "information disclosure, data leakage, error messages"
            }
        }
    ]

    try:
        # -------------------------------------------------------------
        # Initialize RAGSystem (connects to Qdrant)
        # -------------------------------------------------------------
        print("📡 Connecting to Qdrant...")
        rag = RAGSystem()

        # -------------------------------------------------------------
        # Insert documents
        # -------------------------------------------------------------
        print(f"📚 Adding {len(documents)} documents to Qdrant...")
        rag.add_documents(documents, skip_cache_invalidation=True)

        print(f"\n✅ Successfully initialized KB with {len(documents)} documents")

        # -------------------------------------------------------------
        # Test retrieval
        # -------------------------------------------------------------
        print("\n" + "─"*70)
        print("🔍 Testing retrieval: 'SQL injection prevention'")
        print("─"*70)
        results = rag.retrieve("SQL injection prevention", severity="CRITICAL", top_k=3)
        print(f"✓ Retrieved {len(results)} documents")

        for i, doc in enumerate(results, 1):
            print(f"  {i}. {doc['source']} (score={doc['score']:.3f})")

        # -------------------------------------------------------------
        # Test retrieval 2
        # -------------------------------------------------------------
        print("\n" + "─"*70)
        print("🔍 Testing retrieval: 'BOLA authorization'")
        print("─"*70)
        results2 = rag.retrieve("BOLA authorization", severity="HIGH", top_k=3)

        for i, doc in enumerate(results2, 1):
            print(f"  {i}. {doc['source']} (score={doc['score']:.3f})")

        # -------------------------------------------------------------
        # Test retrieval 3
        # -------------------------------------------------------------
        print("\n" + "─"*70)
        print("🔍 Testing retrieval: 'JWT vulnerabilities'")
        print("─"*70)
        results3 = rag.retrieve("JWT vulnerabilities", severity="HIGH", top_k=2)

        for i, doc in enumerate(results3, 1):
            print(f"  {i}. {doc['source']} (score={doc['score']:.3f})")

        # -------------------------------------------------------------
        # Test cache
        # -------------------------------------------------------------
        print("\n" + "─"*70)
        print("🔍 Testing cache reuse...")
        print("─"*70)
        cached = rag.retrieve("SQL injection prevention", severity="CRITICAL", top_k=3)
        print(f"✓ Cache returned {len(cached)} items (should be instant)")

        stats = rag.get_cache_stats()
        print("\n📊 Cache Stats:")
        for key, value in stats.items():
            print(f"   {key}: {value}")

        print("\n" + "="*70)
        print("✅ Knowledge Base Initialization Complete!")
        print("="*70)
        print(f"\n📝 Summary:")
        print(f"   - Documents indexed: {len(documents)}")
        print(f"   - Qdrant collection: Ready")
        print(f"   - RAG cache: Active")
        print(f"   - Retrieval tests: Passed")
        print("\n🚀 You can now run orchestrator_demo.py")
        print("="*70 + "\n")

    except Exception as e:
        logger.error(f"Failed to initialize KB: {e}")
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        
        print("\n🔧 Troubleshooting:")
        print("   1. Is Qdrant running? Check: docker ps | grep qdrant")
        print("   2. Is NumPy < 2.0? Check: pip list | grep numpy")
        print("   3. Try: pip install 'numpy<2.0' --force-reinstall")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())