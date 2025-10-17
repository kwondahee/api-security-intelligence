# initialize_kb.py
"""
Initialize Milvus knowledge base with security documents
"""

import logging
import json
from rag.rag import RAGSystem

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """Initialize knowledge base with default security documents."""
    
    print("=== Initializing Knowledge Base ===")
    
    # Default security documents
    # NOTE: Metadata must be flat (strings, numbers, booleans only)
    # Lists and nested objects are converted to JSON strings
    documents = [
        {
            "text": "SQL Injection is a code injection technique that exploits security vulnerabilities in an application's database layer. To prevent SQL injection attacks, always use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries. Implement input validation and use stored procedures where appropriate. CWE-89 classifies this vulnerability. OWASP ranks it under A03:2021 Injection.",
            "source": "OWASP_SQL_Injection_Prevention",
            "metadata": {
                "cwe_ids": "CWE-89",  # Convert list to string
                "owasp_categories": "A03",  # Convert list to string
                "severity": "CRITICAL",
                "keywords": "sql injection, parameterized queries, prepared statements"  # Convert list to string
            }
        },
        {
            "text": "Cross-Site Scripting (XSS) attacks occur when an application includes untrusted data in a web page without proper validation or escaping. To prevent XSS, implement output encoding based on context (HTML, JavaScript, URL, CSS). Use Content Security Policy (CSP) headers to restrict script execution. Validate and sanitize all user inputs. CWE-79 defines this vulnerability class.",
            "source": "OWASP_XSS_Prevention",
            "metadata": {
                "cwe_ids": "CWE-79",
                "owasp_categories": "A03",
                "severity": "HIGH",
                "keywords": "xss, cross-site scripting, output encoding, csp"
            }
        },
        {
            "text": "Broken Object Level Authorization (BOLA) occurs when an application does not properly verify that a user is authorized to access a specific object. Always implement authorization checks at the object level. Verify that the authenticated user has permission to perform the requested action on the specific resource. Use user IDs from trusted sessions rather than request parameters. OWASP API Security Top 10 2023 ranks this as API1:2023.",
            "source": "OWASP_API_Security_BOLA",
            "metadata": {
                "cwe_ids": "CWE-639",
                "owasp_categories": "API1",
                "severity": "CRITICAL",
                "keywords": "bola, broken object level authorization, access control"
            }
        },
        {
            "text": "Broken Function Level Authorization (BFLA) allows attackers to access functions they shouldn't have permission to use. Implement proper role-based access control (RBAC). Verify user permissions before executing any privileged operations. Deny access by default and explicitly grant permissions. Administrative functions should have additional authentication layers. OWASP API5:2023 addresses this vulnerability.",
            "source": "OWASP_API_Security_BFLA",
            "metadata": {
                "cwe_ids": "CWE-285",
                "owasp_categories": "API5",
                "severity": "CRITICAL",
                "keywords": "bfla, broken function level authorization, rbac"
            }
        },
        {
            "text": "Missing Authentication vulnerabilities occur when sensitive API endpoints are accessible without any authentication. All endpoints that access sensitive data or perform privileged operations must require authentication. Implement authentication middleware that validates credentials before processing requests. Return 401 Unauthorized for unauthenticated requests. CWE-306 describes this weakness.",
            "source": "OWASP_Authentication_Guide",
            "metadata": {
                "cwe_ids": "CWE-306",
                "owasp_categories": "A07",
                "severity": "CRITICAL",
                "keywords": "missing authentication, authentication enforcement"
            }
        },
        {
            "text": "JWT (JSON Web Token) security requires careful implementation. Never accept tokens with 'alg: none'. Always validate the signature using a strong secret key (minimum 256 bits). Implement token expiration and refresh mechanisms. Store JWTs securely and never in localStorage for sensitive applications. Validate all claims and check token revocation. CWE-347 covers improper verification of cryptographic signatures.",
            "source": "JWT_Security_Best_Practices",
            "metadata": {
                "cwe_ids": "CWE-347",
                "owasp_categories": "A07",
                "severity": "HIGH",
                "keywords": "jwt, json web token, signature validation"
            }
        },
        {
            "text": "Rate limiting is essential for preventing abuse and ensuring API ava
