# rag/queries.py
"""
Query Generator for Agent Findings
Generates optimized queries from agent findings using templates.
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class QueryGenerator:
    """
    Generates RAG queries from agent findings using template-based approach.
    """
    
    @staticmethod
    def generate(agent_name: str, finding: Dict[str, Any]) -> str:
        """
        Generate optimized query based on agent and finding.
        
        Args:
            agent_name: Name of the agent
            finding: Finding dictionary
            
        Returns:
            Optimized query string
        """
        vuln = finding.get('vuln', '')
        
        if agent_name == "InputAgent":
            return QueryGenerator._input_query(vuln)
        elif agent_name == "AuthAgent":
            return QueryGenerator._auth_query(vuln)
        elif agent_name == "AccessAgent":
            return QueryGenerator._access_query(vuln)
        elif agent_name == "RateAgent":
            return QueryGenerator._rate_query(vuln)
        elif agent_name == "DocAccuracyAgent":
            return QueryGenerator._doc_query(vuln)
        else:
            return f"{vuln} security vulnerability prevention OWASP best practices"
    
    @staticmethod
    def _input_query(vuln: str) -> str:
        """Generate query for Input Agent."""
        if "SQL Injection" in vuln:
            return ("SQL injection prevention CWE-89 OWASP parameterized queries "
                   "prepared statements secure coding")
        elif "XSS" in vuln or "Cross-Site Scripting" in vuln:
            xss_type = "reflected"
            if "Stored" in vuln:
                xss_type = "stored"
            elif "DOM" in vuln:
                xss_type = "DOM-based"
            return (f"Cross-site scripting XSS prevention {xss_type} CWE-79 "
                   f"OWASP output encoding CSP")
        elif "Path Traversal" in vuln:
            return ("Path traversal prevention CWE-22 OWASP directory traversal "
                   "input validation")
        else:
            return f"Input validation security {vuln} OWASP A03 injection prevention"
    
    @staticmethod
    def _auth_query(vuln: str) -> str:
        """Generate query for Authentication Agent."""
        if "MISSING" in vuln.upper() or "Missing Authentication" in vuln:
            return ("missing authentication API security CWE-306 OWASP A07 "
                   "authentication enforcement")
        elif "BYPASS" in vuln.upper():
            return ("authentication bypass prevention OWASP A07 CWE-287 "
                   "secure authentication")
        elif "JWT" in vuln:
            if "alg" in vuln.lower() or "algorithm" in vuln.lower():
                return ("JWT algorithm none vulnerability CWE-347 JWT security "
                       "signature bypass prevention")
            else:
                return "JWT security vulnerabilities prevention CWE-347 token validation"
        elif "WEAK" in vuln.upper() or "Weak" in vuln:
            return ("weak credentials prevention default passwords OWASP A07 "
                   "CWE-798 credential management")
        else:
            return f"authentication security {vuln} OWASP A07 CWE-287 prevention"
    
    @staticmethod
    def _access_query(vuln: str) -> str:
        """Generate query for Access Agent."""
        if "BOLA" in vuln:
            return ("broken object level authorization BOLA prevention "
                   "OWASP API1:2023 CWE-639 access control")
        elif "BFLA" in vuln:
            return ("broken function level authorization BFLA prevention "
                   "OWASP API5:2023 CWE-285 role-based access control")
        elif "Tenant" in vuln or "tenant" in vuln:
            return ("multi-tenancy security tenant isolation prevention "
                   "OWASP cross-tenant access control")
        else:
            return f"authorization security {vuln} OWASP API access control"
    
    @staticmethod
    def _rate_query(vuln: str) -> str:
        """Generate query for Rate Agent."""
        if "Missing Rate Limiting" in vuln or "NO_RATE_LIMITING" in vuln:
            return ("rate limiting implementation API security OWASP A04 "
                   "CWE-770 token bucket")
        elif "Bypass" in vuln or "BYPASS" in vuln:
            return "rate limiting bypass prevention OWASP A04 header validation"
        elif "Burst" in vuln or "BURST" in vuln:
            return "burst traffic protection rate limiting OWASP A04 DoS prevention"
        elif "DoS" in vuln or "DDoS" in vuln:
            return "denial of service prevention DDoS protection OWASP A04 CWE-400"
        else:
            return f"rate limiting security {vuln} OWASP A04 CWE-770 prevention"
    
    @staticmethod
    def _doc_query(vuln: str) -> str:
        """Generate query for Documentation Agent."""
        if "Undocumented Endpoint" in vuln:
            return ("API documentation best practices OpenAPI Swagger "
                   "shadow API detection")
        elif "Non-Existent Endpoint" in vuln:
            return ("API documentation accuracy OpenAPI specification "
                   "documentation testing")
        else:
            return f"API documentation security {vuln} OpenAPI best practices"
