# demo.py
"""
Example usage of the RAG system
"""

import logging
from rag.rag import RAGSystem

# Configure logging
logging.basicConfig(level=logging.INFO)

def test_rag():
    """Test RAG system functionality."""
    print("=== Testing RAG System ===\n")
    
    # Initialize RAG system
    rag = RAGSystem()
    
    # Test cases
    test_cases = [
        {
            "query": "How do I prevent SQL injection?",
            "severity": "CRITICAL"
        },
        {
            "query": "BOLA vulnerability prevention",
            "severity": "HIGH"
        },
        {
            "query": "Rate limiting best practices",
            "severity": "MEDIUM"
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"Test {i}: {test['query']}")
        print(f"Severity: {test['severity']}")
        
        # Retrieve documents
        results = rag.retrieve(
            query=test['query'],
            severity=test['severity']
        )
        
        print(f"Retrieved {len(results)} documents:")
        for j, doc in enumerate(results, 1):
            print(f"  {j}. Source: {doc.get('source', 'Unknown')}")
            print(f"     Score: {doc.get('score', 0):.2f}")
            print(f"     CWEs: {doc.get('metadata', {}).get('cwe_ids', [])}")
            print(f"     Preview: {doc.get('text', '')[:80]}...")
        print()
    
    # Cache statistics
    print("=== Cache Statistics ===")
    stats = rag.get_cache_stats()
    print(f"Total cache entries: {stats.get('total_entries', 0)}")
    print(f"Severity distribution: {stats.get('severity_distribution', {})}")

def test_agent_integration():
    """Test RAG integration with agent findings."""
    print("\n=== Testing Agent Integration ===\n")
    
    rag = RAGSystem()
    
    # Simulate agent finding
    finding = {
        'vuln': 'SQL Injection',
        'severity': 'CRITICAL',
        'endpoint': '/api/search',
        'method': 'GET'
    }
    
    print(f"Agent Finding: {finding['vuln']}")
    print(f"Severity: {finding['severity']}")
    
    # Retrieve with agent context
    results = rag.retrieve(
        query=None,
        severity=finding['severity'],
        agent_name='InputAgent',
        finding=finding
    )
    
    print(f"\nRetrieved {len(results)} documents for guidance:")
    for doc in results:
        print(f"  - {doc.get('source', 'Unknown')} (score: {doc.get('score', 0):.2f})")

if __name__ == "__main__":
    test_rag()
    test_agent_integration()
    print("\n✓ RAG system tests completed")
