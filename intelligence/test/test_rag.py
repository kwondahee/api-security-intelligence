# test_rag.py
"""
Test LangChain RAG with Milvus and Foundation-Sec-8B
"""

import logging
from intelligence.llm import RAGSystem
from intelligence.llm.llm import FoundationSecLLM

logging.basicConfig(level=logging.INFO)

def test_rag():
    """Test RAG retrieval."""
    print("=== Testing RAG with LangChain + Milvus ===\n")
    
    rag = RAGSystem()
    
    queries = [
        "How to prevent SQL injection?",
        "JWT security best practices",
        "BOLA vulnerability prevention"
    ]
    
    for query in queries:
        print(f"Query: {query}")
        results = rag.retrieve(query, severity="HIGH", top_k=3)
        
        print(f"Retrieved {len(results)} documents:")
        for i, doc in enumerate(results, 1):
            print(f"  {i}. {doc['source']} (score: {doc['score']:.3f})")
        print()

def test_llm():
    """Test Foundation-Sec-8B LLM routing."""
    print("\n=== Testing Foundation-Sec-8B LLM ===\n")
    
    llm = FoundationSecLLM()
    
    # Test payload
    payload = {
        "method": "POST",
        "endpoint": "/api/login",
        "payload": {"username": "admin' OR '1'='1", "password": "test"},
        "headers": {"Content-Type": "application/json"}
    }
    
    print("API Payload:")
    print(f"  Method: {payload['method']}")
    print(f"  Endpoint: {payload['endpoint']}")
    print(f"  Payload: {payload['payload']}")
    
    agent = llm.route_to_agent(payload)
    print(f"\nLLM routed to: {agent}")

if __name__ == "__main__":
    # Test RAG
    test_rag()
    
    # Test LLM (optional - requires GPU)
    # test_llm()
