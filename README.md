# api-security-intelligence


# RAG System for API Security Intelligence Framework

## Overview

This RAG (Retrieval-Augmented Generation) system enhances security findings with context-aware recommendations from authoritative security documentation (OWASP, CWE, MITRE ATT&CK).

## Features

- **Severity-Based Caching**: Different TTL values based on finding severity (CRITICAL: no cache, HIGH: 10min, MEDIUM: 30min, LOW: 1hr)
- **Event-Driven Cache Invalidation**: Automatic cache clearing on knowledge base updates
- **Agent-Specific Query Generation**: Optimized queries for each agent type using templates
- **Simple Knowledge Base**: JSON-based document storage (no external dependencies)
- **Query Optimization**: Template-based query generation for each agent type

## Architecture

From the midterm report:

1. **Cache Layer** (`rag/cache.py`): Severity-based differential caching with event-driven invalidation
2. **Query Generator** (`rag/queries.py`): Agent-specific query templates for optimal retrieval
3. **RAG Core** (`rag/rag.py`): Document retrieval using keyword-based scoring

## Installation
```bash
# Install dependencies
pip install -r requirements.txt

# Run setup script
bash setup.sh
```

## Usage

### With Orchestrator
```python
from orchestrator import APISecurityOrchestrator

# Initialize with RAG enabled
orchestrator = APISecurityOrchestrator(
    base_url="http://localhost:5001",
    enable_rag=True
)

# Run scan
orchestrator.run_full_scan()
orchestrator.generate_report()
```

### Standalone
```python
from rag.rag import RAGSystem

rag = RAGSystem()

# Retrieve documents
results = rag.retrieve(
    query="SQL injection prevention",
    severity="CRITICAL"
)

for doc in results:
    print(doc['source'], doc['score'])
```

### With Agent Finding
```python
finding = {
    'vuln': 'SQL Injection',
    'severity': 'CRITICAL',
    'endpoint': '/api/users'
}

results = rag.retrieve(
    query=None,
    severity=finding['severity'],
    agent_name='InputAgent',
    finding=finding
)
```

## Knowledge Base

The knowledge base is stored in `rag_data/knowledge_base.json` and includes:

- SQL Injection prevention (CWE-89)
- XSS prevention (CWE-79)
- BOLA prevention (OWASP API1:2023)
- BFLA prevention (OWASP API5:2023)
- Authentication security (CWE-306, CWE-287)
- JWT security (CWE-347)
- Rate limiting (CWE-770)
- Path traversal prevention (CWE-22)
- Multi-tenancy security
- API documentation best practices

### Adding Documents
```python
from rag.rag import RAGSystem

rag = RAGSystem()

new_docs = [
    {
        "text": "Your security guidance here...",
        "source": "Your_Source_Name",
        "metadata": {
            "cwe_ids": ["CWE-123"],
            "owasp_categories": ["A03"],
            "severity": "HIGH",
            "keywords": ["keyword1", "keyword2"]
        }
    }
]

rag.add_documents(new_docs)
```

## Configuration

### Cache TTL

Edit `rag/cache.py`:
```python
self.ttl_config = {
    'CRITICAL': 0,      # No caching
    'HIGH': 600,        # 10 minutes
    'MEDIUM': 1800,     # 30 minutes
    'LOW': 3600,        # 1 hour
    'INFO': 7200        # 2 hours
}
```

### Search Configuration

Edit `rag/rag.py`:
```python
def _search_documents(self, query: str, top_k: int = 5):
    # Adjust top_k for more/fewer results
```

## Cache Behavior

From the midterm report Section 2.6.7:

| Severity | TTL | Behavior |
|----------|-----|----------|
| CRITICAL | 0s | Always fresh retrieval |
| HIGH | 10min | Recent updates |
| MEDIUM | 30min | Balanced |
| LOW | 1hr | Maximum caching |

## Performance

- **Retrieval Latency**: 5-15ms (keyword-based search)
- **Cache Hit Rate**: 30-75% (varies by usage)
- **Knowledge Base**: 12 core documents (expandable)

## File Structure
```
api-security-intelligence/
├── agents/
│   ├── access_agent.py
│   ├── auth_agent.py
│   ├── docaccuracy_agent.py
│   ├── input_agent.py
│   └── rate_agent.py
├── rag/
│   ├── __init__.py
│   ├── rag.py          # Core RAG system
│   ├── cache.py        # Severity-based caching
│   └── queries.py      # Query generation
├── rag_data/
│   └── knowledge_base.json
├── orchestrator.py
├── example_usage.py
├── setup.sh
└── requirements.txt
```

## Testing

You need **two terminal windows**:

#### Terminal 1: Start Mock Vulnerable API
```bash
cd api-security-intelligence
source venv/Scripts/activate
python mock_api.py
**Leave this running!**

#### Terminal 2: Run Security Scan
```bash
cd api-security-intelligence
source venv/Scripts/activate
python orchestrator.py
```

## Troubleshooting

### Knowledge Base Not Found

The system automatically creates a default knowledge base on first run. If you see warnings, check that `rag_data/` directory exists.

### Low Retrieval Quality

1. Add more documents to knowledge base
2. Ensure documents have proper metadata (keywords, CWE IDs)
3. Check query generation templates in `rag/queries.py`

### Cache Not Working

1. Verify severity levels match configuration
2. Check cache statistics: `rag.get_cache_stats()`
3. Review logs for cache hit/miss information

## References

- Midterm Report Section 2.2-2.6: RAG Architecture
- Midterm Report Section 2.6.7: Cache Implementation
- OWASP API Security Top 10 2023
- CWE Database
- MITRE ATT&CK Framework
