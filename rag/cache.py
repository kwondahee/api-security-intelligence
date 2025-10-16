# rag/cache.py
"""
Severity-Based Caching with Event-Driven Invalidation
"""

import time
import hashlib
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class RAGCache:
    """
    Implements severity-based differential caching.
    Different TTL values based on finding severity.
    """
    
    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.kb_version = self._get_kb_version()
        
        # TTL configuration (seconds)
        self.ttl_config = {
            'CRITICAL': 0,      # No caching
            'HIGH': 600,        # 10 minutes
            'MEDIUM': 1800,     # 30 minutes
            'LOW': 3600,        # 1 hour
            'INFO': 7200        # 2 hours
        }
        
        logger.info(f"Cache initialized with KB version: {self.kb_version}")
    
    def _get_kb_version(self) -> str:
        """Get current knowledge base version."""
        return str(int(time.time()))
    
    def _generate_key(self, query: str) -> str:
        """Generate cache key from query."""
        normalized = query.lower().strip()
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def get(self, query: str, severity: str = 'MEDIUM') -> Optional[List[Dict[str, Any]]]:
        """
        Retrieve cached results with severity-aware TTL.
        
        Args:
            query: Search query
            severity: Finding severity level
            
        Returns:
            Cached documents if valid, None otherwise
        """
        # Check 1: KB version changed (event-driven invalidation)
        current_version = self._get_kb_version()
        if current_version != self.kb_version:
            self.on_kb_update()
            return None
        
        # Check 2: CRITICAL bypasses cache
        if severity == 'CRITICAL':
            return None
        
        # Check 3: Cache lookup
        cache_key = self._generate_key(query)
        
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            ttl = self.ttl_config.get(severity, 3600)
            age = time.time() - entry['timestamp']
            
            if age < ttl:
                logger.debug(f"Cache HIT: {query[:50]}... (age: {age:.1f}s)")
                return entry['documents']
            else:
                del self.cache[cache_key]
        
        logger.debug(f"Cache MISS: {query[:50]}...")
        return None
    
    def set(self, query: str, documents: List[Dict[str, Any]], severity: str = 'MEDIUM'):
        """Store query results in cache."""
        if severity == 'CRITICAL':
            return
        
        cache_key = self._generate_key(query)
        self.cache[cache_key] = {
            'documents': documents,
            'timestamp': time.time(),
            'severity': severity
        }
    
    def on_kb_update(self):
        """Event-driven cache invalidation."""
        old_version = self.kb_version
        new_version = self._get_kb_version()
        
        if old_version != new_version:
            cache_size = len(self.cache)
            self.cache.clear()
            self.kb_version = new_version
            logger.warning(f"KB updated: {old_version} -> {new_version}. "
                         f"Invalidated {cache_size} entries.")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        severity_counts = {}
        for entry in self.cache.values():
            sev = entry['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            'total_entries': len(self.cache),
            'kb_version': self.kb_version,
            'severity_distribution': severity_counts
        }
