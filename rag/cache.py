# rag/cache.py
"""
Severity-Based Caching with Event-Driven Invalidation
Implements caching strategy from midterm report Section 2.6.7
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
    
    # Class-level KB version (shared across instances)
    _kb_version = None
    
    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        
        # Initialize KB version once
        if RAGCache._kb_version is None:
            RAGCache._kb_version = str(int(time.time()))
        
        self.kb_version = RAGCache._kb_version
        
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
        return RAGCache._kb_version
    
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
        """Event-driven cache invalidation - call when knowledge base is updated."""
        old_version = self.kb_version
        
        # Update the class-level version
        RAGCache._kb_version = str(int(time.time()))
        new_version = RAGCache._kb_version
        
        cache_size = len(self.cache)
        self.cache.clear()
        self.kb_version = new_version
        
        if cache_size > 0:
            logger.warning(f"KB updated: {old_version} -> {
