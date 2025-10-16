#!/usr/bin/env python3
"""
API Security Intelligence Orchestrator with RAG Integration
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any

# Import Agent Modules
from agents.docaccuracy_agent import DocAccuracyAgent
from agents.input_agent import InputAgent
from agents.rate_agent import RateAgent
from agents.auth_agent import AuthAgent 
from agents.access_agent import AccessAgent

# Import RAG System
from rag.rag import RAGSystem

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
TARGET_BASE_URL = "http://localhost:5001"
TARGET_ENDPOINT_DOCS = "/openapi.json"
TARGET_ENDPOINT_SQLI = "/books/v1/search"
TARGET_PARAM_SQLI = "book_title"
TARGET_ENDPOINT_RATE = "/users/v1/profile/1"
TARGET_ENDPOINT_AUTH = "/admin/users"

class APISecurityOrchestrator:
    def __init__(self, base_url: str, enable_rag: bool = True):
        self.base_url = base_url
        self.all_findings: List[Dict[str, Any]] = []
        self.enable_rag = enable_rag

        # Initialize RAG System
        if self.enable_rag:
            try:
                logger.info("Initializing RAG System...")
                self.rag = RAGSystem()
                logger.info("RAG System initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize RAG: {e}")
                logger.warning("Continuing without RAG enhancement")
                self.enable_rag = False
                self.rag = None
        else:
            self.rag = None

        # Initialize Agents
        self.docs_agent = DocAccuracyAgent(base_url=self.base_url)
        self.input_agent = InputAgent(target_base_url=self.base_url)
        self.rate_agent = RateAgent(target_base_url=self.base_url)
        self.auth_agent = AuthAgent(target_base_url=self.base_url)
        self.access_agent = AccessAgent(target_base_url=self.base_url)

        logger.info(f"Orchestrator initialized for target: {self.base_url}")

    def _enrich_with_rag(self, finding: Dict[str, Any], agent_name: str) -> Dict[str, Any]:
        """Enrich finding with RAG-retrieved context."""
        if not self.enable_rag or not self.rag:
            return finding
        
        try:
            severity = finding.get('severity', 'MEDIUM')
            
            # Retrieve relevant documentation
            docs = self.rag.retrieve(
                query=None,
                severity=severity,
                agent_name=agent_name,
                finding=finding
            )
            
            if docs:
                # Add RAG context
                rag_contexts = []
                for doc in docs[:3]:
                    context = {
                        'text_snippet': doc.get('text', '')[:200],
                        'source': doc.get('source', 'Unknown'),
                        'cwe_ids': doc.get('metadata', {}).get('cwe_ids', []),
                        'score': doc.get('score', 0)
                    }
                    rag_contexts.append(context)
                
                finding['rag_context'] = rag_contexts
                
                # Enhance recommendation
                original_rec = finding.get('recommendation', '')
                enhanced_rec = self._build_recommendation(original_rec, docs)
                finding['recommendation'] = enhanced_rec
                finding['rag_enhanced'] = True
                
                logger.debug(f"Enhanced finding with {len(docs)} RAG documents")
            else:
                finding['rag_enhanced'] = False
        
        except Exception as e:
            logger.error(f"Failed to enrich with RAG: {e}")
            finding['rag_enhanced'] = False
        
        return finding
    
    def _build_recommendation(self, original: str, docs: List[Dict[str, Any]]) -> str:
        """Build enhanced recommendation using RAG documents."""
        enhanced = f"{original}\n\n**Additional Guidance:**\n"
        
        for i, doc in enumerate(docs[:2], 1):
            metadata = doc.get('metadata', {})
            source = doc.get('source', 'Security Documentation')
            cwe_ids = metadata.get('cwe_ids', [])
            
            if cwe_ids:
                cwe_str = ', '.join(cwe_ids)
                enhanced += f"\n{i}. From {source} ({cwe_str}):\n"
            else:
                enhanced += f"\n{i}. From {source}:\n"
            
            text = doc.get('text', '')
            excerpt = text[:250].strip()
            if len(text) > 250:
                excerpt += "..."
            enhanced += f"   {excerpt}\n"
        
        return enhanced

    def run_full_scan(self):
        """Execute full security scan with RAG enhancement."""
        print("=" * 70)
        print(f"🛡️  Multi-Agent Security Orchestrator")
        print(f"Target: {self.base_url}")
        print(f"RAG Enhancement: {'Enabled' if self.enable_rag else 'Disabled'}")
        print("=" * 70)

        # --- PHASE 1: Documentation Accuracy ---
        print("\n--- PHASE 1: Documentation Accuracy (DocAccuracyAgent) ---")
        docs_findings = self.docs_agent.run_check(doc_source=TARGET_ENDPOINT_DOCS)
        
        for finding in docs_findings:
            enriched = self._enrich_with_rag(finding, "DocAccuracyAgent")
            self.all_findings.append(enriched)

        # --- PHASE 2: Input Validation ---
        print("\n--- PHASE 2: Input Validation (InputAgent) ---")
        input_findings = self.input_agent.run_scan(
            endpoint_path=TARGET_ENDPOINT_SQLI, 
            parameter=TARGET_PARAM_SQLI, 
            method="GET"
        )
        
        for finding in input_findings:
            enriched = self._enrich_with_rag(finding, "InputAgent")
            self.all_findings.append(enriched)

        # --- PHASE 3: Rate Limiting ---
        print("\n--- PHASE 3: Rate Limiting (RateAgent) ---")
        rate_findings = self.rate_agent.run_scan(
            endpoint_path=TARGET_ENDPOINT_RATE,
            method="GET"
        )
        
        for finding in rate_findings:
            enriched = self._enrich_with_rag(finding, "RateAgent")
            self.all_findings.append(enriched)

        # --- PHASE 4: Authentication ---
        print("\n--- PHASE 4: Authentication (AuthAgent) ---")
        auth_findings = self.auth_agent.run_scan(
            endpoint_url=TARGET_ENDPOINT_AUTH,
            endpoint_method="GET"
        )
        
        for finding in auth_findings:
            enriched = self._enrich_with_rag(finding, "AuthAgent")
            self.all_findings.append(enriched)

        # --- PHASE 5: Authorization ---
        print("\n--- PHASE 5: Authorization (AccessAgent) ---")
        access_findings = self.access_agent.run_scan(
            target_resource=TARGET_ENDPOINT_RATE.replace('1', '2')
        )
        
        for finding in access_findings:
            enriched = self._enrich_with_rag(finding, "AccessAgent")
            self.all_findings.append(enriched)

    def generate_report(self):
        """Generate comprehensive security report."""
        if not self.all_findings:
            print("\n--- SCAN COMPLETE ---")
            print("No security findings were reported.")
            return

        print("\n" + "=" * 70)
        print("                   FINAL SECURITY REPORT                          ")
        print("=" * 70)
        print(f"Total Findings: {len(self.all_findings)}")
        print(f"RAG Enhancement: {'Enabled' if self.enable_rag else 'Disabled'}")
        print(f"Scan Time: {datetime.now().isoformat()}")
        print("-" * 70)
        
        # Severity breakdown
        severity_counts = {}
        rag_enhanced_count = 0
        
        for finding in self.all_findings:
            severity = finding.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if finding.get('rag_enhanced'):
                rag_enhanced_count += 1
        
        print("Severity Breakdown:")
        for severity, count in sorted(severity_counts.items(), reverse=True):
            print(f"  - {severity:<10}: {count}")
        
        if self.enable_rag:
            print(f"\nRAG-Enhanced Findings: {rag_enhanced_count}/{len(self.all_findings)}")
            
            if self.rag:
                cache_stats = self.rag.get_cache_stats()
                print(f"Cache Entries: {cache_stats.get('total_entries', 0)}")
        
        print("-" * 70)
        print("Detailed Findings:")

        for i, finding in enumerate(self.all_findings, 1):
            print(f"\n[{i}/{len(self.all_findings)}] {finding.get('vuln', 'Unknown')}")
            print(f"  Agent   : {finding.get('agent', 'N/A')}")
            print(f"  Endpoint: {finding.get('method', 'N/A')} {finding.get('endpoint', 'N/A')}")
            print(f"  Severity: {finding.get('severity', 'N/A')}")
            print(f"  Status  : {finding.get('status', 'N/A')}")
            
            if finding.get('rag_enhanced'):
                rag_contexts = finding.get('rag_context', [])
                if rag_contexts:
                    print(f"  RAG Sources: {len(rag_contexts)} documents")
                    for ctx in rag_contexts:
                        source = ctx.get('source', 'Unknown')
                        score = ctx.get('score', 0)
                        print(f"    - {source} (score: {score:.2f})")
            
            recommendation = finding.get('recommendation', 'N/A')
            print(f"  Recommend: {recommendation[:150]}...")
        
        # Save to file
        self._save_report()
    
    def _save_report(self):
        """Save detailed report to JSON file."""
        report_path = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report_data = {
            'scan_metadata': {
                'target': self.base_url,
                'timestamp': datetime.now().isoformat(),
                'rag_enabled': self.enable_rag,
                'total_findings': len(self.all_findings)
            },
            'findings': self.all_findings
        }
        
        if self.enable_rag and self.rag:
            report_data['cache_stats'] = self.rag.get_cache_stats()
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n📄 Detailed report saved to: {report_path}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")


if __name__ == "__main__":
    orchestrator = APISecurityOrchestrator(TARGET_BASE_URL, enable_rag=True)
    
    try:
        orchestrator.run_full_scan()
        orchestrator.generate_report()
    except Exception as e:
        print(f"\n!!! ORCHESTRATOR CRITICAL ERROR !!!")
        print(f"Error: {e}")
        logger.exception("Orchestrator error:")
