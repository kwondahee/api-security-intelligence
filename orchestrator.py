#!/usr/bin/env python3
"""
API Security Intelligence Orchestrator with LangChain RAG + Foundation-Sec-8B
"""

# Force UTF-8 encoding for Windows
import sys
import io
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

import json
import logging
import time
from datetime import datetime
from typing import List, Dict, Any

# Import Agent Modules
from agents.docaccuracy_agent import DocAccuracyAgent
from agents.input_agent import InputAgent
from agents.rate_agent import RateAgent
from agents.auth_agent import AuthAgent 
from agents.access_agent import AccessAgent

# Import RAG System with LangChain
from rag.rag import RAGSystem
from rag.llm import FoundationSecLLM

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
    """
    Multi-Agent Security Orchestrator with RAG Enhancement.
    
    Coordinates security agents and enhances findings with RAG-retrieved
    security knowledge from LangChain + Milvus vector database.
    """
    
    def __init__(
        self, 
        base_url: str, 
        enable_rag: bool = True,
        enable_llm_routing: bool = False
    ):
        """
        Initialize orchestrator with all agents and RAG system.
        
        Args:
            base_url: Target API base URL
            enable_rag: Enable RAG enhancement (default: True)
            enable_llm_routing: Enable Foundation-Sec-8B LLM routing (default: False)
        """
        self.base_url = base_url
        self.all_findings: List[Dict[str, Any]] = []
        self.enable_rag = enable_rag
        self.enable_llm_routing = enable_llm_routing
        self.scan_start_time = None

        # Initialize RAG System (LangChain + Milvus)
        if self.enable_rag:
            try:
                logger.info("Initializing LangChain RAG System with Milvus...")
                self.rag = RAGSystem()
                logger.info("RAG System initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize RAG: {e}")
                logger.warning("Continuing without RAG enhancement")
                self.enable_rag = False
                self.rag = None
        else:
            self.rag = None

        # Initialize Foundation-Sec-8B LLM (optional)
        if self.enable_llm_routing:
            try:
                logger.info("Initializing Foundation-Sec-8B LLM...")
                self.llm = FoundationSecLLM()
                logger.info("LLM initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize LLM: {e}")
                logger.warning("Continuing without LLM routing")
                self.enable_llm_routing = False
                self.llm = None
        else:
            self.llm = None

        # Initialize Agents
        logger.info(f"Initializing security agents for target: {self.base_url}")
        self.docs_agent = DocAccuracyAgent(base_url=self.base_url)
        self.input_agent = InputAgent(target_base_url=self.base_url)
        self.rate_agent = RateAgent(target_base_url=self.base_url)
        self.auth_agent = AuthAgent(target_base_url=self.base_url)
        self.access_agent = AccessAgent(target_base_url=self.base_url)

        logger.info(f"Orchestrator initialized for target: {self.base_url}")

    def _enrich_with_rag(self, finding: Dict[str, Any], agent_name: str) -> Dict[str, Any]:
        """
        Enrich finding with RAG-retrieved context using LangChain + Milvus.
        
        Args:
            finding: Security finding from agent
            agent_name: Name of the agent that generated the finding
            
        Returns:
            Enhanced finding with RAG context
        """
        if not self.enable_rag or not self.rag:
            finding['rag_enhanced'] = False
            return finding
        
        try:
            severity = finding.get('severity', 'MEDIUM')
            
            # Retrieve relevant documentation using LangChain
            docs = self.rag.retrieve(
                query=None,
                severity=severity,
                agent_name=agent_name,
                finding=finding,
                top_k=5
            )
            
            if docs:
                # Add RAG context (top 3 documents)
                rag_contexts = []
                for doc in docs[:3]:
                    context = {
                        'text_snippet': doc.get('text', '')[:200],
                        'source': doc.get('source', 'Unknown'),
                        'cwe_ids': doc.get('metadata', {}).get('cwe_ids', ''),
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
        """
        Build enhanced recommendation using RAG documents.
        
        Args:
            original: Original recommendation from agent
            docs: RAG-retrieved documents
            
        Returns:
            Enhanced recommendation with RAG context
        """
        enhanced = f"{original}\n\n**Additional Guidance from Security Standards:**\n"
        
        for i, doc in enumerate(docs[:2], 1):
            metadata = doc.get('metadata', {})
            source = doc.get('source', 'Security Documentation')
            cwe_ids = metadata.get('cwe_ids', '')
            
            if cwe_ids:
                enhanced += f"\n{i}. From {source} ({cwe_ids}):\n"
            else:
                enhanced += f"\n{i}. From {source}:\n"
            
            text = doc.get('text', '')
            excerpt = text[:250].strip()
            if len(text) > 250:
                excerpt += "..."
            enhanced += f"   {excerpt}\n"
        
        return enhanced

    def run_full_scan(self):
        """Execute full security scan with LangChain RAG enhancement."""
        self.scan_start_time = time.time()
        
        print("=" * 70)
        print(f"[ORCHESTRATOR] Multi-Agent Security Orchestrator")
        print(f"Target: {self.base_url}")
        print(f"RAG Enhancement: {'Enabled (LangChain + Milvus)' if self.enable_rag else 'Disabled'}")
        print(f"LLM Routing: {'Enabled (Foundation-Sec-8B)' if self.enable_llm_routing else 'Disabled'}")
        print("=" * 70)

        # --- PHASE 1: Documentation Accuracy ---
        print("\n--- PHASE 1: Documentation Accuracy (DocAccuracyAgent) ---")
        phase_start = time.time()
        
        docs_findings = self.docs_agent.run_check(doc_source=TARGET_ENDPOINT_DOCS)
        
        for finding in docs_findings:
            enriched = self._enrich_with_rag(finding, "DocAccuracyAgent")
            self.all_findings.append(enriched)
        
        phase_duration = time.time() - phase_start
        print(f"[PHASE 1 COMPLETE] Found {len(docs_findings)} documentation issues ({phase_duration:.1f}s)")

        # --- PHASE 2: Input Validation ---
        print("\n--- PHASE 2: Input Validation (InputAgent) ---")
        phase_start = time.time()
        
        input_findings = self.input_agent.run_scan(
            endpoint_path=TARGET_ENDPOINT_SQLI, 
            parameter=TARGET_PARAM_SQLI, 
            method="GET"
        )
        
        for finding in input_findings:
            enriched = self._enrich_with_rag(finding, "InputAgent")
            self.all_findings.append(enriched)
        
        phase_duration = time.time() - phase_start
        print(f"[PHASE 2 COMPLETE] Found {len(input_findings)} input validation issues ({phase_duration:.1f}s)")

        # --- PHASE 3: Rate Limiting ---
        print("\n--- PHASE 3: Rate Limiting (RateAgent) ---")
        print("[INFO] This phase tests rate limiting (may take 15-30 seconds)...")
        phase_start = time.time()
        
        rate_findings = self.rate_agent.run_scan(
            endpoint_path=TARGET_ENDPOINT_RATE,
            method="GET"
        )
        
        for finding in rate_findings:
            enriched = self._enrich_with_rag(finding, "RateAgent")
            self.all_findings.append(enriched)
        
        phase_duration = time.time() - phase_start
        print(f"[PHASE 3 COMPLETE] Found {len(rate_findings)} rate limiting issues ({phase_duration:.1f}s)")

        # --- PHASE 4: Authentication ---
        print("\n--- PHASE 4: Authentication (AuthAgent) ---")
        phase_start = time.time()
        
        auth_findings = self.auth_agent.run_scan(
            endpoint_url=TARGET_ENDPOINT_AUTH,
            endpoint_method="GET"
        )
        
        for finding in auth_findings:
            enriched = self._enrich_with_rag(finding, "AuthAgent")
            self.all_findings.append(enriched)
        
        phase_duration = time.time() - phase_start
        print(f"[PHASE 4 COMPLETE] Found {len(auth_findings)} authentication issues ({phase_duration:.1f}s)")

        # --- PHASE 5: Authorization ---
        print("\n--- PHASE 5: Authorization (AccessAgent) ---")
        phase_start = time.time()
        
        access_findings = self.access_agent.run_scan(
            target_resource=TARGET_ENDPOINT_RATE.replace('1', '2')
        )
        
        for finding in access_findings:
            enriched = self._enrich_with_rag(finding, "AccessAgent")
            self.all_findings.append(enriched)
        
        phase_duration = time.time() - phase_start
        print(f"[PHASE 5 COMPLETE] Found {len(access_findings)} authorization issues ({phase_duration:.1f}s)")
        
        total_duration = time.time() - self.scan_start_time
        print("\n" + "=" * 70)
        print(f"[SCAN COMPLETE] Total time: {total_duration:.1f}s")
        print("Generating report...")
        print("=" * 70)

    def generate_report(self):
        """Generate comprehensive security report with RAG enhancements."""
        if not self.all_findings:
            print("\n--- SCAN COMPLETE ---")
            print("No security findings were reported.")
            return

        print("\n" + "=" * 70)
        print("                   FINAL SECURITY REPORT                          ")
        print("=" * 70)
        print(f"Target: {self.base_url}")
        print(f"Total Findings: {len(self.all_findings)}")
        print(f"RAG Enhancement: {'Enabled (LangChain + Milvus)' if self.enable_rag else 'Disabled'}")
        print(f"LLM Routing: {'Enabled (Foundation-Sec-8B)' if self.enable_llm_routing else 'Disabled'}")
        print(f"Scan Time: {datetime.now().isoformat()}")
        
        if self.scan_start_time:
            total_duration = time.time() - self.scan_start_time
            print(f"Duration: {total_duration:.1f}s")
        
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
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  - {severity:<10}: {count}")
        
        if self.enable_rag:
            print(f"\nRAG-Enhanced Findings: {rag_enhanced_count}/{len(self.all_findings)}")
            
            if self.rag:
                cache_stats = self.rag.get_cache_stats()
                print(f"Cache Statistics:")
                print(f"  - Total entries: {cache_stats.get('total_entries', 0)}")
                print(f"  - KB version: {cache_stats.get('kb_version', 'unknown')}")
        
        print("-" * 70)
        print("Detailed Findings:")

        for i, finding in enumerate(self.all_findings, 1):
            print(f"\n[{i}/{len(self.all_findings)}] {finding.get('vuln', 'Unknown Vulnerability')}")
            print(f"  Agent   : {finding.get('agent', 'N/A')}")
            print(f"  Endpoint: {finding.get('method', 'N/A')} {finding.get('endpoint', 'N/A')}")
            print(f"  Severity: {finding.get('severity', 'N/A')}")
            print(f"  Status  : {finding.get('status', 'N/A')}")
            
            # Show RAG enhancement info
            if finding.get('rag_enhanced'):
                rag_contexts = finding.get('rag_context', [])
                if rag_contexts:
                    print(f"  RAG Sources: {len(rag_contexts)} documents (Milvus + BGE-Large)")
                    for ctx in rag_contexts:
                        source = ctx.get('source', 'Unknown')
                        score = ctx.get('score', 0)
                        cwe = ctx.get('cwe_ids', '')
                        if cwe:
                            print(f"    - {source} ({cwe}) [similarity: {score:.3f}]")
                        else:
                            print(f"    - {source} [similarity: {score:.3f}]")
            
            # Show details if available
            details = finding.get('details', '')
            if details:
                print(f"  Details: {details[:150]}{'...' if len(details) > 150 else ''}")
            
            # Show recommendation (truncated)
            recommendation = finding.get('recommendation', 'N/A')
            rec_preview = recommendation.split('\n')[0][:200]
            print(f"  Recommendation: {rec_preview}...")
        
        # Save to file
        self._save_report()
    
    def _save_report(self):
        """Save detailed report to JSON file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = f"security_report_{timestamp}.json"
        
        report_data = {
            'scan_metadata': {
                'target': self.base_url,
                'timestamp': datetime.now().isoformat(),
                'rag_enabled': self.enable_rag,
                'rag_type': 'LangChain + Milvus + BGE-Large-en-v1.5' if self.enable_rag else None,
                'llm_routing_enabled': self.enable_llm_routing,
                'llm_model': 'Foundation-Sec-8B-Instruct' if self.enable_llm_routing else None,
                'total_findings': len(self.all_findings),
                'duration_seconds': time.time() - self.scan_start_time if self.scan_start_time else None
            },
            'findings': self.all_findings
        }
        
        if self.enable_rag and self.rag:
            report_data['cache_stats'] = self.rag.get_cache_stats()
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n[REPORT] Detailed report saved to: {report_path}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")


def main():
    """Main entry point for orchestrator."""
    print("\n" + "=" * 70)
    print("[ORCHESTRATOR] Starting API Security Intelligence Framework")
    print("=" * 70)
    
    orchestrator = APISecurityOrchestrator(
        TARGET_BASE_URL, 
        enable_rag=True,
        enable_llm_routing=False  # Set to True to enable Foundation-Sec-8B routing
    )
    
    try:
        orchestrator.run_full_scan()
        orchestrator.generate_report()
        
        print("\n" + "=" * 70)
        print("[SUCCESS] Security scan completed successfully!")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Scan interrupted by user")
        print("Generating partial report...")
        orchestrator.generate_report()
        
    except Exception as e:
        print(f"\n[ERROR] Orchestrator critical error: {e}")
        logger.exception("Orchestrator error:")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
