"""
Documentation Accuracy Agent

This agent analyzes API documentation accuracy by comparing documented behavior
with actual API responses. It can work with various documentation formats
including OpenAPI/Swagger specs, and provides detailed accuracy reports.
"""

import requests
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
from urllib.parse import urljoin, urlparse
import yaml
import xml.etree.ElementTree as ET

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DocFormat(Enum):
    OPENAPI = "openapi"
    SWAGGER = "swagger"
    RAML = "raml"
    API_BLUEPRINT = "api_blueprint"
    MARKDOWN = "markdown"
    UNKNOWN = "unknown"

@dataclass
class EndpointInfo:
    """Information about an API endpoint"""
    path: str
    method: str
    description: Optional[str] = None
    parameters: List[Dict[str, Any]] = None
    request_body: Optional[Dict[str, Any]] = None
    responses: Dict[str, Dict[str, Any]] = None
    security: List[Dict[str, Any]] = None

@dataclass
class AccuracyIssue:
    """Represents a documentation accuracy issue"""
    severity: str  # "critical", "high", "medium", "low"
    category: str  # "parameter", "response", "status_code", "security", "endpoint"
    description: str
    expected: Any
    actual: Any
    endpoint: str
    suggestion: Optional[str] = None

class DocAccuracyAgent:
    """
    Agent for checking API documentation accuracy
    """
    
    def __init__(self, base_url: str = None, timeout: int = 10):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DocAccuracyAgent/1.0',
            'Accept': 'application/json'
        })
        self.discovered_endpoints = []
        self.doc_endpoints = []
        self.accuracy_issues = []
        
    def analyze_api(self, doc_source: str, doc_format: DocFormat = DocFormat.UNKNOWN) -> Dict[str, Any]:
        """
        Main method to analyze API documentation accuracy
        
        Args:
            doc_source: Path to documentation file or URL
            doc_format: Format of the documentation
            
        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Starting API documentation accuracy analysis")
        logger.info(f"Documentation source: {doc_source}")
        logger.info(f"Documentation format: {doc_format.value}")
        
        # Step 1: Parse documentation
        self.doc_endpoints = self._parse_documentation(doc_source, doc_format)
        logger.info(f"Found {len(self.doc_endpoints)} documented endpoints")
        
        # Step 2: Discover actual API endpoints
        if self.base_url:
            self.discovered_endpoints = self._discover_endpoints()
            logger.info(f"Discovered {len(self.discovered_endpoints)} actual endpoints")
        
        # Step 3: Compare documentation vs actual behavior
        self.accuracy_issues = self._check_accuracy()
        logger.info(f"Found {len(self.accuracy_issues)} accuracy issues")
        
        # Step 4: Generate report
        report = self._generate_report()
        
        return report
    
    def _parse_documentation(self, doc_source: str, doc_format: DocFormat) -> List[EndpointInfo]:
        """Parse documentation from various formats"""
        try:
            if doc_format == DocFormat.OPENAPI or doc_format == DocFormat.SWAGGER:
                return self._parse_openapi(doc_source)
            elif doc_format == DocFormat.RAML:
                return self._parse_raml(doc_source)
            elif doc_format == DocFormat.API_BLUEPRINT:
                return self._parse_api_blueprint(doc_source)
            elif doc_format == DocFormat.MARKDOWN:
                return self._parse_markdown(doc_source)
            else:
                # Try to auto-detect format
                return self._auto_detect_and_parse(doc_source)
        except Exception as e:
            logger.error(f"Error parsing documentation: {e}")
            return []
    
    def _parse_openapi(self, doc_source: str) -> List[EndpointInfo]:
        """Parse OpenAPI/Swagger documentation"""
        endpoints = []
        
        try:
            # Load the spec
            if doc_source.startswith('http'):
                response = self.session.get(doc_source, timeout=self.timeout)
                spec = response.json()
            else:
                with open(doc_source, 'r', encoding='utf-8') as f:
                    if doc_source.endswith('.yaml') or doc_source.endswith('.yml'):
                        spec = yaml.safe_load(f)
                    else:
                        spec = json.load(f)
            
            # Extract base URL
            if 'servers' in spec and spec['servers']:
                self.base_url = spec['servers'][0]['url']
            
            # Parse paths
            for path, path_item in spec.get('paths', {}).items():
                for method, operation in path_item.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                        endpoint = EndpointInfo(
                            path=path,
                            method=method.upper(),
                            description=operation.get('description', ''),
                            parameters=operation.get('parameters', []),
                            request_body=operation.get('requestBody', {}),
                            responses=operation.get('responses', {}),
                            security=operation.get('security', [])
                        )
                        endpoints.append(endpoint)
        
        except Exception as e:
            logger.error(f"Error parsing OpenAPI spec: {e}")
        
        return endpoints
    
    def _parse_raml(self, doc_source: str) -> List[EndpointInfo]:
        """Parse RAML documentation"""
        # RAML parsing would go here
        # For now, return empty list
        logger.warning("RAML parsing not yet implemented")
        return []
    
    def _parse_api_blueprint(self, doc_source: str) -> List[EndpointInfo]:
        """Parse API Blueprint documentation"""
        # API Blueprint parsing would go here
        # For now, return empty list
        logger.warning("API Blueprint parsing not yet implemented")
        return []
    
    def _parse_markdown(self, doc_source: str) -> List[EndpointInfo]:
        """Parse Markdown documentation"""
        endpoints = []
        
        try:
            with open(doc_source, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Simple regex patterns to extract API endpoints from markdown
            # This is a basic implementation - could be enhanced
            endpoint_pattern = r'`(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s`]+)`'
            matches = re.findall(endpoint_pattern, content, re.IGNORECASE)
            
            for method, path in matches:
                endpoint = EndpointInfo(
                    path=path,
                    method=method.upper(),
                    description="Extracted from markdown"
                )
                endpoints.append(endpoint)
        
        except Exception as e:
            logger.error(f"Error parsing markdown: {e}")
        
        return endpoints
    
    def _auto_detect_and_parse(self, doc_source: str) -> List[EndpointInfo]:
        """Auto-detect documentation format and parse"""
        try:
            if doc_source.startswith('http'):
                response = self.session.get(doc_source, timeout=self.timeout)
                content = response.text
            else:
                with open(doc_source, 'r', encoding='utf-8') as f:
                    content = f.read()
            
            # Try to detect format
            if 'openapi' in content.lower() or 'swagger' in content.lower():
                return self._parse_openapi(doc_source)
            elif 'raml' in content.lower():
                return self._parse_raml(doc_source)
            elif 'api blueprint' in content.lower():
                return self._parse_api_blueprint(doc_source)
            else:
                # Try as markdown
                return self._parse_markdown(doc_source)
        
        except Exception as e:
            logger.error(f"Error in auto-detection: {e}")
            return []
    
    def _discover_endpoints(self) -> List[EndpointInfo]:
        """Discover actual API endpoints through various methods"""
        discovered = []
        
        if not self.base_url:
            logger.warning("No base URL provided for endpoint discovery")
            return discovered
        
        # Method 1: Try common API discovery endpoints
        discovery_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/swagger.json',
            '/swagger.yaml',
            '/openapi.json',
            '/openapi.yaml',
            '/.well-known/api',
            '/docs',
            '/documentation'
        ]
        
        for path in discovery_paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    # Try to parse as OpenAPI spec
                    try:
                        spec = response.json()
                        if 'paths' in spec:
                            discovered.extend(self._parse_openapi_from_dict(spec))
                    except:
                        pass
            except:
                continue
        
        # Method 2: Try to discover endpoints from documented ones
        for doc_endpoint in self.doc_endpoints:
            try:
                url = urljoin(self.base_url, doc_endpoint.path)
                response = self.session.request(
                    method=doc_endpoint.method,
                    url=url,
                    timeout=self.timeout
                )
                
                discovered.append(EndpointInfo(
                    path=doc_endpoint.path,
                    method=doc_endpoint.method,
                    description=f"Discovered via {doc_endpoint.method} request"
                ))
            except:
                continue
        
        return discovered
    
    def _parse_openapi_from_dict(self, spec: Dict[str, Any]) -> List[EndpointInfo]:
        """Parse OpenAPI spec from dictionary"""
        endpoints = []
        
        for path, path_item in spec.get('paths', {}).items():
            for method, operation in path_item.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    endpoint = EndpointInfo(
                        path=path,
                        method=method.upper(),
                        description=operation.get('description', ''),
                        parameters=operation.get('parameters', []),
                        request_body=operation.get('requestBody', {}),
                        responses=operation.get('responses', {}),
                        security=operation.get('security', [])
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _check_accuracy(self) -> List[AccuracyIssue]:
        """Check accuracy of documentation against actual API behavior"""
        issues = []
        
        # Check for undocumented endpoints
        doc_paths = {(ep.path, ep.method) for ep in self.doc_endpoints}
        discovered_paths = {(ep.path, ep.method) for ep in self.discovered_endpoints}
        
        undocumented = discovered_paths - doc_paths
        for path, method in undocumented:
            issues.append(AccuracyIssue(
                severity="medium",
                category="endpoint",
                description=f"Undocumented endpoint found: {method} {path}",
                expected="Should be documented",
                actual="Not documented",
                endpoint=f"{method} {path}",
                suggestion="Add this endpoint to your documentation"
            ))
        
        # Check for documented but non-existent endpoints
        non_existent = doc_paths - discovered_paths
        for path, method in non_existent:
            issues.append(AccuracyIssue(
                severity="high",
                category="endpoint",
                description=f"Documented endpoint not found: {method} {path}",
                expected="Endpoint should exist",
                actual="Endpoint not accessible",
                endpoint=f"{method} {path}",
                suggestion="Remove from documentation or fix endpoint implementation"
            ))
        
        # Check response accuracy for existing endpoints
        for doc_endpoint in self.doc_endpoints:
            if (doc_endpoint.path, doc_endpoint.method) in discovered_paths:
                issues.extend(self._check_endpoint_accuracy(doc_endpoint))
        
        return issues
    
    def _check_endpoint_accuracy(self, doc_endpoint: EndpointInfo) -> List[AccuracyIssue]:
        """Check accuracy for a specific endpoint"""
        issues = []
        
        try:
            url = urljoin(self.base_url, doc_endpoint.path)
            response = self.session.request(
                method=doc_endpoint.method,
                url=url,
                timeout=self.timeout
            )
            
            # Check status code accuracy
            if doc_endpoint.responses:
                expected_status_codes = set(doc_endpoint.responses.keys())
                actual_status_code = str(response.status_code)
                
                if actual_status_code not in expected_status_codes:
                    issues.append(AccuracyIssue(
                        severity="high",
                        category="status_code",
                        description=f"Unexpected status code for {doc_endpoint.method} {doc_endpoint.path}",
                        expected=f"One of: {', '.join(expected_status_codes)}",
                        actual=actual_status_code,
                        endpoint=f"{doc_endpoint.method} {doc_endpoint.path}",
                        suggestion="Update documentation to include this status code or fix the implementation"
                    ))
            
            # Check response format
            try:
                response_json = response.json()
                # Basic check for JSON response when documented
                if 'application/json' in response.headers.get('content-type', ''):
                    if not isinstance(response_json, (dict, list)):
                        issues.append(AccuracyIssue(
                            severity="medium",
                            category="response",
                            description=f"Response format mismatch for {doc_endpoint.method} {doc_endpoint.path}",
                            expected="Valid JSON object or array",
                            actual=f"Invalid JSON: {type(response_json)}",
                            endpoint=f"{doc_endpoint.method} {doc_endpoint.path}",
                            suggestion="Fix response format or update documentation"
                        ))
            except:
                # Not JSON, which might be expected
                pass
        
        except Exception as e:
            issues.append(AccuracyIssue(
                severity="critical",
                category="endpoint",
                description=f"Error testing endpoint {doc_endpoint.method} {doc_endpoint.path}",
                expected="Endpoint should be accessible",
                actual=f"Error: {str(e)}",
                endpoint=f"{doc_endpoint.method} {doc_endpoint.path}",
                suggestion="Fix endpoint implementation or network connectivity"
            ))
        
        return issues
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive accuracy report"""
        # Categorize issues by severity
        issues_by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for issue in self.accuracy_issues:
            issues_by_severity[issue.severity].append(issue)
        
        # Calculate accuracy score
        total_issues = len(self.accuracy_issues)
        total_endpoints = len(set((ep.path, ep.method) for ep in self.doc_endpoints))
        
        if total_endpoints > 0:
            accuracy_score = max(0, 100 - (total_issues * 10))  # Simple scoring
        else:
            accuracy_score = 0
        
        # Generate summary
        summary = {
            "total_documented_endpoints": len(self.doc_endpoints),
            "total_discovered_endpoints": len(self.discovered_endpoints),
            "total_issues": total_issues,
            "accuracy_score": accuracy_score,
            "issues_by_severity": {k: len(v) for k, v in issues_by_severity.items()}
        }
        
        return {
            "summary": summary,
            "issues": self.accuracy_issues,
            "documented_endpoints": [
                {
                    "path": ep.path,
                    "method": ep.method,
                    "description": ep.description
                } for ep in self.doc_endpoints
            ],
            "discovered_endpoints": [
                {
                    "path": ep.path,
                    "method": ep.method,
                    "description": ep.description
                } for ep in self.discovered_endpoints
            ]
        }
    
    def test_endpoint(self, path: str, method: str = "GET", **kwargs) -> Dict[str, Any]:
        """Test a specific endpoint and return detailed information"""
        try:
            url = urljoin(self.base_url, path)
            response = self.session.request(
                method=method.upper(),
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_type": response.headers.get('content-type', ''),
                "response_time": response.elapsed.total_seconds(),
                "content": response.text[:1000] if response.text else None,  # Truncate for safety
                "success": True
            }
        except Exception as e:
            return {
                "error": str(e),
                "success": False
            }

# Example usage and testing
if __name__ == "__main__":
    # Test with the existing testbed app
    agent = DocAccuracyAgent(base_url="http://localhost:5000")
    
    # Create a simple OpenAPI spec for testing
    test_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "servers": [
            {"url": "http://localhost:5000"}
        ],
        "paths": {
            "/api/v1/users/{user_id}": {
                "get": {
                    "summary": "Get user data",
                    "parameters": [
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "balance": {"type": "number"}
                                        }
                                    }
                                }
                            }
                        },
                        "404": {
                            "description": "User not found"
                        }
                    }
                }
            },
            "/api/v1/public/status": {
                "get": {
                    "summary": "Get API status",
                    "responses": {
                        "200": {
                            "description": "API status",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    # Save test spec to file
    with open("test_openapi.json", "w") as f:
        json.dump(test_spec, f, indent=2)
    
    # Run analysis
    print("Running documentation accuracy analysis...")
    report = agent.analyze_api("test_openapi.json", DocFormat.OPENAPI)
    
    print("\n=== DOCUMENTATION ACCURACY REPORT ===")
    print(f"Accuracy Score: {report['summary']['accuracy_score']}%")
    print(f"Total Issues: {report['summary']['total_issues']}")
    print(f"Documented Endpoints: {report['summary']['total_documented_endpoints']}")
    print(f"Discovered Endpoints: {report['summary']['total_discovered_endpoints']}")
    
    print("\n=== ISSUES BY SEVERITY ===")
    for severity, count in report['summary']['issues_by_severity'].items():
        print(f"{severity.upper()}: {count}")
    
    print("\n=== DETAILED ISSUES ===")
    for issue in report['issues']:
        print(f"\n[{issue.severity.upper()}] {issue.category.upper()}")
        print(f"Endpoint: {issue.endpoint}")
        print(f"Description: {issue.description}")
        print(f"Expected: {issue.expected}")
        print(f"Actual: {issue.actual}")
        if issue.suggestion:
            print(f"Suggestion: {issue.suggestion}")
    
    # Clean up test file
    import os
    os.remove("test_openapi.json")
