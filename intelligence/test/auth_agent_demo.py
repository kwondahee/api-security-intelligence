"""
AuthAgent Demo Script
Shows how to use the AuthAgent for testing API authentication security
"""

import sys
import json
from rag.agents.auth_agent import AuthAgent, APIEndpoint

def demo_with_vulnerable_api():
    """
    Demo using a deliberately vulnerable API for testing
    This uses httpbin.org which provides various HTTP testing endpoints
    """
    print("=== AuthAgent Demo with httpbin.org ===\n")
    
    # Initialize the agent
    agent = AuthAgent("https://httpbin.org")
    
    # Define test endpoints that simulate various scenarios
    test_endpoints = [
        # Test basic auth endpoint
        APIEndpoint(
            url="https://httpbin.org/basic-auth/user/passwd",
            method="GET",
            headers={}
        ),
        
        # Test endpoint with bearer token
        APIEndpoint(
            url="https://httpbin.org/bearer",
            method="GET",
            headers={"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."}
        ),
        
        # Test hidden endpoint (simulates admin endpoint)
        APIEndpoint(
            url="https://httpbin.org/hidden-basic-auth/user/passwd",
            method="GET",
            headers={}
        ),
        
        # Test endpoint with API key in URL
        APIEndpoint(
            url="https://httpbin.org/get",
            method="GET",
            parameters={"api_key": "12345", "secret": "weak_secret"}
        ),
        
        # Test endpoint with custom headers
        APIEndpoint(
            url="https://httpbin.org/headers",
            method="GET",
            headers={"X-API-Key": "weak123"}
        )
    ]
    
    all_findings = []
    
    # Analyze each endpoint
    for i, endpoint in enumerate(test_endpoints, 1):
        print(f"[{i}/{len(test_endpoints)}] Testing: {endpoint.method} {endpoint.url}")
        print("-" * 60)
        
        try:
            findings = agent.analyze_endpoint(endpoint)
            all_findings.extend(findings)
            
            if findings:
                for finding in findings:
                    print(f"🚨 {finding.severity.value}: {finding.vulnerability_type}")
                    print(f"   Description: {finding.description}")
                    print(f"   Remediation: {finding.remediation}")
                    print()
            else:
                print("✅ No authentication vulnerabilities detected for this endpoint")
                print()
        
        except Exception as e:
            print(f"❌ Error testing endpoint: {e}")
            print()
    
    # Generate final report
    print("=" * 60)
    print("FINAL SECURITY REPORT")
    print("=" * 60)
    
    report = agent.generate_report()
    
    print(f"Target: {report['target']}")
    print(f"Total Findings: {report['total_findings']}")
    print(f"Timestamp: {report['timestamp']}")
    print()
    
    if report['severity_breakdown']:
        print("Severity Breakdown:")
        for severity, count in report['severity_breakdown'].items():
            if count > 0:
                print(f"  {severity}: {count}")
        print()
    
    if report['recommendations']:
        print("Security Recommendations:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")
        print()
    
    # Save detailed report to file
    with open('auth_security_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"📄 Detailed report saved to: auth_security_report.json")
    
    return all_findings

def demo_with_custom_api():
    """
    Demo for testing your own API endpoints
    Modify the endpoints below to test your actual API
    """
    print("=== AuthAgent Demo with Custom API ===\n")
    
    # Replace with your actual API base URL
    api_base_url = input("Enter your API base URL (e.g., https://api.yoursite.com): ").strip()
    
    if not api_base_url:
        print("No URL provided, using example endpoints...")
        api_base_url = "https://jsonplaceholder.typicode.com"
    
    agent = AuthAgent(api_base_url)
    
    # Define your custom endpoints here
    custom_endpoints = [
        APIEndpoint(
            url=f"{api_base_url}/users",
            method="GET"
        ),
        APIEndpoint(
            url=f"{api_base_url}/posts/1",
            method="GET"
        )
    ]
    
    print(f"Testing {len(custom_endpoints)} endpoints...\n")
    
    for endpoint in custom_endpoints:
        print(f"Testing: {endpoint.url}")
        findings = agent.analyze_endpoint(endpoint)
        
        if findings:
            for finding in findings:
                print(f"  [{finding.severity.value}] {finding.vulnerability_type}: {finding.description}")
        else:
            print("  ✅ No issues found")
        print()
    
    # Generate report
    report = agent.generate_report()
    print("Summary:", report['summary'])

def demo_jwt_analysis():
    """
    Demo specifically for JWT token analysis
    """
    print("=== JWT Token Analysis Demo ===\n")
    
    # Examples of different JWT tokens for testing
    test_tokens = {
        "weak_jwt": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicGFzc3dvcmQiOiJzZWNyZXQxMjMiLCJpYXQiOjE1MTYyMzkwMjJ9.invalid_signature",
        "none_algorithm": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "no_expiration": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid_signature"
    }
    
    agent = AuthAgent("https://httpbin.org")
    
    for token_name, token in test_tokens.items():
        print(f"Analyzing JWT token: {token_name}")
        print(f"Token: {token[:50]}...")
        
        endpoint = APIEndpoint(
            url="https://httpbin.org/bearer",
            method="GET",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        findings = agent.analyze_endpoint(endpoint)
        
        if findings:
            for finding in findings:
                if "JWT" in finding.vulnerability_type:
                    print(f"  🔍 {finding.vulnerability_type}: {finding.description}")
        print()

def main():
    """
    Main demo function - choose which demo to run
    """
    print("AuthAgent Security Testing Demo")
    print("=" * 40)
    print("1. Test with httpbin.org (recommended for first try)")
    print("2. Test with your custom API")
    print("3. JWT token analysis demo")
    print("4. Run all demos")
    print()
    
    choice = input("Select demo (1-4): ").strip()
    
    if choice == "1":
        demo_with_vulnerable_api()
    elif choice == "2":
        demo_with_custom_api()
    elif choice == "3":
        demo_jwt_analysis()
    elif choice == "4":
        print("Running all demos...\n")
        demo_with_vulnerable_api()
        print("\n" + "="*60 + "\n")
        demo_jwt_analysis()
    else:
        print("Invalid choice. Running default demo...")
        demo_with_vulnerable_api()

if __name__ == "__main__":
    main()
