#!/usr/bin/env python3
"""
Simple test script to verify the DocAccuracy Agent works with your API
"""

import sys
import os
import json

# Add the agents directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'agents'))

from docaccuracy_agent import DocAccuracyAgent, DocFormat

def test_with_your_api(api_base_url="https://your-api.com", doc_file="your_api_spec.json", doc_format=DocFormat.OPENAPI):
    """Test the agent with your own API"""
    
    print("🔧 Testing DocAccuracy Agent with Your API")
    print("=" * 50)
    
    # Configuration - MODIFY THESE VALUES
    API_BASE_URL = api_base_url
    DOC_FILE = doc_file
    DOC_FORMAT = doc_format
    
    print(f"API Base URL: {API_BASE_URL}")
    print(f"Documentation File: {DOC_FILE}")
    print(f"Documentation Format: {DOC_FORMAT.value}")
    print()
    
    # Create agent
    agent = DocAccuracyAgent(base_url=API_BASE_URL)
    
    try:
        # Test 1: Parse documentation only
        print("1️⃣ Testing documentation parsing...")
        if os.path.exists(DOC_FILE):
            endpoints = agent._parse_documentation(DOC_FILE, DOC_FORMAT)
            print(f"   ✅ Successfully parsed {len(endpoints)} endpoints")
            for ep in endpoints[:3]:  # Show first 3
                print(f"      • {ep.method} {ep.path}")
            if len(endpoints) > 3:
                print(f"      ... and {len(endpoints) - 3} more")
        else:
            print(f"   ❌ Documentation file '{DOC_FILE}' not found")
            print("   💡 Create a sample OpenAPI spec or point to your existing docs")
        
        print()
        
        # Test 2: Test individual endpoint
        print("2️⃣ Testing individual endpoint...")
        test_endpoint = "/api/v1/status"  # Change this to a known endpoint
        result = agent.test_endpoint(test_endpoint, "GET")
        
        if result['success']:
            print(f"   ✅ {test_endpoint} is accessible")
            print(f"      Status: {result['status_code']}")
            print(f"      Response Time: {result['response_time']:.3f}s")
            print(f"      Content Type: {result['content_type']}")
        else:
            print(f"   ❌ {test_endpoint} failed: {result['error']}")
            print("   💡 Check if the endpoint exists and is accessible")
        
        print()
        
        # Test 3: Full analysis (if both API and docs are available)
        if os.path.exists(DOC_FILE):
            print("3️⃣ Running full accuracy analysis...")
            try:
                report = agent.analyze_api(DOC_FILE, DOC_FORMAT)
                
                summary = report['summary']
                print(f"   ✅ Analysis completed")
                print(f"      Accuracy Score: {summary['accuracy_score']}%")
                print(f"      Total Issues: {summary['total_issues']}")
                print(f"      Documented Endpoints: {summary['total_documented_endpoints']}")
                print(f"      Discovered Endpoints: {summary['total_discovered_endpoints']}")
                
                if report['issues']:
                    print(f"\n   🚨 Issues found:")
                    for issue in report['issues'][:3]:  # Show first 3 issues
                        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(issue.severity, "⚪")
                        print(f"      {severity_emoji} {issue.description}")
                    if len(report['issues']) > 3:
                        print(f"      ... and {len(report['issues']) - 3} more issues")
                else:
                    print(f"   🎉 No issues found!")
                    
            except Exception as e:
                print(f"   ❌ Analysis failed: {e}")
        else:
            print("3️⃣ Skipping full analysis (no documentation file)")
        
        print()
        print("✅ Testing completed!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

def create_sample_openapi():
    """Create a sample OpenAPI specification for testing"""
    sample_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Sample API",
            "version": "1.0.0",
            "description": "A sample API for testing the DocAccuracy Agent"
        },
        "servers": [
            {"url": "https://jsonplaceholder.typicode.com"}
        ],
        "paths": {
            "/posts": {
                "get": {
                    "summary": "Get all posts",
                    "description": "Retrieve a list of all blog posts",
                    "responses": {
                        "200": {
                            "description": "List of posts",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "title": {"type": "string"},
                                                "body": {"type": "string"},
                                                "userId": {"type": "integer"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/posts/{id}": {
                "get": {
                    "summary": "Get post by ID",
                    "description": "Retrieve a specific blog post by its ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                            "description": "Post ID"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Post details",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "title": {"type": "string"},
                                            "body": {"type": "string"},
                                            "userId": {"type": "integer"}
                                        }
                                    }
                                }
                            }
                        },
                        "404": {
                            "description": "Post not found"
                        }
                    }
                }
            },
            "/users": {
                "get": {
                    "summary": "Get all users",
                    "description": "Retrieve a list of all users",
                    "responses": {
                        "200": {
                            "description": "List of users",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "name": {"type": "string"},
                                                "email": {"type": "string"},
                                                "phone": {"type": "string"}
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
    }
    
    with open("sample_openapi.json", "w") as f:
        json.dump(sample_spec, f, indent=2)
    
    print("📝 Created sample OpenAPI specification: sample_openapi.json")
    print("   This uses JSONPlaceholder API (https://jsonplaceholder.typicode.com)")
    print("   You can test with this by running:")
    print("   python test_your_api.py --use-sample")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test DocAccuracy Agent with your API")
    parser.add_argument("--use-sample", action="store_true", 
                       help="Use the sample OpenAPI spec for testing")
    parser.add_argument("--create-sample", action="store_true",
                       help="Create a sample OpenAPI spec file")
    
    args = parser.parse_args()
    
    if args.create_sample:
        create_sample_openapi()
        return
    
    if args.use_sample:
        # Modify the test to use the sample
        API_BASE_URL = "https://jsonplaceholder.typicode.com"
        DOC_FILE = "sample_openapi.json"
        DOC_FORMAT = DocFormat.OPENAPI
        
        if not os.path.exists(DOC_FILE):
            print("Sample file not found. Creating it...")
            create_sample_openapi()
        
        test_with_your_api(API_BASE_URL, DOC_FILE, DOC_FORMAT)
    else:
        test_with_your_api()

if __name__ == "__main__":
    main()
