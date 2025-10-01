#!/usr/bin/env python3
"""
Demo script showing how to use the Documentation Accuracy Agent
This demonstrates the agent's capabilities without needing a running API
"""

import sys
import os
import json

# Add the agents directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'agents'))

from docaccuracy_agent import DocAccuracyAgent, DocFormat

def demo_1_parse_documentation():
    """Demo 1: Parse different types of documentation"""
    print("=" * 60)
    print("DEMO 1: PARSING DOCUMENTATION")
    print("=" * 60)
    
    # Create a sample OpenAPI specification
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Sample API",
            "version": "1.0.0",
            "description": "A sample API for demonstration"
        },
        "servers": [
            {"url": "https://api.example.com"}
        ],
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get all users",
                    "responses": {
                        "200": {
                            "description": "List of users",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "object"}
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create a new user",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "User created successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User details",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
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
            }
        }
    }
    
    # Save to file
    with open("demo_openapi.json", "w") as f:
        json.dump(openapi_spec, f, indent=2)
    
    # Create agent and parse
    agent = DocAccuracyAgent()
    endpoints = agent._parse_documentation("demo_openapi.json", DocFormat.OPENAPI)
    
    print(f"✅ Successfully parsed OpenAPI specification")
    print(f"📊 Found {len(endpoints)} documented endpoints:")
    
    for i, endpoint in enumerate(endpoints, 1):
        print(f"   {i}. {endpoint.method} {endpoint.path}")
        print(f"      Description: {endpoint.description}")
        if endpoint.parameters:
            print(f"      Parameters: {len(endpoint.parameters)}")
        if endpoint.responses:
            print(f"      Response codes: {list(endpoint.responses.keys())}")
        print()
    
    # Clean up
    os.remove("demo_openapi.json")
    return endpoints

def demo_2_markdown_parsing():
    """Demo 2: Parse Markdown documentation"""
    print("=" * 60)
    print("DEMO 2: PARSING MARKDOWN DOCUMENTATION")
    print("=" * 60)
    
    # Create a sample markdown file
    markdown_content = """
# API Documentation

## Authentication
All endpoints require a Bearer token in the Authorization header.

## Endpoints

### Users

#### `GET /api/v1/users`
Get all users

#### `POST /api/v1/users`
Create a new user

#### `GET /api/v1/users/{id}`
Get user by ID

#### `PUT /api/v1/users/{id}`
Update user

#### `DELETE /api/v1/users/{id}`
Delete user

### Products

#### `GET /api/v1/products`
Get all products

#### `POST /api/v1/products`
Create a new product
"""
    
    with open("demo_api.md", "w") as f:
        f.write(markdown_content)
    
    # Parse markdown
    agent = DocAccuracyAgent()
    endpoints = agent._parse_documentation("demo_api.md", DocFormat.MARKDOWN)
    
    print(f"✅ Successfully parsed Markdown documentation")
    print(f"📊 Found {len(endpoints)} documented endpoints:")
    
    for i, endpoint in enumerate(endpoints, 1):
        print(f"   {i}. {endpoint.method} {endpoint.path}")
        print(f"      Description: {endpoint.description}")
        print()
    
    # Clean up
    os.remove("demo_api.md")
    return endpoints

def demo_3_accuracy_analysis():
    """Demo 3: Simulate accuracy analysis"""
    print("=" * 60)
    print("DEMO 3: ACCURACY ANALYSIS SIMULATION")
    print("=" * 60)
    
    # Create agent with a mock base URL
    agent = DocAccuracyAgent(base_url="https://api.example.com")
    
    # Create a sample OpenAPI spec with some intentional issues
    problematic_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Problematic API",
            "version": "1.0.0"
        },
        "servers": [
            {"url": "https://api.example.com"}
        ],
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get all users",
                    "responses": {
                        "200": {
                            "description": "List of users"
                        }
                    }
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User details"
                        },
                        "404": {
                            "description": "User not found"
                        }
                    }
                }
            },
            "/nonexistent": {
                "get": {
                    "summary": "This endpoint doesn't exist",
                    "responses": {
                        "200": {
                            "description": "This will never work"
                        }
                    }
                }
            }
        }
    }
    
    # Save spec
    with open("problematic_spec.json", "w") as f:
        json.dump(problematic_spec, f, indent=2)
    
    # Mock some discovered endpoints (simulating what would be found)
    agent.discovered_endpoints = [
        agent._create_endpoint_info("GET", "/users"),
        agent._create_endpoint_info("GET", "/users/{id}"),
        agent._create_endpoint_info("POST", "/users"),  # This exists but not documented
        agent._create_endpoint_info("GET", "/health"),   # This exists but not documented
    ]
    
    # Parse documentation
    agent.doc_endpoints = agent._parse_documentation("problematic_spec.json", DocFormat.OPENAPI)
    
    # Check accuracy
    issues = agent._check_accuracy()
    
    print(f"✅ Analyzed documentation accuracy")
    print(f"📊 Found {len(issues)} accuracy issues:")
    
    for i, issue in enumerate(issues, 1):
        severity_emoji = {
            "critical": "🔴",
            "high": "🟠", 
            "medium": "🟡",
            "low": "🟢"
        }.get(issue.severity, "⚪")
        
        print(f"\n   {i}. {severity_emoji} [{issue.severity.upper()}] {issue.category.upper()}")
        print(f"      Endpoint: {issue.endpoint}")
        print(f"      Description: {issue.description}")
        print(f"      Expected: {issue.expected}")
        print(f"      Actual: {issue.actual}")
        if issue.suggestion:
            print(f"      💡 Suggestion: {issue.suggestion}")
    
    # Clean up
    os.remove("problematic_spec.json")
    return issues

def demo_4_usage_examples():
    """Demo 4: Show different usage patterns"""
    print("=" * 60)
    print("DEMO 4: USAGE EXAMPLES")
    print("=" * 60)
    
    print("🔧 How to use the DocAccuracy Agent:")
    print()
    
    print("1️⃣ Basic usage with OpenAPI spec:")
    print("""
   agent = DocAccuracyAgent(base_url='https://api.example.com')
   report = agent.analyze_api('openapi.json', DocFormat.OPENAPI)
   print(f"Accuracy Score: {report['summary']['accuracy_score']}%")
    """)
    
    print("2️⃣ Parse documentation only (no API testing):")
    print("""
   agent = DocAccuracyAgent()
   endpoints = agent._parse_documentation('api_docs.md', DocFormat.MARKDOWN)
   for ep in endpoints:
       print(f"{ep.method} {ep.path}")
    """)
    
    print("3️⃣ Test a specific endpoint:")
    print("""
   agent = DocAccuracyAgent(base_url='https://api.example.com')
   result = agent.test_endpoint('/users/123', 'GET')
   if result['success']:
       print(f"Status: {result['status_code']}")
       print(f"Response: {result['content']}")
    """)
    
    print("4️⃣ Auto-detect documentation format:")
    print("""
   agent = DocAccuracyAgent(base_url='https://api.example.com')
   report = agent.analyze_api('documentation.yaml')  # Auto-detects format
    """)
    
    print("5️⃣ Work with different documentation formats:")
    print("""
   # OpenAPI/Swagger
   report = agent.analyze_api('swagger.json', DocFormat.OPENAPI)
   
   # Markdown
   report = agent.analyze_api('api_docs.md', DocFormat.MARKDOWN)
   
   # RAML (when implemented)
   report = agent.analyze_api('api.raml', DocFormat.RAML)
    """)

def demo_5_report_generation():
    """Demo 5: Show report generation capabilities"""
    print("=" * 60)
    print("DEMO 5: REPORT GENERATION")
    print("=" * 60)
    
    # Create a sample report
    sample_report = {
        "summary": {
            "total_documented_endpoints": 5,
            "total_discovered_endpoints": 4,
            "total_issues": 3,
            "accuracy_score": 70,
            "issues_by_severity": {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 0
            }
        },
        "issues": [
            {
                "severity": "high",
                "category": "endpoint",
                "description": "Documented endpoint not found: GET /api/v1/nonexistent",
                "expected": "Endpoint should exist",
                "actual": "Endpoint not accessible",
                "endpoint": "GET /api/v1/nonexistent",
                "suggestion": "Remove from documentation or fix endpoint implementation"
            },
            {
                "severity": "medium",
                "category": "endpoint",
                "description": "Undocumented endpoint found: POST /api/v1/users",
                "expected": "Should be documented",
                "actual": "Not documented",
                "endpoint": "POST /api/v1/users",
                "suggestion": "Add this endpoint to your documentation"
            },
            {
                "severity": "medium",
                "category": "status_code",
                "description": "Unexpected status code for GET /api/v1/users",
                "expected": "One of: 200, 404",
                "actual": "500",
                "endpoint": "GET /api/v1/users",
                "suggestion": "Update documentation to include this status code or fix the implementation"
            }
        ]
    }
    
    print("📊 Sample Report Structure:")
    print(json.dumps(sample_report, indent=2))
    
    print("\n🎯 Key Features of the Report:")
    print("   • Accuracy score (0-100%)")
    print("   • Issues categorized by severity")
    print("   • Detailed issue descriptions with suggestions")
    print("   • Comparison of documented vs discovered endpoints")
    print("   • Actionable recommendations for improvement")

# Add helper method to DocAccuracyAgent for demo
def _create_endpoint_info(self, method, path, description="Mock endpoint"):
    """Helper method for creating endpoint info"""
    from docaccuracy_agent import EndpointInfo
    return EndpointInfo(
        path=path,
        method=method,
        description=description
    )

# Monkey patch the method for demo
DocAccuracyAgent._create_endpoint_info = _create_endpoint_info

def main():
    """Run all demos"""
    print("🚀 DOCUMENTATION ACCURACY AGENT DEMO")
    print("This demo shows how the agent works without needing a running API")
    print()
    
    try:
        # Run all demos
        demo_1_parse_documentation()
        print()
        
        demo_2_markdown_parsing()
        print()
        
        demo_3_accuracy_analysis()
        print()
        
        demo_4_usage_examples()
        print()
        
        demo_5_report_generation()
        print()
        
        print("=" * 60)
        print("✅ DEMO COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print()
        print("🎉 The DocAccuracy Agent is ready to use!")
        print("📚 Check the agents/docaccuracy_agent.py file for the full implementation")
        print("🔧 Use the examples above to integrate it into your projects")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
