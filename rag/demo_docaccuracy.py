#!/usr/bin/env python3
"""
Demo: Documentation Accuracy Agent
----------------------------------
This demo shows how the DocAccuracyAgent works — analyzing an OpenAPI spec
and detecting undocumented endpoints or inconsistencies.

No live API is required; it uses local mock data to simulate results.
"""

import json
import os
from docaccuracy_agent import DocAccuracyAgent, DocFormat
from pprint import pprint

# --------------------------------------------------------------------
# Demo Data Setup
# --------------------------------------------------------------------
MOCK_SPEC_JSON = {
    "openapi": "3.0.0",
    "info": {"title": "Demo API", "version": "1.0.0"},
    "paths": {
        "/users": {
            "get": {
                "summary": "List all users",
                "responses": {"200": {"description": "Successful response"}}
            }
        },
        "/users/{id}": {
            "get": {
                "summary": "Retrieve a user by ID",
                "parameters": [{"name": "id", "in": "path", "required": True}],
                "responses": {"200": {"description": "User found"}},
            }
        },
        "/auth/login": {
            "post": {
                "summary": "User login",
                "responses": {"200": {"description": "Login successful"}},
            }
        }
    }
}

# Write mock spec to file for demo
os.makedirs("demo_data", exist_ok=True)
with open("demo_data/demo_openapi.json", "w") as f:
    json.dump(MOCK_SPEC_JSON, f, indent=4)

# --------------------------------------------------------------------
# Demo Steps
# --------------------------------------------------------------------

def demo_1_parse_documentation():
    """Step 1: Parse the OpenAPI documentation"""
    print("============================================================")
    print("DEMO 1: PARSING DOCUMENTATION")
    print("============================================================")

    agent = DocAccuracyAgent(base_url="https://demo.example.com")

    # Load and parse the mock spec
    with open("demo_data/demo_openapi.json", "r") as f:
        spec = json.load(f)
    endpoints = agent._parse_openapi_spec(spec)

    print(f"✅ Parsed {len(endpoints)} endpoints from documentation.\n")
    for ep in endpoints:
        print(f"  - {ep.method} {ep.path}: {ep.description}")


def demo_2_discovery_and_accuracy():
    """Step 2: Run the discovery logic to simulate undocumented endpoints"""
    print("\n============================================================")
    print("DEMO 2: DISCOVERING UNDOCUMENTED ENDPOINTS")
    print("============================================================")

    agent = DocAccuracyAgent(base_url="https://demo.example.com")

    # Manually set documented endpoints from our mock spec
    with open("demo_data/demo_openapi.json", "r") as f:
        spec = json.load(f)
    agent.doc_endpoints = agent._parse_openapi_spec(spec)

    # Simulate the discovery process
    agent._discover_endpoints()

    report = agent._generate_report()

    print(f"✅ Found {report['summary']['total_issues']} issues total.")
    print(f"   - Documented endpoints: {report['summary']['documented_count']}")
    print(f"   - Discovered endpoints: {report['summary']['discovered_count']}")
    print("\n📋 Issues Found:")
    pprint(report["issues"], width=120)


def demo_3_full_run():
    """Step 3: Simulate a full agent run with report output"""
    print("\n============================================================")
    print("DEMO 3: FULL AGENT RUN")
    print("============================================================")

    agent = DocAccuracyAgent(base_url="https://demo.example.com")

    # Simulate a full check using the local demo spec
    with open("demo_data/demo_openapi.json", "r") as f:
        spec = json.load(f)
    agent.doc_endpoints = agent._parse_openapi_spec(spec)
    agent._discover_endpoints()

    full_report = agent._generate_report()

    print("\n✅ SUMMARY:")
    pprint(full_report["summary"], width=80)

    print("\n🚨 DETAILED FINDINGS:")
    for issue in full_report["issues"]:
        print(f"  [{issue['severity']}] {issue['description']}")
        print(f"     → Suggestion: {issue['suggestion']}\n")


# --------------------------------------------------------------------
# MAIN EXECUTION
# --------------------------------------------------------------------

def main():
    print("🚀 DOCUMENTATION ACCURACY AGENT DEMO")
    print("This demo shows how the agent works without needing a running API\n")

    demo_1_parse_documentation()
    demo_2_discovery_and_accuracy()
    demo_3_full_run()

if __name__ == "__main__":
    main()
