"""
Basic Langchain RAG Authorization Example

This example demonstrates how to use Casbin with Langchain for document access control
in a Retrieval-Augmented Generation (RAG) system.
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from casbin import Enforcer
from casbin.integrations import LangchainEnforcer


def get_examples(filename):
    """Get the path to an example file."""
    examples_path = os.path.join(os.path.dirname(__file__), "..")
    return os.path.join(examples_path, filename)


def main():
    """Demonstrate basic Langchain RAG authorization."""
    print("=" * 60)
    print("Casbin + Langchain: Basic RAG Authorization Example")
    print("=" * 60)
    print()

    # Initialize Casbin enforcer with Langchain RAG model
    enforcer = Enforcer(
        get_examples("langchain_rag_model.conf"),
        get_examples("langchain_rag_policy.csv")
    )

    # Wrap with LangchainEnforcer for convenience methods
    lc_enforcer = LangchainEnforcer(enforcer)

    # Test document access for different users
    print("Document Access Control:")
    print("-" * 40)
    
    users = ["alice", "bob", "charlie"]
    documents = [
        "document:public:readme",
        "document:analytics:report",
        "document:private:secret"
    ]
    
    for user in users:
        print(f"\nUser: {user}")
        for doc in documents:
            can_read = lc_enforcer.can_access_document(user, doc, "read")
            print(f"  {doc}: {'✓ Allowed' if can_read else '✗ Denied'}")
    
    # Test tool usage authorization
    print("\n\nTool Usage Authorization:")
    print("-" * 40)
    
    tools = ["search", "calculator", "database"]
    
    for user in users:
        print(f"\nUser: {user}")
        for tool in tools:
            can_use = lc_enforcer.can_use_tool(user, tool)
            print(f"  tool:{tool}: {'✓ Allowed' if can_use else '✗ Denied'}")
    
    # Test agent execution
    print("\n\nAgent Execution Authorization:")
    print("-" * 40)
    
    agents = ["chatbot", "analyst", "admin_agent"]
    
    for user in ["alice", "dave", "charlie"]:
        print(f"\nUser: {user}")
        for agent in agents:
            can_execute = lc_enforcer.can_execute_agent(user, agent)
            print(f"  agent:{agent}: {'✓ Allowed' if can_execute else '✗ Denied'}")
    
    # Get accessible resources for a user
    print("\n\nAccessible Resources for Bob (data_analyst):")
    print("-" * 40)
    
    accessible_docs = lc_enforcer.get_accessible_documents("bob", "read")
    print(f"Accessible documents: {accessible_docs}")
    
    available_tools = lc_enforcer.get_available_tools("bob")
    print(f"Available tools: {available_tools}")
    
    # Demonstrate document filtering for RAG
    print("\n\nDocument Filtering for RAG:")
    print("-" * 40)
    
    # Simulated retrieved documents from a vector database
    retrieved_docs = [
        {"id": "document:public:readme", "content": "Public readme content"},
        {"id": "document:analytics:report", "content": "Analytics report"},
        {"id": "document:private:secret", "content": "Secret information"},
    ]
    
    # Filter documents based on user permissions
    filtered_docs = lc_enforcer.filter_documents_by_permission(
        "charlie", retrieved_docs, document_id_field="id"
    )
    
    print(f"Charlie retrieved {len(retrieved_docs)} documents from vector DB")
    print(f"After authorization filtering: {len(filtered_docs)} documents allowed")
    print("Allowed documents:")
    for doc in filtered_docs:
        print(f"  - {doc['id']}")
    
    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
