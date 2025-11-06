"""
Multi-Tenant Langchain Authorization Example

This example demonstrates how to use Casbin with Langchain for multi-tenant applications
where users have different permissions in different domains/tenants.
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
    """Demonstrate multi-tenant Langchain authorization."""
    print("=" * 60)
    print("Casbin + Langchain: Multi-Tenant Authorization Example")
    print("=" * 60)
    print()

    # Initialize Casbin enforcer with multi-tenant model
    enforcer = Enforcer(
        get_examples("langchain_with_domains_model.conf"),
        get_examples("langchain_with_domains_policy.csv")
    )

    # Wrap with LangchainEnforcer
    lc_enforcer = LangchainEnforcer(enforcer)

    # Test access across different tenants
    print("Multi-Tenant Document Access:")
    print("-" * 40)
    
    test_cases = [
        ("alice", "tenant1", "document:public:readme"),
        ("alice", "tenant1", "document:private:data"),
        ("bob", "tenant1", "document:public:readme"),
        ("bob", "tenant1", "document:private:data"),
        ("carol", "tenant2", "document:shared:doc"),
        ("dave", "tenant2", "document:shared:doc"),
        ("dave", "tenant2", "document:private:admin"),
    ]
    
    for user, tenant, doc in test_cases:
        can_access = lc_enforcer.can_access_document(user, doc, "read", domain=tenant)
        print(f"{user}@{tenant} → {doc}: {'✓ Allowed' if can_access else '✗ Denied'}")
    
    # Test tool access across tenants
    print("\n\nMulti-Tenant Tool Access:")
    print("-" * 40)
    
    tool_tests = [
        ("alice", "tenant1", "search"),
        ("bob", "tenant1", "search"),
        ("bob", "tenant1", "admin_tool"),
        ("carol", "tenant2", "search"),
        ("dave", "tenant2", "search"),
    ]
    
    for user, tenant, tool in tool_tests:
        can_use = lc_enforcer.can_use_tool(user, tool, domain=tenant)
        print(f"{user}@{tenant} → tool:{tool}: {'✓ Allowed' if can_use else '✗ Denied'}")
    
    # Get tenant-specific accessible resources
    print("\n\nTenant-Specific Accessible Resources:")
    print("-" * 40)
    
    for user, tenant in [("bob", "tenant1"), ("dave", "tenant2")]:
        print(f"\n{user}@{tenant}:")
        docs = lc_enforcer.get_accessible_documents(user, "read", domain=tenant)
        tools = lc_enforcer.get_available_tools(user, domain=tenant)
        print(f"  Documents: {docs}")
        print(f"  Tools: {tools}")
    
    print("\n" + "=" * 60)
    print("Multi-tenant example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
