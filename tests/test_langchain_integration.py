# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import casbin
from casbin.integrations import LangchainEnforcer
from unittest import TestCase


def get_examples(filename):
    """Get the path to an example file."""
    examples_path = os.path.split(os.path.realpath(__file__))[0]
    examples_path = os.path.join(examples_path, "..", "examples")
    return os.path.join(examples_path, filename)


class TestLangchainIntegration(TestCase):
    """Test cases for Langchain integration with Casbin."""

    def test_document_access_basic(self):
        """Test basic document access control."""
        e = casbin.Enforcer(
            get_examples("langchain_rag_model.conf"),
            get_examples("langchain_rag_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Admin (alice) should have access to all documents
        self.assertTrue(lc_enforcer.can_access_document("alice", "document:public:readme", "read"))
        self.assertTrue(lc_enforcer.can_access_document("alice", "document:analytics:report", "read"))
        self.assertTrue(lc_enforcer.can_access_document("alice", "document:private:secret", "write"))

        # Data analyst (bob) should have access to public and analytics documents
        self.assertTrue(lc_enforcer.can_access_document("bob", "document:public:readme", "read"))
        self.assertTrue(lc_enforcer.can_access_document("bob", "document:analytics:report", "read"))
        self.assertFalse(lc_enforcer.can_access_document("bob", "document:private:secret", "read"))

        # Basic user (charlie) should only have access to public documents
        self.assertTrue(lc_enforcer.can_access_document("charlie", "document:public:readme", "read"))
        self.assertFalse(lc_enforcer.can_access_document("charlie", "document:analytics:report", "read"))
        self.assertFalse(lc_enforcer.can_access_document("charlie", "document:private:secret", "read"))

    def test_tool_usage(self):
        """Test tool usage authorization."""
        e = casbin.Enforcer(
            get_examples("langchain_rag_model.conf"),
            get_examples("langchain_rag_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Admin should be able to use all tools
        self.assertTrue(lc_enforcer.can_use_tool("alice", "search"))
        self.assertTrue(lc_enforcer.can_use_tool("alice", "calculator"))
        self.assertTrue(lc_enforcer.can_use_tool("alice", "database"))

        # Data analyst should be able to use search and calculator
        self.assertTrue(lc_enforcer.can_use_tool("bob", "search"))
        self.assertTrue(lc_enforcer.can_use_tool("bob", "calculator"))
        self.assertFalse(lc_enforcer.can_use_tool("bob", "database"))

        # Basic user should only be able to use search
        self.assertTrue(lc_enforcer.can_use_tool("charlie", "search"))
        self.assertFalse(lc_enforcer.can_use_tool("charlie", "calculator"))
        self.assertFalse(lc_enforcer.can_use_tool("charlie", "database"))

    def test_agent_execution(self):
        """Test agent execution authorization."""
        e = casbin.Enforcer(
            get_examples("langchain_rag_model.conf"),
            get_examples("langchain_rag_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Admin should be able to execute all agents
        self.assertTrue(lc_enforcer.can_execute_agent("alice", "chatbot"))
        self.assertTrue(lc_enforcer.can_execute_agent("alice", "analyst"))

        # Agent user should be able to execute chatbot
        self.assertTrue(lc_enforcer.can_execute_agent("dave", "chatbot"))
        self.assertFalse(lc_enforcer.can_execute_agent("dave", "analyst"))

        # Basic user should not be able to execute agents
        self.assertFalse(lc_enforcer.can_execute_agent("charlie", "chatbot"))
        self.assertFalse(lc_enforcer.can_execute_agent("charlie", "analyst"))

    def test_get_accessible_documents(self):
        """Test getting list of accessible documents."""
        e = casbin.Enforcer(
            get_examples("langchain_rag_model.conf"),
            get_examples("langchain_rag_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Get accessible documents for data analyst
        accessible = lc_enforcer.get_accessible_documents("bob", "read")
        
        # Bob should have access to public and analytics documents
        self.assertTrue(any("public" in doc for doc in accessible))
        self.assertTrue(any("analytics" in doc for doc in accessible))
        
        # Get accessible documents for basic user
        accessible = lc_enforcer.get_accessible_documents("charlie", "read")
        
        # Charlie should only have access to public documents
        self.assertTrue(any("public" in doc for doc in accessible))
        self.assertFalse(any("analytics" in doc for doc in accessible))

    def test_get_available_tools(self):
        """Test getting list of available tools."""
        e = casbin.Enforcer(
            get_examples("langchain_rag_model.conf"),
            get_examples("langchain_rag_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Get available tools for data analyst
        tools = lc_enforcer.get_available_tools("bob")
        
        # Bob should have access to search and calculator
        self.assertTrue(any("search" in tool for tool in tools))
        self.assertTrue(any("calculator" in tool for tool in tools))
        
        # Get available tools for basic user
        tools = lc_enforcer.get_available_tools("charlie")
        
        # Charlie should only have access to search
        self.assertTrue(any("search" in tool for tool in tools))
        self.assertEqual(len(tools), 1)

    def test_filter_documents_by_permission(self):
        """Test filtering documents based on permissions."""
        e = casbin.Enforcer(
            get_examples("langchain_rag_model.conf"),
            get_examples("langchain_rag_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Simulated documents from a RAG system
        documents = [
            {"id": "document:public:readme", "content": "Public content"},
            {"id": "document:analytics:report", "content": "Analytics content"},
            {"id": "document:private:secret", "content": "Secret content"},
        ]

        # Filter for basic user (charlie)
        filtered = lc_enforcer.filter_documents_by_permission("charlie", documents)
        
        # Charlie should only see public documents
        self.assertEqual(len(filtered), 1)
        self.assertTrue("public" in filtered[0]["id"])

        # Filter for data analyst (bob)
        filtered = lc_enforcer.filter_documents_by_permission("bob", documents)
        
        # Bob should see public and analytics documents
        self.assertEqual(len(filtered), 2)
        ids = [doc["id"] for doc in filtered]
        self.assertTrue(any("public" in id for id in ids))
        self.assertTrue(any("analytics" in id for id in ids))

        # Filter for admin (alice)
        filtered = lc_enforcer.filter_documents_by_permission("alice", documents)
        
        # Alice should see all documents
        self.assertEqual(len(filtered), 3)

    def test_multi_tenant_document_access(self):
        """Test document access with multi-tenant support."""
        e = casbin.Enforcer(
            get_examples("langchain_with_domains_model.conf"),
            get_examples("langchain_with_domains_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Test access in tenant1
        self.assertTrue(lc_enforcer.can_access_document("alice", "document:public:readme", "read", "tenant1"))
        self.assertTrue(lc_enforcer.can_access_document("bob", "document:public:readme", "read", "tenant1"))
        
        # Test access in tenant2
        self.assertTrue(lc_enforcer.can_access_document("carol", "document:shared:doc", "read", "tenant2"))
        self.assertTrue(lc_enforcer.can_access_document("dave", "document:shared:doc", "read", "tenant2"))
        
        # Test cross-tenant access (should fail)
        self.assertFalse(lc_enforcer.can_access_document("alice", "document:shared:doc", "read", "tenant2"))
        self.assertFalse(lc_enforcer.can_access_document("carol", "document:public:readme", "read", "tenant1"))

    def test_multi_tenant_tool_access(self):
        """Test tool access with multi-tenant support."""
        e = casbin.Enforcer(
            get_examples("langchain_with_domains_model.conf"),
            get_examples("langchain_with_domains_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Test tool access in tenant1
        self.assertTrue(lc_enforcer.can_use_tool("alice", "search", "tenant1"))
        self.assertTrue(lc_enforcer.can_use_tool("bob", "search", "tenant1"))
        
        # Test tool access in tenant2
        self.assertTrue(lc_enforcer.can_use_tool("carol", "search", "tenant2"))
        
        # Alice is admin in tenant1 but not in tenant2
        self.assertFalse(lc_enforcer.can_use_tool("alice", "search", "tenant2"))

    def test_tool_name_with_prefix(self):
        """Test that tool names work with or without 'tool:' prefix."""
        e = casbin.Enforcer(
            get_examples("langchain_rag_model.conf"),
            get_examples("langchain_rag_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Test with and without prefix
        self.assertEqual(
            lc_enforcer.can_use_tool("bob", "search"),
            lc_enforcer.can_use_tool("bob", "tool:search")
        )

    def test_agent_name_with_prefix(self):
        """Test that agent names work with or without 'agent:' prefix."""
        e = casbin.Enforcer(
            get_examples("langchain_rag_model.conf"),
            get_examples("langchain_rag_policy.csv")
        )
        lc_enforcer = LangchainEnforcer(e)

        # Test with and without prefix
        self.assertEqual(
            lc_enforcer.can_execute_agent("dave", "chatbot"),
            lc_enforcer.can_execute_agent("dave", "agent:chatbot")
        )
