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

"""
Langchain integration for Casbin authorization.

This module provides authorization support for Langchain applications including:
- Document access control in RAG systems
- Tool usage authorization
- Agent action permissions
- Multi-tenant support for Langchain applications
"""

from typing import Optional, List, Dict, Any


class LangchainEnforcer:
    """
    LangchainEnforcer provides authorization helpers for Langchain applications.
    
    This class wraps a Casbin enforcer with Langchain-specific convenience methods
    for common authorization patterns in LLM applications.
    """

    def __init__(self, enforcer):
        """
        Initialize the LangchainEnforcer with a Casbin enforcer.
        
        Args:
            enforcer: A Casbin enforcer instance (Enforcer, AsyncEnforcer, etc.)
        """
        self.enforcer = enforcer

    def can_access_document(self, user: str, document_id: str, action: str = "read", domain: Optional[str] = None) -> bool:
        """
        Check if a user can access a document in a RAG system.
        
        Args:
            user: User identifier
            document_id: Document identifier (e.g., "document:public:readme", "document:private:secret")
            action: Action to perform (read, write, delete)
            domain: Optional domain/tenant identifier for multi-tenant applications
            
        Returns:
            bool: True if access is allowed, False otherwise
        """
        if domain:
            return self.enforcer.enforce(user, domain, document_id, action)
        return self.enforcer.enforce(user, document_id, action)

    def can_use_tool(self, user: str, tool_name: str, domain: Optional[str] = None) -> bool:
        """
        Check if a user can use a specific Langchain tool.
        
        Args:
            user: User identifier
            tool_name: Tool identifier (e.g., "tool:search", "tool:calculator")
            domain: Optional domain/tenant identifier for multi-tenant applications
            
        Returns:
            bool: True if tool usage is allowed, False otherwise
        """
        tool_resource = f"tool:{tool_name}" if not tool_name.startswith("tool:") else tool_name
        if domain:
            return self.enforcer.enforce(user, domain, tool_resource, "use")
        return self.enforcer.enforce(user, tool_resource, "use")

    def can_execute_agent(self, user: str, agent_name: str, domain: Optional[str] = None) -> bool:
        """
        Check if a user can execute a specific Langchain agent.
        
        Args:
            user: User identifier
            agent_name: Agent identifier (e.g., "agent:chatbot", "agent:analyst")
            domain: Optional domain/tenant identifier for multi-tenant applications
            
        Returns:
            bool: True if agent execution is allowed, False otherwise
        """
        agent_resource = f"agent:{agent_name}" if not agent_name.startswith("agent:") else agent_name
        if domain:
            return self.enforcer.enforce(user, domain, agent_resource, "execute")
        return self.enforcer.enforce(user, agent_resource, "execute")

    def get_accessible_documents(self, user: str, action: str = "read", domain: Optional[str] = None) -> List[str]:
        """
        Get all documents accessible to a user.
        
        Args:
            user: User identifier
            action: Action to check (read, write, delete)
            domain: Optional domain/tenant identifier for multi-tenant applications
            
        Returns:
            List[str]: List of accessible document identifiers
        """
        accessible_docs = []
        
        # Get all policies
        policies = self.enforcer.get_policy()
        
        for policy in policies:
            if domain:
                # Format: [sub, dom, obj, act]
                if len(policy) >= 4:
                    pol_sub, pol_dom, pol_obj, pol_act = policy[0], policy[1], policy[2], policy[3]
                    if pol_obj.startswith("document:") and pol_act == action and pol_dom == domain:
                        # Check if user has this permission
                        if self.enforcer.enforce(user, domain, pol_obj, action):
                            accessible_docs.append(pol_obj)
            else:
                # Format: [sub, obj, act]
                if len(policy) >= 3:
                    pol_sub, pol_obj, pol_act = policy[0], policy[1], policy[2]
                    if pol_obj.startswith("document:") and pol_act == action:
                        # Check if user has this permission
                        if self.enforcer.enforce(user, pol_obj, action):
                            accessible_docs.append(pol_obj)
        
        # Remove duplicates
        return list(set(accessible_docs))

    def get_available_tools(self, user: str, domain: Optional[str] = None) -> List[str]:
        """
        Get all tools available to a user.
        
        Args:
            user: User identifier
            domain: Optional domain/tenant identifier for multi-tenant applications
            
        Returns:
            List[str]: List of available tool identifiers
        """
        available_tools = []
        
        # Get all policies
        policies = self.enforcer.get_policy()
        
        for policy in policies:
            if domain:
                # Format: [sub, dom, obj, act]
                if len(policy) >= 4:
                    pol_sub, pol_dom, pol_obj, pol_act = policy[0], policy[1], policy[2], policy[3]
                    if pol_obj.startswith("tool:") and pol_act == "use" and pol_dom == domain:
                        # Check if user has this permission
                        if self.enforcer.enforce(user, domain, pol_obj, "use"):
                            available_tools.append(pol_obj)
            else:
                # Format: [sub, obj, act]
                if len(policy) >= 3:
                    pol_sub, pol_obj, pol_act = policy[0], policy[1], policy[2]
                    if pol_obj.startswith("tool:") and pol_act == "use":
                        # Check if user has this permission
                        if self.enforcer.enforce(user, pol_obj, "use"):
                            available_tools.append(pol_obj)
        
        # Remove duplicates
        return list(set(available_tools))

    def filter_documents_by_permission(self, user: str, documents: List[Dict[str, Any]], 
                                      document_id_field: str = "id", 
                                      action: str = "read",
                                      domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Filter a list of documents based on user permissions.
        
        This is useful for RAG systems where you need to filter retrieved documents
        before passing them to the LLM.
        
        Args:
            user: User identifier
            documents: List of document dictionaries
            document_id_field: Field name containing the document ID
            action: Action to check (read, write, delete)
            domain: Optional domain/tenant identifier for multi-tenant applications
            
        Returns:
            List[Dict[str, Any]]: Filtered list of documents user can access
        """
        filtered_docs = []
        
        for doc in documents:
            doc_id = doc.get(document_id_field)
            if doc_id:
                if self.can_access_document(user, doc_id, action, domain):
                    filtered_docs.append(doc)
        
        return filtered_docs


__all__ = ["LangchainEnforcer"]
