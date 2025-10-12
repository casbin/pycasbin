# Langchain Authorization with Casbin

This directory contains examples demonstrating how to use Casbin for authorization in Langchain applications.

## Overview

Casbin provides powerful authorization capabilities for Langchain applications, including:

- **Document Access Control**: Control which documents users can access in RAG (Retrieval-Augmented Generation) systems
- **Tool Usage Authorization**: Restrict which Langchain tools users can execute
- **Agent Execution Control**: Manage permissions for running different Langchain agents
- **Multi-tenant Support**: Implement authorization across different tenants/domains

## Examples

### Basic RAG Authorization

[`basic_rag_example.py`](basic_rag_example.py) demonstrates:
- Document access control with different user roles (admin, data_analyst, basic_user)
- Tool usage authorization (search, calculator, database)
- Agent execution permissions
- Filtering retrieved documents based on user permissions

Run the example:
```bash
python examples/langchain/basic_rag_example.py
```

### Multi-Tenant Authorization

[`multi_tenant_example.py`](multi_tenant_example.py) demonstrates:
- Authorization across multiple tenants/domains
- Users having different permissions in different tenants
- Tenant-specific resource access

Run the example:
```bash
python examples/langchain/multi_tenant_example.py
```

## Usage

### 1. Basic Setup

```python
from casbin import Enforcer
from casbin.integrations import LangchainEnforcer

# Initialize Casbin enforcer with Langchain RAG model
enforcer = Enforcer(
    "langchain_rag_model.conf",
    "langchain_rag_policy.csv"
)

# Wrap with LangchainEnforcer for convenience methods
lc_enforcer = LangchainEnforcer(enforcer)
```

### 2. Document Access Control

```python
# Check if user can access a document
can_read = lc_enforcer.can_access_document("alice", "document:public:readme", "read")

# Get all accessible documents for a user
accessible_docs = lc_enforcer.get_accessible_documents("bob", "read")

# Filter documents based on permissions (useful for RAG)
retrieved_docs = [
    {"id": "document:public:readme", "content": "..."},
    {"id": "document:private:secret", "content": "..."},
]
filtered = lc_enforcer.filter_documents_by_permission("user", retrieved_docs)
```

### 3. Tool Usage Authorization

```python
# Check if user can use a tool
can_use = lc_enforcer.can_use_tool("bob", "search")

# Get all available tools for a user
tools = lc_enforcer.get_available_tools("bob")
```

### 4. Agent Execution Control

```python
# Check if user can execute an agent
can_execute = lc_enforcer.can_execute_agent("alice", "chatbot")
```

### 5. Multi-Tenant Authorization

```python
# Check access with tenant/domain
can_read = lc_enforcer.can_access_document(
    "alice", "document:private:data", "read", domain="tenant1"
)

# Get tenant-specific resources
docs = lc_enforcer.get_accessible_documents("bob", "read", domain="tenant1")
```

## Model Configuration

### Basic RAG Model

The basic model (`langchain_rag_model.conf`) uses RBAC with pattern matching:

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && r.act == p.act
```

### Multi-Tenant Model

The multi-tenant model (`langchain_with_domains_model.conf`) adds domain support:

```ini
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch(r.obj, p.obj) && r.act == p.act
```

## Policy Configuration

Policies define the actual permissions using pattern matching:

```csv
# Role permissions
p, admin, document:*, read
p, admin, tool:*, use
p, data_analyst, document:public:*, read
p, data_analyst, document:analytics:*, read
p, data_analyst, tool:search, use

# Role assignments
g, alice, admin
g, bob, data_analyst
```

## Resource Naming Conventions

- **Documents**: `document:<category>:<name>` (e.g., `document:public:readme`, `document:analytics:report`)
- **Tools**: `tool:<name>` (e.g., `tool:search`, `tool:calculator`)
- **Agents**: `agent:<name>` (e.g., `agent:chatbot`, `agent:analyst`)

## Integration with Langchain

### RAG Document Filtering

```python
from langchain.vectorstores import FAISS
from langchain.embeddings import OpenAIEmbeddings

# After retrieving documents from vector store
retrieved_docs = vectorstore.similarity_search(query)

# Convert to format suitable for filtering
docs_with_ids = [
    {"id": f"document:{doc.metadata['category']}:{doc.metadata['name']}", 
     "content": doc.page_content}
    for doc in retrieved_docs
]

# Filter based on user permissions
authorized_docs = lc_enforcer.filter_documents_by_permission(
    user_id, docs_with_ids, document_id_field="id"
)

# Pass only authorized documents to LLM
authorized_content = [doc["content"] for doc in authorized_docs]
```

### Tool Authorization

```python
from langchain.agents import initialize_agent, Tool

# Get available tools for user
available_tool_names = lc_enforcer.get_available_tools(user_id)

# Filter tools based on authorization
authorized_tools = [
    tool for tool in all_tools 
    if f"tool:{tool.name}" in available_tool_names or 
       lc_enforcer.can_use_tool(user_id, tool.name)
]

# Initialize agent with authorized tools only
agent = initialize_agent(authorized_tools, llm, agent="zero-shot-react-description")
```

## Benefits

1. **Centralized Authorization**: Manage all access control in one place
2. **Fine-grained Control**: Control access at document, tool, and agent level
3. **Multi-tenancy**: Support multiple organizations/tenants with different policies
4. **Flexible Policies**: Use patterns and wildcards for easy policy management
5. **Production-Ready**: Built on battle-tested Casbin authorization library

## Learn More

- [Casbin Documentation](https://casbin.org/docs/)
- [Langchain Documentation](https://python.langchain.com/)
- [PyCasbin GitHub](https://github.com/casbin/pycasbin)
