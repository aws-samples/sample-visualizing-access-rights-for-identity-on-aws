"""FastMCP server exposing the ARIA-gv identity access graph as tools.

The graph is a point-in-time Neptune Analytics snapshot of identity/access
relationships collected from IAM Identity Center, IAM, and IAM Access Analyzer.
All tools are read-only. See queries.py for the graph model.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import queries
from .graph_client import AriaGraphClient, GraphError, ReadOnlyViolation

# Host/port/path satisfy the AgentCore Runtime MCP contract (0.0.0.0:8000, /mcp).
# Stateless mode is required by AgentCore Runtime, which injects its own
# Mcp-Session-Id header.
mcp = FastMCP(
    "aria-gv",
    host="0.0.0.0",  # nosec B104 - required by the AgentCore Runtime contract
    port=8000,
    stateless_http=True,
    streamable_http_path="/mcp",
)

# One lazily-initialised client for the process. boto3/graph-id resolution
# happens on first query, not at import time, so the server starts cleanly even
# without credentials configured.
_client = AriaGraphClient()


def _run(query: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute a query and normalise success/error into a dict for the model."""
    try:
        result = _client.execute(query, parameters)
        result["query"] = query
        return result
    except ReadOnlyViolation as exc:
        return {"error": "read_only_violation", "message": str(exc), "query": query}
    except GraphError as exc:
        # Return the query so the caller can paste it into Graph Explorer if the
        # private endpoint is unreachable.
        return {"error": "graph_error", "message": str(exc), "query": query}


SCHEMA_DOC = """\
ARIA-gv graph model (Neptune Analytics, openCypher).

Nodes (node id `~id` in parentheses):
- UserName (UserId): username
- GroupName (GroupId): groupname
- PermissionSet (PermissionSetArn): name, description
- AccountName (AccountId): name
- RoleName (IamRoleArn): rolename, accountid, roleid, attachedpolicies
- CriticalResources (ResourceARN): resourcetype
- InternalAccessFinding (FindingId): action, principal, resourcearn, findingtype, accesstype, status, ...
- UnusedAccessFinding (FindingId): resourcearn, numberofunusedactions, numberofunusedservices, status, ...

Edges (from -> to):
- (GroupName)-[:HAS_MEMBERS]->(UserName)
- (UserName|GroupName)-[:ASSIGNED_PERMISSIONSET]->(PermissionSet)
- (UserName|GroupName)-[:ASSIGNED_ACCOUNT]->(AccountName)
- (PermissionSet)-[:PROVISIONED_INTO]->(AccountName)
- (PermissionSet)-[:CREATED_AS]->(RoleName)
- (RoleName)-[:CREATED_IN]->(AccountName)
- (InternalAccessFinding)-[:LINKED_TO]->(RoleName | CriticalResources)
- (RoleName)-[:GRANTS_ACCESS_TO]->(CriticalResources)
- (CriticalResources)-[:BELONGS_TO]->(AccountName)
- (RoleName)-[:HAS_UNUSED_ACCESS]->(UnusedAccessFinding)

A human-to-resource path is typically:
  (User)<-[:HAS_MEMBERS]-(Group)-[:ASSIGNED_PERMISSIONSET]->(PermissionSet)
        -[:CREATED_AS]->(Role)-[:GRANTS_ACCESS_TO]->(CriticalResources)
or, for a directly-assigned user, without the group hop.

What a principal can DO to a resource lives on InternalAccessFinding.action, not
on the edge. Filter on that property for verbs like update / write / delete.

Notes: names are case-sensitive in the data; resources are matched by ARN
substring. The graph shows POTENTIAL access at snapshot time - it does not model
IdP context, IAM trust-policy conditions, SCPs/RCPs, or session policies, and is
not proof an action occurred.
"""


@mcp.tool()
def describe_graph_schema() -> str:
    """Return the ARIA-gv graph node/edge model and the property names.

    Call this first when composing a custom query so you use the correct labels,
    relationship names, and property keys.
    """
    return SCHEMA_DOC


@mcp.tool()
def find_access_paths(
    principal: str, resource: str, actions: list[str] | None = None
) -> dict[str, Any]:
    """Show HOW a user can reach a critical resource (the "how was Bob able to
    update this resource" question).

    Returns every distinct path from the user to the resource: the group (if
    any), permission set, IAM role, and the finding actions that permit it.

    Args:
        principal: user name or a substring of it (case-insensitive match).
        resource: resource ARN or a substring of it (e.g. a bucket name).
        actions: optional list of action substrings to require, e.g.
            ["put", "delete", "update"] to answer "how could they UPDATE it".
            Omit for any access. Use WRITE_ACTION_HINTS-style verbs.
    """
    query, params = queries.find_access_paths(principal, resource, actions)
    return _run(query, params)


@mcp.tool()
def who_can_access(
    resource: str, actions: list[str] | None = None
) -> dict[str, Any]:
    """List every human principal (users, directly or via groups) that can reach
    a resource.

    Args:
        resource: resource ARN or substring.
        actions: optional action-substring filter, e.g. ["delete"] for "who can
            delete this". Omit for any access.
    """
    query, params = queries.who_can_access(resource, actions)
    return _run(query, params)


@mcp.tool()
def get_principal_access(
    principal: str, account: str | None = None
) -> dict[str, Any]:
    """Report everything a user can access: their permission sets, the accounts
    those are provisioned into, and the critical resources reachable.

    Args:
        principal: user name or substring.
        account: optional account-name substring to scope the report.
    """
    query, params = queries.principal_access_report(principal, account)
    return _run(query, params)


@mcp.tool()
def find_unused_access(limit: int = 50) -> dict[str, Any]:
    """List IAM roles flagged with IAM Access Analyzer unused-access findings
    (least-privilege violations), worst first, with the users/groups that hold
    them.

    Args:
        limit: max roles to return (default 50).
    """
    query, params = queries.unused_access(limit)
    return _run(query, params)


@mcp.tool()
def list_entities(entity: str, limit: int = 100) -> dict[str, Any]:
    """List nodes of one kind - useful to confirm exact names/ARNs before a
    targeted query.

    Args:
        entity: one of users, groups, permissionsets, accounts, roles, resources.
        limit: max rows (default 100).
    """
    try:
        query, params = queries.list_entities(entity, limit)
    except ValueError as exc:
        return {"error": "bad_argument", "message": str(exc)}
    return _run(query, params)


@mcp.tool()
def graph_summary() -> dict[str, Any]:
    """Return a count of nodes per label - a quick health/inventory check that
    also confirms the server can reach the graph.
    """
    query, params = queries.node_label_counts()
    return _run(query, params)


@mcp.tool()
def execute_cypher(query: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run an arbitrary READ-ONLY openCypher query against the graph.

    Use the higher-level tools when they fit; use this for questions they do not
    cover. Mutating queries (CREATE/MERGE/SET/DELETE/REMOVE/DETACH/DROP/LOAD) are
    rejected. Prefer passing user values via `parameters` ($name placeholders)
    rather than string interpolation. Always include a LIMIT for exploration.

    Args:
        query: the openCypher query. Call describe_graph_schema first for the model.
        parameters: optional map of openCypher parameters referenced as $name.
    """
    return _run(query, parameters)


def main_http() -> None:
    """Console-script entrypoint: run over streamable-HTTP on 0.0.0.0:8000 /mcp.

    This is the only transport the server exposes. It hosts the MCP protocol on
    Amazon Bedrock AgentCore Runtime, which speaks streamable-HTTP and provides
    session isolation.
    """
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main_http()
