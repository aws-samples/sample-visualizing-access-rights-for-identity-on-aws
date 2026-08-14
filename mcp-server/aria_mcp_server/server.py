"""MCP server exposing the ARIA-gv identity access graph as tools.

The graph is a point-in-time Neptune Analytics snapshot of identity/access
relationships collected from IAM Identity Center, IAM, and IAM Access Analyzer.
All tools are read-only. See queries.py for the graph model.

Built on the mcp 2.x SDK. The 2.0 release replaced ``mcp.server.fastmcp.FastMCP``
with ``mcp.server.mcpserver.MCPServer``, and the transport settings
(host/port/path/stateless) moved from the constructor onto ``run()``.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from . import queries
from .graph_client import AriaGraphClient, GraphError, ReadOnlyViolation

# The transport settings that satisfy the AgentCore Runtime MCP contract
# (0.0.0.0:8000, /mcp, stateless) are applied at run() time - see main_http().
mcp = MCPServer("aria-gv")

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
- RoleName (IamRoleArn): rolename, accountid, roleid, attachedpolicies, source
    `source` records provenance. It is set to AccountAccessManager for roles a
    principal is entitled to DIRECTLY (a direct role assignment), as opposed to
    roles reached via an IAM Identity Center permission set. A role reached by
    both routes is a single node carrying the union of properties.
- CriticalResources (ResourceARN): resourcetype
- InternalAccessFinding (FindingId): action, principal, resourcearn, findingtype, accesstype, status, ...
- UnusedAccessFinding (FindingId): resourcearn, numberofunusedactions, numberofunusedservices, status, ...
- ExternalAccessFinding (FindingId): action, principal, principaltype, resourcearn, resourceaccount, condition, ispublic, status, ...
- ExternalPrincipal (Principal): principalname, principaltype - an entity OUTSIDE the
    zone of trust (another AWS account, a federated/service principal, or the
    special node "PUBLIC" for anonymous access)

Edges (from -> to):
- (GroupName)-[:HAS_MEMBERS]->(UserName)
- (UserName|GroupName)-[:ASSIGNED_PERMISSIONSET]->(PermissionSet)
- (UserName|GroupName)-[:ASSIGNED_ROLE]->(RoleName)     # direct role assignment (no permission set)
- (UserName|GroupName)-[:ASSIGNED_ACCOUNT]->(AccountName)
- (PermissionSet)-[:PROVISIONED_INTO]->(AccountName)
- (PermissionSet)-[:CREATED_AS]->(RoleName)
- (RoleName)-[:CREATED_IN]->(AccountName)
- (RoleName)-[:EXISTS_IN]->(AccountName)                # direct-role placement in an account
- (InternalAccessFinding)-[:LINKED_TO]->(RoleName | CriticalResources)
- (RoleName)-[:GRANTS_ACCESS_TO]->(CriticalResources)
- (CriticalResources)-[:BELONGS_TO]->(AccountName)
- (RoleName)-[:HAS_UNUSED_ACCESS]->(UnusedAccessFinding)
- (ExternalAccessFinding)-[:LINKED_TO]->(ExternalPrincipal | CriticalResources)
- (ExternalPrincipal)-[:HAS_EXTERNAL_ACCESS_TO]->(CriticalResources)

External access is the inverse direction of the internal model: an
ExternalPrincipal (outside the zone of trust) reaches an internal
CriticalResources node. CriticalResources is shared with internal findings, so a
resource flagged by both analyzers is a single node keyed on its ARN. What the
external principal can DO lives on ExternalAccessFinding.action.

There are TWO independent ways a human principal reaches an IAM role, and either
can lead on to a critical resource. Do NOT assume access is only via permission
sets:

1. Permission-set route (IAM Identity Center):
   (User)<-[:HAS_MEMBERS]-(Group)-[:ASSIGNED_PERMISSIONSET]->(PermissionSet)
         -[:CREATED_AS]->(Role)-[:GRANTS_ACCESS_TO]->(CriticalResources)
2. Direct role assignment (e.g. Account Access Manager entitlement):
   (User)<-[:HAS_MEMBERS]-(Group)-[:ASSIGNED_ROLE]->(Role)
         -[:GRANTS_ACCESS_TO]->(CriticalResources)

In both routes the group hop is optional - a user can be assigned directly. When
answering "who can access" / "how can X access", cover BOTH routes (UNION them)
unless asked about one specifically.

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

    Returns every distinct path from the user to the resource across BOTH access
    routes - IAM Identity Center permission sets and direct role assignments
    (Account Access Manager entitlements). Each row includes the group (if any),
    an `access_via` tag (permission_set or direct_role), the permission set (null
    for direct-role access), the IAM role, the role's `source`, and the finding
    actions that permit it.

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
    a resource, across BOTH access routes: IAM Identity Center permission sets
    and direct role assignments (Account Access Manager entitlements).

    Returns one row per (principal, role, route); the `access_via` field tags
    each as permission_set or direct_role.

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
    """Report everything a user can access across BOTH routes - IAM Identity
    Center permission sets and direct role assignments (Account Access Manager
    entitlements) - one row per reachable resource (or per account-level grant
    when no critical resource is attached).

    Each row carries an `access_via` tag (permission_set or direct_role); the
    `permission_set` is null for the direct-role route. `account` is where the
    access lands (the account the permission set is provisioned into, or the
    account the direct role sits in); `resource` / `resource_account` describe the
    reachable critical resource and its owning account.

    Args:
        principal: user name or substring.
        account: optional account-name substring to scope the report (matched
            against the account the access lands in or the resource's owner).
    """
    query, params = queries.principal_access_report(principal, account)
    return _run(query, params)


@mcp.tool()
def get_principal_access_summary(
    principal: str, account: str | None = None
) -> dict[str, Any]:
    """Compact roll-up of what a user can reach, grouped by route and grant.

    Same two-route coverage as get_principal_access, but returns one row per
    (access_via, grant, iam_role) with a `resource_count` and the deduplicated
    `resources` list instead of one row per resource. Prefer this for
    wide-access principals (e.g. admins) where the per-resource report runs to
    hundreds of rows. `grant` is the permission-set name on the permission_set
    route and the role's source (e.g. AccountAccessManager) on the direct_role
    route. Only grants that reach at least one critical resource are returned.

    Args:
        principal: user name or substring.
        account: optional account-name substring, matched against the resource's
            owning account.
    """
    query, params = queries.principal_access_summary(principal, account)
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
def find_external_access(
    resource: str | None = None, actions: list[str] | None = None, limit: int = 100
) -> dict[str, Any]:
    """List external-access exposures: which external principals (other AWS
    accounts, federated/service principals, or PUBLIC) can reach which internal
    resources, per IAM Access Analyzer external-access findings.

    Returns one row per (external principal, resource) with the granted actions,
    principal type, whether the access is public, and the resource's account.

    Args:
        resource: optional resource ARN substring to scope the report (e.g. a
            bucket name). Omit to list all external exposures.
        actions: optional action-substring filter, e.g. ["get", "put"]. Omit for
            any access.
        limit: max rows (default 100).
    """
    query, params = queries.external_access(resource, actions, limit)
    return _run(query, params)


@mcp.tool()
def list_entities(entity: str, limit: int = 100) -> dict[str, Any]:
    """List nodes of one kind - useful to confirm exact names/ARNs before a
    targeted query.

    Args:
        entity: one of users, groups, permissionsets, accounts, roles, resources,
            externalprincipals.
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
    session isolation. Stateless mode is required because AgentCore injects its
    own Mcp-Session-Id header.
    """
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",  # nosec B104 - required by the AgentCore Runtime contract
        port=8000,
        streamable_http_path="/mcp",
        stateless_http=True,
    )


if __name__ == "__main__":
    main_http()
