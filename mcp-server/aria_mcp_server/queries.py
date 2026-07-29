"""openCypher query builders for the ARIA-gv graph.

Every builder returns a (query_string, parameters) pair. User-supplied values
are passed as openCypher parameters ($name), never string-interpolated, so the
tools are injection-safe.

Graph model (see the solution's s3export lambda for the source of truth):

  Nodes:  UserName{username}, GroupName{groupname}, PermissionSet{name},
          AccountName{name}, RoleName{rolename,accountid},
          CriticalResources{resourcetype}, InternalAccessFinding{action,...},
          UnusedAccessFinding{...}
  Edges:  (Group)-[:HAS_MEMBERS]->(User)
          (User|Group)-[:ASSIGNED_PERMISSIONSET]->(PermissionSet)
          (User|Group)-[:ASSIGNED_ACCOUNT]->(Account)
          (PermissionSet)-[:PROVISIONED_INTO]->(Account)
          (PermissionSet)-[:CREATED_AS]->(Role)
          (Role)-[:CREATED_IN]->(Account)
          (InternalAccessFinding)-[:LINKED_TO]->(Role|CriticalResources)
          (Role)-[:GRANTS_ACCESS_TO]->(CriticalResources)
          (CriticalResources)-[:BELONGS_TO]->(Account)
          (Role)-[:HAS_UNUSED_ACCESS]->(UnusedAccessFinding)
"""

from __future__ import annotations

from typing import Any

# Default action substrings that indicate a mutating / write-style permission.
WRITE_ACTION_HINTS = ["put", "update", "write", "delete", "create", "modify", "*"]

_ENTITY_MAP = {
    "users": ("UserName", "username"),
    "groups": ("GroupName", "groupname"),
    "permissionsets": ("PermissionSet", "name"),
    "accounts": ("AccountName", "name"),
    "roles": ("RoleName", "rolename"),
    "resources": ("CriticalResources", "`~id`"),
}


def _action_filter(var: str, actions_param: str = "actions") -> str:
    """openCypher predicate: finding `var`.action matches any hint in $actions."""
    return (
        f"ANY(a IN ${actions_param} WHERE "
        f"toLower({var}.action) CONTAINS toLower(a))"
    )


def find_access_paths(
    principal: str, resource: str, actions: list[str] | None
) -> tuple[str, dict[str, Any]]:
    """Every path from a user to a critical resource, optional action filter."""
    params: dict[str, Any] = {"principal": principal, "resource": resource}
    action_clause = ""
    if actions:
        params["actions"] = actions
        action_clause = f"  AND {_action_filter('f')}\n"

    query = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (r:CriticalResources)\n"
        "WHERE r.`~id` CONTAINS $resource\n"
        "MATCH (u)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps:PermissionSet)\n"
        "MATCH (ps)-[:CREATED_AS]->(role:RoleName)-[:GRANTS_ACCESS_TO]->(r)\n"
        "MATCH (f:InternalAccessFinding)-[:LINKED_TO]->(role)\n"
        "WHERE (f)-[:LINKED_TO]->(r)\n"
        f"{action_clause}"
        "OPTIONAL MATCH (g:GroupName)-[:HAS_MEMBERS]->(u)\n"
        "WHERE (g)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "RETURN DISTINCT u.username AS user, g.groupname AS via_group,\n"
        "       ps.name AS permission_set, role.rolename AS iam_role,\n"
        "       r.`~id` AS resource, f.action AS granted_actions\n"
        "LIMIT 50"
    )
    return query, params


def who_can_access(
    resource: str, actions: list[str] | None
) -> tuple[str, dict[str, Any]]:
    """Every human principal that can reach a resource, optional action filter."""
    params: dict[str, Any] = {"resource": resource}
    action_join = ""
    action_clause = ""
    if actions:
        params["actions"] = actions
        action_join = (
            "MATCH (f:InternalAccessFinding)-[:LINKED_TO]->(role)\n"
            "WHERE (f)-[:LINKED_TO]->(r)\n"
        )
        action_clause = f"  AND {_action_filter('f')}\n"

    query = (
        "MATCH (r:CriticalResources)\n"
        "WHERE r.`~id` CONTAINS $resource\n"
        "MATCH (role:RoleName)-[:GRANTS_ACCESS_TO]->(r)\n"
        "MATCH (ps:PermissionSet)-[:CREATED_AS]->(role)\n"
        f"{action_join}{action_clause}"
        "OPTIONAL MATCH (du:UserName)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "OPTIONAL MATCH (g:GroupName)-[:ASSIGNED_PERMISSIONSET]->(ps),\n"
        "               (g)-[:HAS_MEMBERS]->(gu:UserName)\n"
        "RETURN r.`~id` AS resource, role.rolename AS iam_role,\n"
        "       ps.name AS permission_set,\n"
        "       collect(DISTINCT du.username) AS directly_assigned_users,\n"
        "       collect(DISTINCT g.groupname) AS via_groups,\n"
        "       collect(DISTINCT gu.username) AS group_member_users\n"
        "LIMIT 100"
    )
    return query, params


def principal_access_report(
    principal: str, account: str | None
) -> tuple[str, dict[str, Any]]:
    """Everything a user can reach, optionally scoped to one account name."""
    params: dict[str, Any] = {"principal": principal}
    account_clause = ""
    if account:
        params["account"] = account
        account_clause = (
            "WHERE acct.name CONTAINS $account OR resacct.name CONTAINS $account\n"
        )

    query = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (u)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps:PermissionSet)\n"
        "OPTIONAL MATCH (ps)-[:PROVISIONED_INTO]->(acct:AccountName)\n"
        "OPTIONAL MATCH (ps)-[:CREATED_AS]->(role:RoleName)"
        "-[:GRANTS_ACCESS_TO]->(res:CriticalResources)\n"
        "OPTIONAL MATCH (res)-[:BELONGS_TO]->(resacct:AccountName)\n"
        f"{account_clause}"
        "RETURN DISTINCT u.username AS user, ps.name AS permission_set,\n"
        "       acct.name AS account, role.rolename AS iam_role,\n"
        "       res.`~id` AS resource, resacct.name AS resource_account\n"
        "ORDER BY account, permission_set\n"
        "LIMIT 200"
    )
    return query, params


def unused_access(limit: int) -> tuple[str, dict[str, Any]]:
    """Roles with IAM Access Analyzer unused-access findings, worst first."""
    params = {"limit": limit}
    query = (
        "MATCH (role:RoleName)-[:HAS_UNUSED_ACCESS]->(f:UnusedAccessFinding)\n"
        "OPTIONAL MATCH (ps:PermissionSet)-[:CREATED_AS]->(role)\n"
        "OPTIONAL MATCH (u:UserName)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "OPTIONAL MATCH (g:GroupName)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "RETURN role.rolename AS iam_role, role.accountid AS account,\n"
        "       f.numberofunusedactions AS unused_actions,\n"
        "       f.numberofunusedservices AS unused_services, f.status AS status,\n"
        "       collect(DISTINCT u.username) AS users,\n"
        "       collect(DISTINCT g.groupname) AS groups\n"
        "ORDER BY toInteger(f.numberofunusedactions) DESC\n"
        "LIMIT $limit"
    )
    return query, params


def list_entities(entity: str, limit: int) -> tuple[str, dict[str, Any]]:
    """List nodes of one kind. `entity` is a key of _ENTITY_MAP."""
    key = entity.lower().strip()
    if key not in _ENTITY_MAP:
        raise ValueError(
            f"Unknown entity '{entity}'. Choose one of: {', '.join(sorted(_ENTITY_MAP))}."
        )
    label, prop = _ENTITY_MAP[key]
    extra = ", n.resourcetype AS resourcetype" if key == "resources" else ""
    query = (
        f"MATCH (n:{label})\n"
        f"RETURN n.{prop} AS value{extra}\n"
        f"ORDER BY value\n"
        "LIMIT $limit"
    )
    return query, {"limit": limit}


def node_label_counts() -> tuple[str, dict[str, Any]]:
    """Count of nodes per label - a quick snapshot sanity check."""
    query = (
        "MATCH (n)\n"
        "RETURN labels(n) AS label, count(*) AS count\n"
        "ORDER BY count DESC"
    )
    return query, {}
