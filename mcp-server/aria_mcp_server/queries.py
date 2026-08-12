"""openCypher query builders for the ARIA-gv graph.

Every builder returns a (query_string, parameters) pair. User-supplied values
are passed as openCypher parameters ($name), never string-interpolated, so the
tools are injection-safe.

Graph model (see the solution's s3export lambda for the source of truth):

  Nodes:  UserName{username}, GroupName{groupname}, PermissionSet{name},
          AccountName{name}, RoleName{rolename,accountid,source},
          CriticalResources{resourcetype}, InternalAccessFinding{action,...},
          UnusedAccessFinding{...}, ExternalAccessFinding{action,principal,...},
          ExternalPrincipal{principalname,principaltype}

          RoleName.source records provenance: it is set to AccountAccessManager
          for roles that arrive via an AAM entitlement. A role that is both an
          IdC-provisioned role and an AAM-entitled role merges into one RoleName
          node (matched on the Iam role ARN) carrying the union of properties.

          ExternalPrincipal is an entity OUTSIDE the zone of trust (another AWS
          account, a federated/service principal, or the special node "PUBLIC"
          for anonymous access). CriticalResources is shared with internal
          findings: a resource flagged by both analyzers is one node keyed on its
          ARN.

  Edges:  (Group)-[:HAS_MEMBERS]->(User)
          (User|Group)-[:ASSIGNED_PERMISSIONSET]->(PermissionSet)
          (User|Group)-[:ASSIGNED_ACCOUNT]->(Account)
          (PermissionSet)-[:PROVISIONED_INTO]->(Account)
          (PermissionSet)-[:CREATED_AS]->(Role)
          (Role)-[:CREATED_IN]->(Account)
          (User|Group)-[:ASSIGNED_ROLE]->(Role)    # AAM entitlement
          (Role)-[:EXISTS_IN]->(Account)           # AAM role placement
          (InternalAccessFinding)-[:LINKED_TO]->(Role|CriticalResources)
          (Role)-[:GRANTS_ACCESS_TO]->(CriticalResources)
          (CriticalResources)-[:BELONGS_TO]->(Account)
          (Role)-[:HAS_UNUSED_ACCESS]->(UnusedAccessFinding)
          (ExternalAccessFinding)-[:LINKED_TO]->(ExternalPrincipal|CriticalResources)
          (ExternalPrincipal)-[:HAS_EXTERNAL_ACCESS_TO]->(CriticalResources)

  Two routes reach an account from a principal: the IdC permission-set route
  (principal -> PermissionSet -> Account) and the AAM route
  (principal -[:ASSIGNED_ROLE]-> Role -[:EXISTS_IN|CREATED_IN]-> Account).
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
    "externalprincipals": ("ExternalPrincipal", "`~id`"),
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
    """Every path from a user to a critical resource, optional action filter.

    Covers BOTH routes to the granting IAM role and UNIONs them:
      - permission_set: principal -> PermissionSet -> Role -> resource
      - direct_role:    principal -[:ASSIGNED_ROLE]-> Role -> resource
    The `access_via` column tells the two apart; `permission_set` is null for the
    direct-role route. Either route allows the optional group hop via HAS_MEMBERS.
    """
    params: dict[str, Any] = {"principal": principal, "resource": resource}
    action_clause = ""
    if actions:
        params["actions"] = actions
        action_clause = f"  AND {_action_filter('f')}\n"

    # Mandatory finding match (carries the granted actions), shared by both routes.
    finding_block = (
        "MATCH (f:InternalAccessFinding)-[:LINKED_TO]->(role)\n"
        "WHERE (f)-[:LINKED_TO]->(r)\n"
        f"{action_clause}"
    )

    ps_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (r:CriticalResources)\n"
        "WHERE r.`~id` CONTAINS $resource\n"
        "MATCH (u)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps:PermissionSet)\n"
        "MATCH (ps)-[:CREATED_AS]->(role:RoleName)-[:GRANTS_ACCESS_TO]->(r)\n"
        f"{finding_block}"
        "OPTIONAL MATCH (g:GroupName)-[:HAS_MEMBERS]->(u)\n"
        "WHERE (g)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "RETURN DISTINCT u.username AS user, g.groupname AS via_group,\n"
        "       'permission_set' AS access_via, ps.name AS permission_set,\n"
        "       role.rolename AS iam_role, role.source AS role_source,\n"
        "       r.`~id` AS resource, f.action AS granted_actions\n"
        "LIMIT 50"
    )

    role_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (r:CriticalResources)\n"
        "WHERE r.`~id` CONTAINS $resource\n"
        "MATCH (u)-[:ASSIGNED_ROLE|HAS_MEMBERS*1..2]-(role:RoleName)\n"
        "MATCH (role)-[:GRANTS_ACCESS_TO]->(r)\n"
        f"{finding_block}"
        "OPTIONAL MATCH (g:GroupName)-[:HAS_MEMBERS]->(u)\n"
        "WHERE (g)-[:ASSIGNED_ROLE]->(role)\n"
        "RETURN DISTINCT u.username AS user, g.groupname AS via_group,\n"
        "       'direct_role' AS access_via, null AS permission_set,\n"
        "       role.rolename AS iam_role, role.source AS role_source,\n"
        "       r.`~id` AS resource, f.action AS granted_actions\n"
        "LIMIT 50"
    )

    query = f"{ps_branch}\nUNION\n{role_branch}"
    return query, params


def who_can_access(
    resource: str, actions: list[str] | None
) -> tuple[str, dict[str, Any]]:
    """Every human principal that can reach a resource, optional action filter.

    Returns one row per (principal, role, route). Covers BOTH routes to the
    granting role and UNIONs them:
      - permission_set: principal -> PermissionSet -> Role -> resource
      - direct_role:    principal -[:ASSIGNED_ROLE]-> Role -> resource
    `access_via` distinguishes them, `via_group` names the group when access is
    inherited through group membership (null when assigned directly), and
    `permission_set` is null for the direct-role route.
    """
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

    # Shared prefix: pin the resource and the role(s) that grant access to it,
    # applying the optional action-finding filter.
    base = (
        "MATCH (r:CriticalResources)\n"
        "WHERE r.`~id` CONTAINS $resource\n"
        "MATCH (role:RoleName)-[:GRANTS_ACCESS_TO]->(r)\n"
        f"{action_join}{action_clause}"
    )

    ps_branch = (
        f"{base}"
        "MATCH (ps:PermissionSet)-[:CREATED_AS]->(role)\n"
        "MATCH (u:UserName)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps)\n"
        "OPTIONAL MATCH (g:GroupName)-[:HAS_MEMBERS]->(u)\n"
        "WHERE (g)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "RETURN DISTINCT r.`~id` AS resource, role.rolename AS iam_role,\n"
        "       role.source AS role_source, 'permission_set' AS access_via,\n"
        "       ps.name AS permission_set, u.username AS principal,\n"
        "       g.groupname AS via_group\n"
        "LIMIT 100"
    )

    role_branch = (
        f"{base}"
        "MATCH (u:UserName)-[:ASSIGNED_ROLE|HAS_MEMBERS*1..2]-(role)\n"
        "OPTIONAL MATCH (g:GroupName)-[:HAS_MEMBERS]->(u)\n"
        "WHERE (g)-[:ASSIGNED_ROLE]->(role)\n"
        "RETURN DISTINCT r.`~id` AS resource, role.rolename AS iam_role,\n"
        "       role.source AS role_source, 'direct_role' AS access_via,\n"
        "       null AS permission_set, u.username AS principal,\n"
        "       g.groupname AS via_group\n"
        "LIMIT 100"
    )

    query = f"{ps_branch}\nUNION\n{role_branch}"
    return query, params


def principal_access_report(
    principal: str, account: str | None
) -> tuple[str, dict[str, Any]]:
    """Everything a user can reach, optionally scoped to one account name.

    Covers both access routes: the IdC permission-set path
    (principal -> PermissionSet -> Account / Role / Resource) and the Account
    Access Manager path (principal -[:ASSIGNED_ROLE]-> Role
    -[:EXISTS_IN|CREATED_IN]-> Account), so AAM entitlements appear alongside
    permission-set access. Both paths allow the group hop via HAS_MEMBERS.
    """
    params: dict[str, Any] = {"principal": principal}
    account_clause = ""
    if account:
        params["account"] = account
        account_clause = (
            "WHERE acct.name CONTAINS $account\n"
            "   OR resacct.name CONTAINS $account\n"
            "   OR aamacct.name CONTAINS $account\n"
        )

    query = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        # IdC permission-set route (directly or via a group).
        "OPTIONAL MATCH (u)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps:PermissionSet)\n"
        "OPTIONAL MATCH (ps)-[:PROVISIONED_INTO]->(acct:AccountName)\n"
        "OPTIONAL MATCH (ps)-[:CREATED_AS]->(role:RoleName)"
        "-[:GRANTS_ACCESS_TO]->(res:CriticalResources)\n"
        "OPTIONAL MATCH (res)-[:BELONGS_TO]->(resacct:AccountName)\n"
        # Account Access Manager route (directly or via a group).
        "OPTIONAL MATCH (u)-[:ASSIGNED_ROLE|HAS_MEMBERS*1..2]-(aamrole:RoleName)\n"
        "OPTIONAL MATCH (aamrole)-[:EXISTS_IN|CREATED_IN]->(aamacct:AccountName)\n"
        f"{account_clause}"
        "RETURN DISTINCT u.username AS user, ps.name AS permission_set,\n"
        "       acct.name AS account, role.rolename AS iam_role,\n"
        "       res.`~id` AS resource, resacct.name AS resource_account,\n"
        "       aamrole.rolename AS aam_role, aamrole.source AS aam_role_source,\n"
        "       aamacct.name AS aam_account\n"
        "ORDER BY account, permission_set\n"
        "LIMIT 200"
    )
    return query, params


def unused_access(limit: int) -> tuple[str, dict[str, Any]]:
    """Roles with IAM Access Analyzer unused-access findings, worst first.

    Attributes each flagged role to the principals that hold it by BOTH routes:
    permission-set holders (permissionset_users/groups) and direct-role holders
    (direct_role_users/groups). `role_source` shows provenance.
    """
    params = {"limit": limit}
    query = (
        "MATCH (role:RoleName)-[:HAS_UNUSED_ACCESS]->(f:UnusedAccessFinding)\n"
        "OPTIONAL MATCH (ps:PermissionSet)-[:CREATED_AS]->(role)\n"
        "OPTIONAL MATCH (u:UserName)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "OPTIONAL MATCH (g:GroupName)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "OPTIONAL MATCH (du:UserName)-[:ASSIGNED_ROLE]->(role)\n"
        "OPTIONAL MATCH (dg:GroupName)-[:ASSIGNED_ROLE]->(role)\n"
        "RETURN role.rolename AS iam_role, role.accountid AS account,\n"
        "       role.source AS role_source,\n"
        "       f.numberofunusedactions AS unused_actions,\n"
        "       f.numberofunusedservices AS unused_services, f.status AS status,\n"
        "       collect(DISTINCT u.username) AS permissionset_users,\n"
        "       collect(DISTINCT g.groupname) AS permissionset_groups,\n"
        "       collect(DISTINCT du.username) AS direct_role_users,\n"
        "       collect(DISTINCT dg.groupname) AS direct_role_groups\n"
        "ORDER BY toInteger(f.numberofunusedactions) DESC\n"
        "LIMIT $limit"
    )
    return query, params


def external_access(
    resource: str | None, actions: list[str] | None, limit: int
) -> tuple[str, dict[str, Any]]:
    """External-access exposures: which external principals can reach which
    internal resources (the "what is shared outside my zone of trust" question).

    Returns one row per (external principal, resource) exposure with the granting
    finding's actions, the principal type, whether it is public, and the resource
    account. Optionally scope to a resource ARN substring and/or require certain
    action verbs.
    """
    params: dict[str, Any] = {"limit": limit}
    resource_clause = ""
    if resource:
        params["resource"] = resource
        resource_clause = "  AND r.`~id` CONTAINS $resource\n"
    action_clause = ""
    if actions:
        params["actions"] = actions
        action_clause = f"  AND {_action_filter('f')}\n"

    query = (
        "MATCH (p:ExternalPrincipal)-[:HAS_EXTERNAL_ACCESS_TO]->(r:CriticalResources)\n"
        "MATCH (f:ExternalAccessFinding)-[:LINKED_TO]->(r)\n"
        "WHERE (f)-[:LINKED_TO]->(p)\n"
        f"{resource_clause}{action_clause}"
        "OPTIONAL MATCH (r)-[:BELONGS_TO]->(acct:AccountName)\n"
        "RETURN DISTINCT p.`~id` AS external_principal,\n"
        "       p.principaltype AS principal_type, f.ispublic AS is_public,\n"
        "       r.`~id` AS resource, acct.name AS resource_account,\n"
        "       f.action AS granted_actions, f.status AS status\n"
        "ORDER BY resource, external_principal\n"
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
    if key == "resources":
        extra = ", n.resourcetype AS resourcetype"
    elif key == "roles":
        # source distinguishes direct-assignment (AccountAccessManager) roles.
        extra = ", n.accountid AS account, n.source AS source"
    elif key == "externalprincipals":
        extra = ", n.principaltype AS principaltype"
    else:
        extra = ""
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
