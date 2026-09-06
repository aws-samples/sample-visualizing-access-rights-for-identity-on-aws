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
          (UserName|RoleName)-[:CAN_ASSUME]->(RoleName)   # trust policy: source principal may assume target role

  CAN_ASSUME encodes IAM trust policies: `~from` is a principal ARN, `~to` is the
  trusted (target) role ARN. RoleName nodes are keyed on the IAM role ARN, so
  role-to-role CAN_ASSUME edges connect to existing RoleName nodes and support
  multi-hop role chaining. UserName nodes are keyed on UserId, so a trusting-USER
  ARN does NOT line up with an existing UserName node and instead attaches to a
  standalone ARN-keyed node. CAN_ASSUME covers IAM role and IAM user principals
  only (service, account-root, wildcard, and federated SAML/OIDC principals are
  excluded); STS assumed-role ARNs were normalized to their IAM role ARN.

  Two routes reach an account from a principal: the IdC permission-set route
  (principal -> PermissionSet -> Account) and the AAM route
  (principal -[:ASSIGNED_ROLE]-> Role -[:EXISTS_IN|CREATED_IN]-> Account). A
  third route, role chaining, is now UNIONed into find_access_paths,
  who_can_access, principal_access_report, and principal_access_summary: it
  reaches the granting role via one or more CAN_ASSUME hops from a role the
  principal reaches through either of the two routes above, tagged
  access_via = "role_chain". find_role_assumption_paths remains the dedicated
  tool for role-to-role assumption chains independent of any resource.
"""

from __future__ import annotations

from typing import Any

# Default action substrings that indicate a mutating / write-style permission.
WRITE_ACTION_HINTS = ["put", "update", "write", "delete", "create", "modify", "*"]

# Role-chaining traversal bounds (CAN_ASSUME edge).
MAX_HOPS_CAP = 10   # hard upper bound on chaining depth (Max_Hops_Cap)
DEFAULT_HOPS = 5    # default traversal depth when the caller supplies none


def effective_hops(max_hops: Any) -> int:
    """Clamp a caller-supplied hop bound to a validated integer in [1, cap].

    Casts to int (falling back to DEFAULT_HOPS on TypeError/ValueError), floors
    at 1, and caps at MAX_HOPS_CAP. The result is the ONE value embedded into the
    variable-length pattern text, since openCypher variable-length bounds cannot
    be parameters - so it must be a provably-bounded integer.
    """
    try:
        n = int(max_hops)
    except (TypeError, ValueError):
        n = DEFAULT_HOPS
    if n < 1:
        n = 1
    if n > MAX_HOPS_CAP:
        n = MAX_HOPS_CAP
    return n

_ENTITY_MAP = {
    "users": ("UserName", "username"),
    "groups": ("GroupName", "groupname"),
    "permissionsets": ("PermissionSet", "name"),
    "accounts": ("AccountName", "name"),
    "roles": ("RoleName", "rolename"),
    "assumableroles": ("RoleName", "rolename"),
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
    principal: str,
    resource: str,
    actions: list[str] | None,
    max_hops: int = DEFAULT_HOPS,
) -> tuple[str, dict[str, Any]]:
    """Every path from a user to a critical resource, optional action filter.

    Covers THREE routes to the granting IAM role and UNIONs them:
      - permission_set: principal -> PermissionSet -> Role -> resource
      - direct_role:    principal -[:ASSIGNED_ROLE]-> Role -> resource
      - role_chain:     principal -> (PermissionSet or direct) -> Entry_Role
                        -[:CAN_ASSUME*1..N]-> Role -> resource
    The `access_via` column tells the routes apart; `permission_set` is null for
    the direct-role route and for the role-chain arm reached via a direct role.
    Every route allows the optional group hop via HAS_MEMBERS. `chain_hops`,
    `chain_arns`, and `chain_roles` are null on the permission_set/direct_role
    rows (required for UNION column-compatibility) and populated on role_chain
    rows. `max_hops` bounds the role_chain route's CAN_ASSUME traversal depth
    via effective_hops(); it has no effect on the other two routes.
    """
    params: dict[str, Any] = {"principal": principal, "resource": resource}
    action_clause = ""
    if actions:
        params["actions"] = actions
        action_clause = f"  AND {_action_filter('f')}\n"
    eff = effective_hops(max_hops)

    # Mandatory finding match (carries the granted actions), shared by all routes.
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
        "       r.`~id` AS resource, f.action AS granted_actions,\n"
        "       null AS chain_hops, null AS chain_arns, null AS chain_roles\n"
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
        "       r.`~id` AS resource, f.action AS granted_actions,\n"
        "       null AS chain_hops, null AS chain_arns, null AS chain_roles\n"
        "LIMIT 50"
    )

    chain_ps_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (r:CriticalResources)\n"
        "WHERE r.`~id` CONTAINS $resource\n"
        "MATCH (u)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps:PermissionSet)\n"
        "MATCH (ps)-[:CREATED_AS]->(entry:RoleName)\n"
        f"MATCH chain = (entry)-[:CAN_ASSUME*1..{eff}]->(role:RoleName)\n"
        "MATCH (role)-[:GRANTS_ACCESS_TO]->(r)\n"
        f"{finding_block}"
        "OPTIONAL MATCH (g:GroupName)-[:HAS_MEMBERS]->(u)\n"
        "WHERE (g)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "RETURN DISTINCT u.username AS user, g.groupname AS via_group,\n"
        "       'role_chain' AS access_via, ps.name AS permission_set,\n"
        "       role.rolename AS iam_role, role.source AS role_source,\n"
        "       r.`~id` AS resource, f.action AS granted_actions,\n"
        "       length(chain) AS chain_hops,\n"
        "       [n IN nodes(chain) | n.`~id`] AS chain_arns,\n"
        "       [n IN nodes(chain) | n.rolename] AS chain_roles\n"
        "LIMIT 50"
    )

    chain_role_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (r:CriticalResources)\n"
        "WHERE r.`~id` CONTAINS $resource\n"
        "MATCH (u)-[:ASSIGNED_ROLE|HAS_MEMBERS*1..2]-(entry:RoleName)\n"
        f"MATCH chain = (entry)-[:CAN_ASSUME*1..{eff}]->(role:RoleName)\n"
        "MATCH (role)-[:GRANTS_ACCESS_TO]->(r)\n"
        f"{finding_block}"
        "OPTIONAL MATCH (g:GroupName)-[:HAS_MEMBERS]->(u)\n"
        "WHERE (g)-[:ASSIGNED_ROLE]->(entry)\n"
        "RETURN DISTINCT u.username AS user, g.groupname AS via_group,\n"
        "       'role_chain' AS access_via, null AS permission_set,\n"
        "       role.rolename AS iam_role, role.source AS role_source,\n"
        "       r.`~id` AS resource, f.action AS granted_actions,\n"
        "       length(chain) AS chain_hops,\n"
        "       [n IN nodes(chain) | n.`~id`] AS chain_arns,\n"
        "       [n IN nodes(chain) | n.rolename] AS chain_roles\n"
        "LIMIT 50"
    )

    query = (
        f"{ps_branch}\nUNION\n{role_branch}\n"
        f"UNION\n{chain_ps_branch}\nUNION\n{chain_role_branch}"
    )
    return query, params


def who_can_access(
    resource: str, actions: list[str] | None, max_hops: int = DEFAULT_HOPS
) -> tuple[str, dict[str, Any]]:
    """Every human principal that can reach a resource, optional action filter.

    Returns one row per (principal, role, route). Covers THREE routes to the
    granting role and UNIONs them:
      - permission_set: principal -> PermissionSet -> Role -> resource
      - direct_role:    principal -[:ASSIGNED_ROLE]-> Role -> resource
      - role_chain:     Entry_Role -[:CAN_ASSUME*1..N]-> Role -> resource,
                        with the Entry_Role itself reached via a permission set
                        or directly, same as above
    `access_via` distinguishes the routes, `via_group` names the group when
    access is inherited through group membership (null when assigned directly),
    and `permission_set` is null for the direct-role route and for the
    role-chain arm reached via a direct role. `chain_hops`, `chain_arns`, and
    `chain_roles` are null on the permission_set/direct_role rows (required for
    UNION column-compatibility) and populated on role_chain rows. `max_hops`
    bounds the role_chain route's CAN_ASSUME traversal depth via
    effective_hops(); it has no effect on the other two routes.
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
    eff = effective_hops(max_hops)

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
        "       g.groupname AS via_group,\n"
        "       null AS chain_hops, null AS chain_arns, null AS chain_roles\n"
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
        "       g.groupname AS via_group,\n"
        "       null AS chain_hops, null AS chain_arns, null AS chain_roles\n"
        "LIMIT 100"
    )

    chain_ps_branch = (
        f"{base}"
        f"MATCH chain = (entry:RoleName)-[:CAN_ASSUME*1..{eff}]->(role)\n"
        "MATCH (ps:PermissionSet)-[:CREATED_AS]->(entry)\n"
        "MATCH (u:UserName)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps)\n"
        "OPTIONAL MATCH (g:GroupName)-[:HAS_MEMBERS]->(u)\n"
        "WHERE (g)-[:ASSIGNED_PERMISSIONSET]->(ps)\n"
        "RETURN DISTINCT r.`~id` AS resource, role.rolename AS iam_role,\n"
        "       role.source AS role_source, 'role_chain' AS access_via,\n"
        "       ps.name AS permission_set, u.username AS principal,\n"
        "       g.groupname AS via_group,\n"
        "       length(chain) AS chain_hops,\n"
        "       [n IN nodes(chain) | n.`~id`] AS chain_arns,\n"
        "       [n IN nodes(chain) | n.rolename] AS chain_roles\n"
        "LIMIT 100"
    )

    chain_role_branch = (
        f"{base}"
        f"MATCH chain = (entry:RoleName)-[:CAN_ASSUME*1..{eff}]->(role)\n"
        "MATCH (u:UserName)-[:ASSIGNED_ROLE|HAS_MEMBERS*1..2]-(entry)\n"
        "OPTIONAL MATCH (g:GroupName)-[:HAS_MEMBERS]->(u)\n"
        "WHERE (g)-[:ASSIGNED_ROLE]->(entry)\n"
        "RETURN DISTINCT r.`~id` AS resource, role.rolename AS iam_role,\n"
        "       role.source AS role_source, 'role_chain' AS access_via,\n"
        "       null AS permission_set, u.username AS principal,\n"
        "       g.groupname AS via_group,\n"
        "       length(chain) AS chain_hops,\n"
        "       [n IN nodes(chain) | n.`~id`] AS chain_arns,\n"
        "       [n IN nodes(chain) | n.rolename] AS chain_roles\n"
        "LIMIT 100"
    )

    query = (
        f"{ps_branch}\nUNION\n{role_branch}\n"
        f"UNION\n{chain_ps_branch}\nUNION\n{chain_role_branch}"
    )
    return query, params


def principal_access_report(
    principal: str, account: str | None, max_hops: int = DEFAULT_HOPS
) -> tuple[str, dict[str, Any]]:
    """Everything a user can reach, optionally scoped to one account name.

    Covers THREE access routes and UNIONs them so they never cross-join:
      - permission_set: principal -> PermissionSet -> (Account / Role -> Resource)
      - direct_role:    principal -[:ASSIGNED_ROLE]-> Role
                        -[:EXISTS_IN|CREATED_IN]-> Account,
                        -[:GRANTS_ACCESS_TO]-> Resource
      - role_chain:     principal -> (PermissionSet or direct) -> Entry_Role
                        -[:CAN_ASSUME*1..N]-> Role -[:GRANTS_ACCESS_TO]-> Resource

    Each row is tagged with `access_via`; `permission_set` is null on the
    direct-role route and on the role-chain arm reached via a direct role.
    `account` is where the access lands - the account the granting role lives
    in (CREATED_IN for the IdC route, EXISTS_IN/CREATED_IN for the direct route
    and for the role-chain routes); `resource` / `resource_account` describe
    the reachable critical resource (null when the grant is account-level only
    on the permission_set/direct_role routes; the role-chain routes always
    require a resource, since chaining without ever reaching a resource isn't
    a reportable access path). Every route allows the optional group hop via
    HAS_MEMBERS. `chain_hops`, `chain_arns`, and `chain_roles` are null on the
    permission_set/direct_role rows (required for UNION column-compatibility)
    and populated on role_chain rows. `max_hops` bounds the role_chain route's
    CAN_ASSUME traversal depth via effective_hops(); it has no effect on the
    other two routes.

    Deriving the account from the granting role (not from the permission set's
    PROVISIONED_INTO edges) matters: a permission set provisioned into many
    accounts would otherwise cross-join every one of those accounts with every
    resource the role grants, multiplying rows and blowing the LIMIT. Each SSO
    role instance lives in exactly one account, so CREATED_IN keeps one row per
    (role, resource).

    Matching the two routes as two independent OPTIONAL MATCH chains off the same
    user produces a cartesian product (every permission-set row crossed with every
    direct-role row), which both smears bogus duplicate data across rows and
    exhausts the LIMIT with junk. UNIONing the routes - as find_access_paths and
    who_can_access already do - avoids that.
    """
    params: dict[str, Any] = {"principal": principal}
    account_clause = ""
    if account:
        params["account"] = account
        # Unambiguous now: match either the account the access lands in or the
        # account that owns the reachable resource - not three ORed meanings.
        account_clause = (
            "WHERE acct.name CONTAINS $account\n"
            "   OR resacct.name CONTAINS $account\n"
        )
    eff = effective_hops(max_hops)

    ps_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (u)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps:PermissionSet)\n"
        "OPTIONAL MATCH (ps)-[:CREATED_AS]->(role:RoleName)\n"
        "OPTIONAL MATCH (role)-[:CREATED_IN]->(acct:AccountName)\n"
        "OPTIONAL MATCH (role)-[:GRANTS_ACCESS_TO]->(res:CriticalResources)"
        "-[:BELONGS_TO]->(resacct:AccountName)\n"
        f"{account_clause}"
        "RETURN DISTINCT u.username AS user, 'permission_set' AS access_via,\n"
        "       ps.name AS permission_set, role.rolename AS iam_role,\n"
        "       role.source AS role_source, acct.name AS account,\n"
        "       res.`~id` AS resource, resacct.name AS resource_account,\n"
        "       null AS chain_hops, null AS chain_arns, null AS chain_roles\n"
        "LIMIT 200"
    )

    role_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (u)-[:ASSIGNED_ROLE|HAS_MEMBERS*1..2]-(role:RoleName)\n"
        "OPTIONAL MATCH (role)-[:EXISTS_IN|CREATED_IN]->(acct:AccountName)\n"
        "OPTIONAL MATCH (role)-[:GRANTS_ACCESS_TO]->(res:CriticalResources)"
        "-[:BELONGS_TO]->(resacct:AccountName)\n"
        f"{account_clause}"
        "RETURN DISTINCT u.username AS user, 'direct_role' AS access_via,\n"
        "       null AS permission_set, role.rolename AS iam_role,\n"
        "       role.source AS role_source, acct.name AS account,\n"
        "       res.`~id` AS resource, resacct.name AS resource_account,\n"
        "       null AS chain_hops, null AS chain_arns, null AS chain_roles\n"
        "LIMIT 200"
    )

    chain_ps_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (u)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps:PermissionSet)\n"
        "MATCH (ps)-[:CREATED_AS]->(entry:RoleName)\n"
        f"MATCH chain = (entry)-[:CAN_ASSUME*1..{eff}]->(role:RoleName)\n"
        "MATCH (role)-[:GRANTS_ACCESS_TO]->(res:CriticalResources)"
        "-[:BELONGS_TO]->(resacct:AccountName)\n"
        "OPTIONAL MATCH (role)-[:EXISTS_IN|CREATED_IN]->(acct:AccountName)\n"
        f"{account_clause}"
        "RETURN DISTINCT u.username AS user, 'role_chain' AS access_via,\n"
        "       ps.name AS permission_set, role.rolename AS iam_role,\n"
        "       role.source AS role_source, acct.name AS account,\n"
        "       res.`~id` AS resource, resacct.name AS resource_account,\n"
        "       length(chain) AS chain_hops,\n"
        "       [n IN nodes(chain) | n.`~id`] AS chain_arns,\n"
        "       [n IN nodes(chain) | n.rolename] AS chain_roles\n"
        "LIMIT 200"
    )

    chain_role_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (u)-[:ASSIGNED_ROLE|HAS_MEMBERS*1..2]-(entry:RoleName)\n"
        f"MATCH chain = (entry)-[:CAN_ASSUME*1..{eff}]->(role:RoleName)\n"
        "MATCH (role)-[:GRANTS_ACCESS_TO]->(res:CriticalResources)"
        "-[:BELONGS_TO]->(resacct:AccountName)\n"
        "OPTIONAL MATCH (role)-[:EXISTS_IN|CREATED_IN]->(acct:AccountName)\n"
        f"{account_clause}"
        "RETURN DISTINCT u.username AS user, 'role_chain' AS access_via,\n"
        "       null AS permission_set, role.rolename AS iam_role,\n"
        "       role.source AS role_source, acct.name AS account,\n"
        "       res.`~id` AS resource, resacct.name AS resource_account,\n"
        "       length(chain) AS chain_hops,\n"
        "       [n IN nodes(chain) | n.`~id`] AS chain_arns,\n"
        "       [n IN nodes(chain) | n.rolename] AS chain_roles\n"
        "LIMIT 200"
    )

    query = (
        f"{ps_branch}\nUNION\n{role_branch}\n"
        f"UNION\n{chain_ps_branch}\nUNION\n{chain_role_branch}"
    )
    return query, params


def principal_access_summary(
    principal: str, account: str | None, max_hops: int = DEFAULT_HOPS
) -> tuple[str, dict[str, Any]]:
    """Compact roll-up of what a user can reach, grouped by route and grant.

    Same THREE-route coverage as principal_access_report, but instead of one
    row per reachable resource it returns one row per (access_via, grant,
    iam_role) with a `resource_count` and the deduplicated `resources` list.
    This is the readable shape for wide-access principals, where the
    per-resource report runs to hundreds of rows. `grant` is the permission-set
    name on the IdC route, the role's `source` (e.g. AccountAccessManager) on
    the direct route, and the Entry_Role's originating entitlement (permission
    set name or `source`) on the role_chain route.

    Only rows with at least one reachable critical resource are returned; scope
    to an account via `account` (matched against the resource's owning account).
    `max_hops` bounds the role_chain route's CAN_ASSUME traversal depth via
    effective_hops(); it has no effect on the other two routes. Hop count and
    chain roles are not surfaced here: a single grouped row can be reached by
    chains of different lengths across different resources, so a per-row hop
    count would not have a well-defined value once grouped.
    """
    params: dict[str, Any] = {"principal": principal}
    account_clause = ""
    if account:
        params["account"] = account
        account_clause = "  AND acct.name CONTAINS $account\n"
    eff = effective_hops(max_hops)

    ps_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (u)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps:PermissionSet)\n"
        "MATCH (ps)-[:CREATED_AS]->(role:RoleName)"
        "-[:GRANTS_ACCESS_TO]->(res:CriticalResources)-[:BELONGS_TO]->(acct:AccountName)\n"
        "WHERE res IS NOT NULL\n"
        f"{account_clause}"
        "RETURN 'permission_set' AS access_via, ps.name AS grant,\n"
        "       role.rolename AS iam_role, res.`~id` AS resource"
    )

    role_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (u)-[:ASSIGNED_ROLE|HAS_MEMBERS*1..2]-(role:RoleName)\n"
        "MATCH (role)-[:GRANTS_ACCESS_TO]->(res:CriticalResources)"
        "-[:BELONGS_TO]->(acct:AccountName)\n"
        "WHERE res IS NOT NULL\n"
        f"{account_clause}"
        "RETURN 'direct_role' AS access_via, role.source AS grant,\n"
        "       role.rolename AS iam_role, res.`~id` AS resource"
    )

    chain_ps_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (u)-[:ASSIGNED_PERMISSIONSET|HAS_MEMBERS*1..2]-(ps:PermissionSet)\n"
        "MATCH (ps)-[:CREATED_AS]->(entry:RoleName)\n"
        f"MATCH (entry)-[:CAN_ASSUME*1..{eff}]->(role:RoleName)\n"
        "MATCH (role)-[:GRANTS_ACCESS_TO]->(res:CriticalResources)"
        "-[:BELONGS_TO]->(acct:AccountName)\n"
        "WHERE res IS NOT NULL\n"
        f"{account_clause}"
        "RETURN 'role_chain' AS access_via, ps.name AS grant,\n"
        "       role.rolename AS iam_role, res.`~id` AS resource"
    )

    chain_role_branch = (
        "MATCH (u:UserName)\n"
        "WHERE toLower(u.username) CONTAINS toLower($principal)\n"
        "MATCH (u)-[:ASSIGNED_ROLE|HAS_MEMBERS*1..2]-(entry:RoleName)\n"
        f"MATCH (entry)-[:CAN_ASSUME*1..{eff}]->(role:RoleName)\n"
        "MATCH (role)-[:GRANTS_ACCESS_TO]->(res:CriticalResources)"
        "-[:BELONGS_TO]->(acct:AccountName)\n"
        "WHERE res IS NOT NULL\n"
        f"{account_clause}"
        "RETURN 'role_chain' AS access_via, entry.source AS grant,\n"
        "       role.rolename AS iam_role, res.`~id` AS resource"
    )

    query = (
        "CALL {\n"
        f"{ps_branch}\n"
        "UNION\n"
        f"{role_branch}\n"
        "UNION\n"
        f"{chain_ps_branch}\n"
        "UNION\n"
        f"{chain_role_branch}\n"
        "}\n"
        "RETURN access_via, grant, iam_role,\n"
        "       count(DISTINCT resource) AS resource_count,\n"
        "       collect(DISTINCT resource) AS resources\n"
        "ORDER BY access_via, grant"
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
    """List nodes of one kind. `entity` is a key of _ENTITY_MAP.

    Accepted keywords: users, groups, permissionsets, accounts, roles,
    assumableroles, resources, externalprincipals. `assumableroles` enumerates
    RoleName nodes that are the TARGET of at least one CAN_ASSUME edge (i.e.
    roles that some principal is trusted to assume).
    """
    key = entity.lower().strip()
    if key not in _ENTITY_MAP:
        raise ValueError(
            f"Unknown entity '{entity}'. Choose one of: {', '.join(sorted(_ENTITY_MAP))}."
        )
    label, prop = _ENTITY_MAP[key]
    if key == "assumableroles":
        # Roles that are the TARGET of at least one CAN_ASSUME edge.
        query = (
            "MATCH ()-[:CAN_ASSUME]->(n:RoleName)\n"
            "RETURN DISTINCT n.rolename AS value, n.`~id` AS arn,\n"
            "       n.accountid AS account\n"
            "ORDER BY value\n"
            "LIMIT $limit"
        )
        return query, {"limit": limit}
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


def role_assumption_paths(
    role: str, direction: str = "backward", max_hops: int = DEFAULT_HOPS
) -> tuple[str, dict[str, Any]]:
    """Bounded role-to-role CAN_ASSUME traversal, in one of two directions.

    Centers on role-to-role trust chaining: both endpoints are RoleName nodes
    (keyed on the IAM role ARN), so chains of CAN_ASSUME edges connect existing
    nodes and traverse reliably.

    backward (default): anchors the TARGET endpoint by role ARN substring and
    walks CAN_ASSUME edges toward it - "which roles can ultimately assume the
    target role".
    forward: anchors the SOURCE endpoint and walks CAN_ASSUME edges away from it
    - "which roles can this source role reach by assuming onward".

    The role substring is matched case-insensitively against the anchored
    endpoint's `~id` (an ARN) and carried ONLY in the $role parameter - never
    string-interpolated. `max_hops` is clamped to a bounded integer via
    effective_hops and interpolated into the variable-length pattern bound
    (variable-length bounds cannot be parameters).
    """
    eff = effective_hops(max_hops)
    if direction == "forward":
        query = (
            f"MATCH path = (source:RoleName)-[:CAN_ASSUME*1..{eff}]->(reached:RoleName)\n"
            "WHERE toLower(source.`~id`) CONTAINS toLower($role)\n"
            "RETURN DISTINCT\n"
            "       source.rolename AS from_role, source.`~id` AS from_arn,\n"
            "       reached.rolename AS to_role, reached.`~id` AS to_arn,\n"
            "       length(path) AS hops,\n"
            "       [n IN nodes(path) | n.`~id`] AS chain_arns,\n"
            "       [n IN nodes(path) | n.rolename] AS chain_roles\n"
            "ORDER BY hops\n"
            "LIMIT 100"
        )
    else:
        query = (
            f"MATCH path = (start:RoleName)-[:CAN_ASSUME*1..{eff}]->(target:RoleName)\n"
            "WHERE toLower(target.`~id`) CONTAINS toLower($role)\n"
            "RETURN DISTINCT\n"
            "       start.rolename AS from_role, start.`~id` AS from_arn,\n"
            "       target.rolename AS to_role, target.`~id` AS to_arn,\n"
            "       length(path) AS hops,\n"
            "       [n IN nodes(path) | n.`~id`] AS chain_arns,\n"
            "       [n IN nodes(path) | n.rolename] AS chain_roles\n"
            "ORDER BY hops\n"
            "LIMIT 100"
        )
    return query, {"role": role}
