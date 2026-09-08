"""Unit + property tests for the role-chaining query builders.

Feature: mcp-role-chaining-support (Requirement 7).

Runner: Python standard-library ``unittest`` ONLY. No third-party dependency is
added (no pytest, no hypothesis). The "property" tests are realized with in-test
randomized generation: a fixed random seed (for reproducibility) plus a loop of
>= 100 generated cases per property.

Discovery / imports
-------------------
This module is designed to run both as::

    python -m unittest discover -s mcp-server/tests        # from repo root
    python -m unittest                                     # from within mcp-server/
    python -m unittest tests.test_queries                  # from within mcp-server/

``aria_mcp_server`` lives one directory up from ``tests/``. To make it importable
regardless of the current working directory, we prepend the ``mcp-server`` dir
(the parent of this file's directory) to ``sys.path`` at import time.

``queries.py`` imports only ``typing`` and is safe to import directly.

``graph_client.py`` imports ``boto3`` at module top. In environments without
boto3 (the plain-python3 test environment here), a normal
``from aria_mcp_server.graph_client import assert_read_only`` raises ImportError.
To keep the suite import-safe AND to validate against the REAL guard rather than
a re-typed copy, we:

  1. try the normal import first, and
  2. on ImportError, load ONLY the ``assert_read_only`` + ``ReadOnlyViolation`` +
     the module-level mutating regexes from the ``graph_client.py`` SOURCE via
     ``ast`` + ``exec`` of exactly those definitions.

Either way the tests exercise the same regex-based guard that ships in
``graph_client.py``.
"""

from __future__ import annotations

import ast
import os
import random
import re
import sys
import unittest

# --- make aria_mcp_server importable regardless of CWD ---------------------
# This file is at <mcp-server>/tests/test_queries.py; its grandparent is
# <mcp-server>, which contains the aria_mcp_server package.
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_MCP_SERVER_DIR = os.path.dirname(_TESTS_DIR)
if _MCP_SERVER_DIR not in sys.path:
    sys.path.insert(0, _MCP_SERVER_DIR)

from aria_mcp_server import queries  # noqa: E402  (path setup must come first)


# --- load the REAL assert_read_only / ReadOnlyViolation --------------------
def _load_read_only_guard():
    """Return (assert_read_only, ReadOnlyViolation) from the real source.

    Prefers the normal import. Falls back to extracting just the guard-relevant
    definitions from graph_client.py source when boto3 (a module-top import in
    graph_client.py) is unavailable, so the suite never depends on boto3 while
    still validating the shipped guard.
    """
    try:
        from aria_mcp_server.graph_client import (  # type: ignore
            ReadOnlyViolation,
            assert_read_only,
        )

        return assert_read_only, ReadOnlyViolation
    except ImportError:
        pass

    # Fallback: parse graph_client.py and exec only the definitions the guard
    # needs (the two exception classes, the two module regexes, the tuple of
    # mutating clauses, and assert_read_only). This avoids importing boto3.
    source_path = os.path.join(_MCP_SERVER_DIR, "aria_mcp_server", "graph_client.py")
    with open(source_path, "r", encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=source_path)

    wanted_names = {
        "GraphError",
        "ReadOnlyViolation",
        "_MUTATING_CLAUSES",
        "_MUTATING_RE",
        "_FORBIDDEN_CALL_RE",
        "assert_read_only",
    }
    selected: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in wanted_names:
            selected.append(node)
        elif isinstance(node, ast.Assign):
            targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if targets & wanted_names:
                selected.append(node)

    module = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace: dict = {"re": re, "Exception": Exception}
    exec(compile(module, source_path, "exec"), namespace)  # noqa: S102
    return namespace["assert_read_only"], namespace["ReadOnlyViolation"]


assert_read_only, ReadOnlyViolation = _load_read_only_guard()


# --- shared generators -----------------------------------------------------
# Fixed seed so each run generates the same >=100 cases (reproducible failures).
_SEED = 1337
_ITERATIONS = 100

# Role substrings that include openCypher keywords and metacharacters, used to
# prove the substring is parameterized (never interpolated into the query text).
_HOSTILE_ROLE_SUBSTRINGS = [
    "DELETE me",
    "a) RETURN",
    "x*",
    "role' OR '1'='1",
    'role" DROP',
    "role`~id`",
    "MATCH (n) DETACH DELETE n",
    "SET x = 1",
    "CREATE (n)",
    "MERGE (m)",
    "neptune.reset",
    "*1..99",
    "arn:aws:iam::123456789012:role/Admin",
    "; //",
    "LOAD CSV",
]

_BENIGN_ROLE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/:"


def _random_role(rng: random.Random) -> str:
    """Pick either a hostile substring or a random benign one."""
    if rng.random() < 0.4:
        return rng.choice(_HOSTILE_ROLE_SUBSTRINGS)
    length = rng.randint(1, 24)
    return "".join(rng.choice(_BENIGN_ROLE_CHARS) for _ in range(length))


def _random_resource(rng: random.Random) -> str:
    """Pick either a hostile substring or a random benign one (resource ARN
    substring). Mirrors ``_random_role``; used by the role-chaining-detection
    property tests (feature: role-chaining-detection) to exercise the
    ``$resource`` substring under adversarial input.
    """
    if rng.random() < 0.4:
        return rng.choice(_HOSTILE_ROLE_SUBSTRINGS)
    length = rng.randint(1, 24)
    return "".join(rng.choice(_BENIGN_ROLE_CHARS) for _ in range(length))


def _random_account(rng: random.Random) -> str:
    """Pick either a hostile substring or a random benign one (account name
    substring). Mirrors ``_random_role``; used by the role-chaining-detection
    property tests (feature: role-chaining-detection) to exercise the
    ``$account`` substring under adversarial input.
    """
    if rng.random() < 0.4:
        return rng.choice(_HOSTILE_ROLE_SUBSTRINGS)
    length = rng.randint(1, 24)
    return "".join(rng.choice(_BENIGN_ROLE_CHARS) for _ in range(length))


def _expected_eff(max_hops: int) -> int:
    return min(max(int(max_hops), 1), queries.MAX_HOPS_CAP)


class QueryShapeTests(unittest.TestCase):
    """Task 5.1 - example-based query-shape assertions (non-optional core).

    Asserts role_assumption_paths generated text uses the RoleName label, the
    CAN_ASSUME edge, the direction-appropriate orientation, the bounded
    CAN_ASSUME*1..N pattern, and a LIMIT clause. (Req 7.2, 7.3, 7.4)
    """

    def test_backward_shape(self):
        query, params = queries.role_assumption_paths(
            "Admin", direction="backward", max_hops=5
        )
        # RoleName label present on both endpoints (Req 7.2).
        self.assertIn(":RoleName", query)
        self.assertEqual(query.count(":RoleName"), 2)
        # CAN_ASSUME edge present (Req 7.2).
        self.assertIn("CAN_ASSUME", query)
        # Bounded variable-length pattern (Req 7.3).
        self.assertIn("CAN_ASSUME*1..5", query)
        # LIMIT clause present (Req 7.4).
        self.assertIn("LIMIT", query)
        # Backward orientation: the $role predicate anchors the TARGET endpoint.
        self.assertIn("(target:RoleName)", query)
        self.assertIn("toLower(target.`~id`) CONTAINS toLower($role)", query)
        self.assertEqual(params, {"role": "Admin"})

    def test_forward_shape(self):
        query, params = queries.role_assumption_paths(
            "Admin", direction="forward", max_hops=5
        )
        self.assertIn(":RoleName", query)
        self.assertEqual(query.count(":RoleName"), 2)
        self.assertIn("CAN_ASSUME*1..5", query)
        self.assertIn("LIMIT", query)
        # Forward orientation: the $role predicate anchors the SOURCE endpoint.
        self.assertIn("(source:RoleName)", query)
        self.assertIn("toLower(source.`~id`) CONTAINS toLower($role)", query)
        self.assertEqual(params, {"role": "Admin"})

    def test_edge_direction_arrow_present(self):
        # The traversal orientation is the forward arrow on the CAN_ASSUME edge.
        for direction in ("backward", "forward"):
            query, _ = queries.role_assumption_paths("r", direction=direction)
            self.assertRegex(query, r"-\[:CAN_ASSUME\*1\.\.\d+\]->")


class Property1DirectionalPatternTests(unittest.TestCase):
    """Feature: mcp-role-chaining-support, Property 1: Directional chaining
    pattern is well-formed and role-to-role.

    For any role substring, any direction in {backward, forward}, and any integer
    max_hops: both endpoints are RoleName, the CAN_ASSUME*1..N pattern is present,
    length(path) + a per-node chain projection are present, a LIMIT is present,
    and the $role predicate anchors the target endpoint (backward) or the source
    endpoint (forward).

    Validates: Requirements 2.2, 2.4, 2.6, 3.1, 3.2, 4.5, 5.1
    """

    def test_property_1(self):
        rng = random.Random(_SEED)
        iterations = 0
        for _ in range(_ITERATIONS):
            role = _random_role(rng)
            direction = rng.choice(["backward", "forward"])
            max_hops = rng.randint(-5, 15)
            query, params = queries.role_assumption_paths(
                role, direction=direction, max_hops=max_hops
            )
            eff = _expected_eff(max_hops)

            # (5.1) returns a (query, params) pair; params carries role only.
            self.assertIsInstance(query, str)
            self.assertEqual(params, {"role": role})

            # (2.6, 3.1) role-to-role: both endpoints RoleName.
            self.assertEqual(query.count(":RoleName"), 2)

            # (4.1/4.5-shape) bounded CAN_ASSUME*1..N with N == eff.
            self.assertIn(f"CAN_ASSUME*1..{eff}", query)
            self.assertRegex(query, r"-\[:CAN_ASSUME\*1\.\.\d+\]->")

            # (2.4) path / hop projection.
            self.assertIn("length(path) AS hops", query)
            self.assertIn("[n IN nodes(path) | n.`~id`] AS chain_arns", query)
            self.assertIn("[n IN nodes(path) | n.rolename] AS chain_roles", query)

            # (4.5) LIMIT present.
            self.assertIn("LIMIT", query)

            # (2.2 / 3.2) direction-appropriate anchoring.
            if direction == "forward":
                self.assertIn(
                    "toLower(source.`~id`) CONTAINS toLower($role)", query
                )
                self.assertIn("(source:RoleName)", query)
            else:
                self.assertIn(
                    "toLower(target.`~id`) CONTAINS toLower($role)", query
                )
                self.assertIn("(target:RoleName)", query)

            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(f"\n[Property 1] executed {iterations} generated cases")


class Property2HopBoundTests(unittest.TestCase):
    """Feature: mcp-role-chaining-support, Property 2: Effective hop bound is a
    clamped integer in [1, MAX_HOPS_CAP].

    For any max_hops sampled across <1, 1..CAP, and >CAP (plus some non-int/None
    values), the pattern is exactly CAN_ASSUME*1..N with
    N == min(max(int(max_hops), 1), MAX_HOPS_CAP); N == CAP when exceeded, N == 1
    when below 1, and N is always an integer within [1, MAX_HOPS_CAP].

    Validates: Requirements 4.1, 4.3, 4.4, 5.3, 7.7
    """

    def test_property_2(self):
        rng = random.Random(_SEED + 1)
        cap = queries.MAX_HOPS_CAP
        pattern = re.compile(r"CAN_ASSUME\*1\.\.(\d+)")
        iterations = 0
        for _ in range(_ITERATIONS):
            bucket = rng.choice(["below", "inrange", "above"])
            if bucket == "below":
                max_hops = rng.randint(-20, 0)
            elif bucket == "inrange":
                max_hops = rng.randint(1, cap)
            else:
                max_hops = rng.randint(cap + 1, cap + 50)

            direction = rng.choice(["backward", "forward"])
            query, _ = queries.role_assumption_paths(
                "role", direction=direction, max_hops=max_hops
            )

            matches = pattern.findall(query)
            # Exactly one CAN_ASSUME*1..N pattern.
            self.assertEqual(len(matches), 1)
            n = int(matches[0])

            expected = _expected_eff(max_hops)
            self.assertEqual(n, expected)
            # Invariant: N within [1, CAP].
            self.assertGreaterEqual(n, 1)
            self.assertLessEqual(n, cap)
            if max_hops > cap:
                self.assertEqual(n, cap)
            if max_hops < 1:
                self.assertEqual(n, 1)

            iterations += 1

        # Additionally exercise non-int / None values -> default hops, clamped.
        for bad in [None, "abc", 3.9, "7", float("nan")]:
            query, _ = queries.role_assumption_paths("role", max_hops=bad)
            matches = pattern.findall(query)
            self.assertEqual(len(matches), 1)
            n = int(matches[0])
            self.assertGreaterEqual(n, 1)
            self.assertLessEqual(n, cap)
            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(f"\n[Property 2] executed {iterations} generated cases")


class Property3ParameterizationTests(unittest.TestCase):
    """Feature: mcp-role-chaining-support, Property 3: Role substring is
    parameterized, case-insensitive, and never interpolated.

    For any role substring (including openCypher keywords/metacharacters):
    params["role"] equals the substring unchanged, the raw substring is ABSENT
    from the query text, and the predicate is
    toLower(<endpoint>.`~id`) CONTAINS toLower($role).

    Validates: Requirements 2.3, 3.3, 5.2, 7.5
    """

    def test_property_3(self):
        rng = random.Random(_SEED + 2)
        iterations = 0

        # Every hostile substring (openCypher keywords / metacharacters) is
        # forced through at least once - these are the injection-relevant cases
        # that MUST NOT leak into the query text. The remaining iterations use a
        # distinctive-marker generator: each benign role carries a "ZzMarker_"
        # prefix that cannot appear in the fixed query scaffolding, so the
        # "raw substring absent" assertion is meaningful rather than tripping on
        # a trivial one-character collision with words like `rolename`/`length`.
        forced = list(_HOSTILE_ROLE_SUBSTRINGS)
        for i in range(_ITERATIONS):
            if i < len(forced):
                role = forced[i]
            else:
                suffix = "".join(
                    rng.choice(_BENIGN_ROLE_CHARS) for _ in range(rng.randint(1, 24))
                )
                role = f"ZzMarker_{suffix}"
            direction = rng.choice(["backward", "forward"])
            query, params = queries.role_assumption_paths(role, direction=direction)

            # (5.2/7.5) substring carried unchanged in params.
            self.assertEqual(params["role"], role)

            # (2.3/3.3) case-insensitive predicate on the anchored endpoint.
            endpoint = "source" if direction == "forward" else "target"
            predicate = f"toLower({endpoint}.`~id`) CONTAINS toLower($role)"
            self.assertIn(predicate, query)

            # (5.2/7.5) raw caller value absent from the query text - it travels
            # only in params. The lone exception is the degenerate case where the
            # caller value IS the parameter token "$role", asserted separately
            # in test_value_equal_to_placeholder_still_parameterized.
            if role != "$role":
                self.assertNotIn(role, query)

            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(f"\n[Property 3] executed {iterations} generated cases")

    def test_value_equal_to_placeholder_still_parameterized(self):
        # Degenerate injection case: caller value == the parameter token.
        # It must still be carried in params (bound separately by the driver),
        # and the query text contains only the single fixed "$role" reference.
        query, params = queries.role_assumption_paths("$role", direction="backward")
        self.assertEqual(params["role"], "$role")
        # Exactly one "$role" occurrence: the query's own parameter reference.
        self.assertEqual(query.count("$role"), 1)


class Property4ReadOnlyGuardTests(unittest.TestCase):
    """Feature: mcp-role-chaining-support, Property 4: Generated chaining query
    passes the read-only guard.

    For any role substring, any direction, and any integer max_hops,
    assert_read_only(query) does not raise ReadOnlyViolation.

    Validates: Requirements 5.4, 7.6
    """

    def test_property_4(self):
        rng = random.Random(_SEED + 3)
        iterations = 0
        for _ in range(_ITERATIONS):
            role = _random_role(rng)
            direction = rng.choice(["backward", "forward"])
            max_hops = rng.randint(-5, 15)
            query, _ = queries.role_assumption_paths(
                role, direction=direction, max_hops=max_hops
            )
            try:
                assert_read_only(query)
            except ReadOnlyViolation as exc:  # pragma: no cover - failure path
                self.fail(
                    f"assert_read_only raised for role={role!r} "
                    f"direction={direction!r} max_hops={max_hops!r}: {exc}"
                )
            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(f"\n[Property 4] executed {iterations} generated cases")


class Property5AssumableRolesTests(unittest.TestCase):
    """Feature: mcp-role-chaining-support, Property 5: Assumable-trust-roles
    listing targets CAN_ASSUME and is read-only.

    For any limit, list_entities("assumableroles", limit) text contains a
    CAN_ASSUME edge terminating at a RoleName node and RETURN DISTINCT, carries
    the limit under $limit, and passes assert_read_only.

    Validates: Requirements 6.1, 6.2, 7.6
    """

    def test_property_5(self):
        rng = random.Random(_SEED + 4)
        iterations = 0
        for _ in range(_ITERATIONS):
            limit = rng.randint(0, 100000)
            query, params = queries.list_entities("assumableroles", limit)

            # (6.1/6.2) CAN_ASSUME edge terminating at a RoleName node.
            self.assertRegex(query, r"-\[:CAN_ASSUME\]->\(n:RoleName\)")
            self.assertIn("RETURN DISTINCT", query)

            # limit carried under $limit.
            self.assertEqual(params, {"limit": limit})
            self.assertIn("$limit", query)

            # (7.6) read-only guard passes.
            try:
                assert_read_only(query)
            except ReadOnlyViolation as exc:  # pragma: no cover - failure path
                self.fail(f"assert_read_only raised for limit={limit!r}: {exc}")

            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(f"\n[Property 5] executed {iterations} generated cases")


class RoleChainFindAccessPathsPropertyTests(unittest.TestCase):
    """Feature: role-chaining-detection, Property 1: find_access_paths
    role_chain route is well-formed, filter-consistent, and role-to-role.

    For any principal substring, any resource substring, any optional actions
    list, and any max_hops: queries.find_access_paths returns query text
    containing at least one arm tagged 'role_chain' AS access_via whose pattern
    includes a bounded CAN_ASSUME*1..N traversal between two RoleName
    endpoints, a chain_hops column, chain_arns and chain_roles columns, and a
    LIMIT clause; that arm references the same $principal / $resource / (when
    supplied) $actions parameters the existing permission_set and direct_role
    arms already reference.

    Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.6
    """

    def test_property_1(self):
        rng = random.Random(_SEED + 10)
        pattern = re.compile(r"CAN_ASSUME\*1\.\.(\d+)")
        iterations = 0
        for _ in range(_ITERATIONS):
            principal = _random_role(rng)
            resource = _random_resource(rng)

            actions_bucket = rng.random()
            if actions_bucket < 0.5:
                actions = None
            else:
                n_actions = rng.randint(1, 3)
                actions = [
                    rng.choice(
                        [
                            "s3:GetObject",
                            "iam:PassRole",
                            "sts:AssumeRole",
                            "DELETE me",
                            "action' OR '1'='1",
                        ]
                    )
                    for _ in range(n_actions)
                ]

            hops_bucket = rng.choice(["below", "inrange", "above", "omitted"])
            if hops_bucket == "below":
                max_hops = rng.randint(-20, 0)
                query, params = queries.find_access_paths(
                    principal, resource, actions, max_hops
                )
            elif hops_bucket == "inrange":
                max_hops = rng.randint(1, queries.MAX_HOPS_CAP)
                query, params = queries.find_access_paths(
                    principal, resource, actions, max_hops
                )
            elif hops_bucket == "above":
                max_hops = rng.randint(queries.MAX_HOPS_CAP + 1, queries.MAX_HOPS_CAP + 50)
                query, params = queries.find_access_paths(
                    principal, resource, actions, max_hops
                )
            else:
                # Omitted -> exercise the default parameter.
                query, params = queries.find_access_paths(principal, resource, actions)
                max_hops = queries.DEFAULT_HOPS

            eff = _expected_eff(max_hops)

            # (1.2) role_chain tag present.
            self.assertIn("'role_chain' AS access_via", query)

            # (1.1, 1.3) bounded CAN_ASSUME*1..N between two RoleName endpoints,
            # within a role_chain arm. There are two role_chain arms in this
            # builder (chain_ps_branch / chain_role_branch), each with its own
            # CAN_ASSUME*1..N occurrence at the clamped eff value.
            self.assertIn(f"CAN_ASSUME*1..{eff}", query)
            matches = pattern.findall(query)
            self.assertTrue(len(matches) >= 1)
            for n in matches:
                self.assertEqual(int(n), eff)

            # Both role_chain arms traverse between two RoleName-labelled
            # endpoints (entry and role).
            self.assertRegex(
                query, r"\(entry:RoleName\)\n?MATCH chain = \(entry\)-\[:CAN_ASSUME\*1\.\.\d+\]->\(role:RoleName\)"
            )

            # (1.3) chain_hops / chain_arns / chain_roles columns.
            self.assertIn("chain_hops", query)
            self.assertIn("chain_arns", query)
            self.assertIn("chain_roles", query)
            self.assertIn("length(chain) AS chain_hops", query)
            self.assertIn("[n IN nodes(chain) | n.`~id`] AS chain_arns", query)
            self.assertIn("[n IN nodes(chain) | n.rolename] AS chain_roles", query)

            # (1.6) a LIMIT clause is present.
            self.assertIn("LIMIT", query)

            # (1.4) same $principal / $resource references as the existing
            # arms, and $actions when actions were supplied.
            self.assertIn("$principal", query)
            self.assertIn("$resource", query)
            self.assertEqual(params["principal"], principal)
            self.assertEqual(params["resource"], resource)
            if actions:
                self.assertIn("$actions", query)
                self.assertEqual(params["actions"], actions)
            else:
                self.assertNotIn("$actions", query)
                self.assertNotIn("actions", params)

            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(f"\n[role-chaining-detection Property 1] executed {iterations} generated cases")


class RoleChainWhoCanAccessPropertyTests(unittest.TestCase):
    """Feature: role-chaining-detection, Property 2: who_can_access role_chain
    route reaches Entry_Role backward from the Granting_Role.

    For any resource substring, any optional actions list, and any max_hops:
    queries.who_can_access returns query text containing at least one arm
    tagged 'role_chain' AS access_via whose pattern includes a bounded
    CAN_ASSUME*1..N traversal ending at the SAME `role` variable the
    resource-anchored GRANTS_ACCESS_TO match binds - i.e. the chain closes on
    the bare `(role)` reference, not a freshly re-typed `(role:RoleName)`,
    since the resource-anchored role is already typed by the shared `base`
    prefix - together with a chain_hops / chain_arns / chain_roles projection
    and a LIMIT clause; that arm references the same $resource / (when
    supplied) $actions parameters the existing permission_set and direct_role
    arms already reference.

    Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.6
    """

    def test_property_2(self):
        rng = random.Random(_SEED + 11)
        pattern = re.compile(r"CAN_ASSUME\*1\.\.(\d+)")
        iterations = 0
        for _ in range(_ITERATIONS):
            resource = _random_resource(rng)

            actions_bucket = rng.random()
            if actions_bucket < 0.5:
                actions = None
            else:
                n_actions = rng.randint(1, 3)
                actions = [
                    rng.choice(
                        [
                            "s3:GetObject",
                            "iam:PassRole",
                            "sts:AssumeRole",
                            "DELETE me",
                            "action' OR '1'='1",
                        ]
                    )
                    for _ in range(n_actions)
                ]

            hops_bucket = rng.choice(["below", "inrange", "above", "omitted"])
            if hops_bucket == "below":
                max_hops = rng.randint(-20, 0)
                query, params = queries.who_can_access(resource, actions, max_hops)
            elif hops_bucket == "inrange":
                max_hops = rng.randint(1, queries.MAX_HOPS_CAP)
                query, params = queries.who_can_access(resource, actions, max_hops)
            elif hops_bucket == "above":
                max_hops = rng.randint(
                    queries.MAX_HOPS_CAP + 1, queries.MAX_HOPS_CAP + 50
                )
                query, params = queries.who_can_access(resource, actions, max_hops)
            else:
                # Omitted -> exercise the default parameter.
                query, params = queries.who_can_access(resource, actions)
                max_hops = queries.DEFAULT_HOPS

            eff = _expected_eff(max_hops)

            # (2.2) role_chain tag present.
            self.assertIn("'role_chain' AS access_via", query)

            # (2.1, 2.3) bounded CAN_ASSUME*1..N traversal at the clamped eff
            # value. There are two role_chain arms in this builder
            # (chain_ps_branch / chain_role_branch), each with its own
            # occurrence.
            self.assertIn(f"CAN_ASSUME*1..{eff}", query)
            matches = pattern.findall(query)
            self.assertTrue(len(matches) >= 1)
            for n in matches:
                self.assertEqual(int(n), eff)

            # (2.1) the traversal ends at the SAME `role` variable the
            # resource-anchored GRANTS_ACCESS_TO match binds - the chain
            # pattern closes on bare `(role)`, never re-typing it as
            # `(role:RoleName)`. Both role_chain arms share this exact shape.
            traversal_re = re.compile(
                rf"\(entry:RoleName\)-\[:CAN_ASSUME\*1\.\.{eff}\]->\(role\)"
            )
            chain_traversals = traversal_re.findall(query)
            self.assertEqual(len(chain_traversals), 2)
            self.assertNotIn(f"CAN_ASSUME*1..{eff}]->(role:RoleName)", query)

            # (2.3) chain_hops / chain_arns / chain_roles columns, exact
            # projections.
            self.assertIn("chain_hops", query)
            self.assertIn("chain_arns", query)
            self.assertIn("chain_roles", query)
            self.assertIn("length(chain) AS chain_hops", query)
            self.assertIn("[n IN nodes(chain) | n.`~id`] AS chain_arns", query)
            self.assertIn("[n IN nodes(chain) | n.rolename] AS chain_roles", query)

            # (2.6) a LIMIT clause is present.
            self.assertIn("LIMIT", query)

            # (2.4) same $resource reference as the existing arms, and
            # $actions when actions were supplied (never when they weren't).
            self.assertIn("$resource", query)
            self.assertEqual(params["resource"], resource)
            if actions:
                self.assertIn("$actions", query)
                self.assertEqual(params["actions"], actions)
            else:
                self.assertNotIn("$actions", query)
                self.assertNotIn("actions", params)

            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(
            f"\n[role-chaining-detection Property 2] executed {iterations} generated cases"
        )


class RoleChainPrincipalAccessReportPropertyTests(unittest.TestCase):
    """Feature: role-chaining-detection, Property 3: principal_access_report
    role_chain route reports the resource and account columns.

    For any principal substring and any optional account substring:
    queries.principal_access_report returns query text containing at least one
    arm tagged 'role_chain' AS access_via whose RETURN clause includes the
    account, resource, and resource_account aliases alongside chain_hops,
    chain_arns, and chain_roles; and, when an account substring is supplied,
    that arm's query text contains the same account-filter predicate text the
    existing permission_set / direct_role arms contain.

    Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5
    """

    def test_property_3(self):
        rng = random.Random(_SEED + 12)
        pattern = re.compile(r"CAN_ASSUME\*1\.\.(\d+)")
        iterations = 0
        for _ in range(_ITERATIONS):
            principal = _random_role(rng)

            account_bucket = rng.random()
            account = None if account_bucket < 0.5 else _random_account(rng)

            hops_bucket = rng.choice(["below", "inrange", "above", "omitted"])
            if hops_bucket == "below":
                max_hops = rng.randint(-20, 0)
                query, params = queries.principal_access_report(
                    principal, account, max_hops
                )
            elif hops_bucket == "inrange":
                max_hops = rng.randint(1, queries.MAX_HOPS_CAP)
                query, params = queries.principal_access_report(
                    principal, account, max_hops
                )
            elif hops_bucket == "above":
                max_hops = rng.randint(
                    queries.MAX_HOPS_CAP + 1, queries.MAX_HOPS_CAP + 50
                )
                query, params = queries.principal_access_report(
                    principal, account, max_hops
                )
            else:
                # Omitted -> exercise the default parameter.
                query, params = queries.principal_access_report(principal, account)
                max_hops = queries.DEFAULT_HOPS

            eff = _expected_eff(max_hops)

            # (3.2) role_chain tag present.
            self.assertIn("'role_chain' AS access_via", query)

            # (3.1, 3.3) bounded CAN_ASSUME*1..N at the clamped eff value.
            # There are two role_chain arms in this builder (chain_ps_branch /
            # chain_role_branch), each with its own occurrence.
            self.assertIn(f"CAN_ASSUME*1..{eff}", query)
            matches = pattern.findall(query)
            self.assertTrue(len(matches) >= 1)
            for n in matches:
                self.assertEqual(int(n), eff)

            # (3.3) chain_hops / chain_arns / chain_roles columns, exact
            # projections.
            self.assertIn("chain_hops", query)
            self.assertIn("chain_arns", query)
            self.assertIn("chain_roles", query)
            self.assertIn("length(chain) AS chain_hops", query)
            self.assertIn("[n IN nodes(chain) | n.`~id`] AS chain_arns", query)
            self.assertIn("[n IN nodes(chain) | n.rolename] AS chain_roles", query)

            # (3.1, 3.4) a role_chain arm's RETURN clause includes account,
            # resource, and resource_account aliases alongside the chain
            # columns. Both role_chain arms in this builder share this shape.
            self.assertIn("acct.name AS account", query)
            self.assertIn("res.`~id` AS resource", query)
            self.assertIn("resacct.name AS resource_account", query)
            return_re = re.compile(
                r"RETURN DISTINCT[^\n]*'role_chain' AS access_via,[\s\S]*?"
                r"acct\.name AS account,\n\s*res\.`~id` AS resource, "
                r"resacct\.name AS resource_account,\n\s*"
                r"length\(chain\) AS chain_hops,"
            )
            role_chain_returns = return_re.findall(query)
            self.assertEqual(len(role_chain_returns), 2)

            # a LIMIT clause is present.
            self.assertIn("LIMIT", query)

            # $principal referenced/carried in params.
            self.assertIn("$principal", query)
            self.assertEqual(params["principal"], principal)

            # (3.5) when account is supplied, the same account-filter
            # predicate text the existing ps_branch/role_branch arms contain
            # is present verbatim.
            if account:
                self.assertIn("$account", query)
                self.assertEqual(params["account"], account)
                self.assertIn("WHERE acct.name CONTAINS $account", query)
                self.assertIn("OR resacct.name CONTAINS $account", query)
            else:
                self.assertNotIn("$account", query)
                self.assertNotIn("account", params)

            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(
            f"\n[role-chaining-detection Property 3] executed {iterations} generated cases"
        )


class RoleChainPrincipalAccessSummaryPropertyTests(unittest.TestCase):
    """Feature: role-chaining-detection, Property 4: principal_access_summary
    role_chain contributions are resource-gated and account-filtered.

    For any principal substring and any optional account substring:
    queries.principal_access_summary returns query text whose CALL {} block
    contains at least one arm tagged 'role_chain' AS access_via that requires
    a GRANTS_ACCESS_TO match to a CriticalResources node (so no chain
    contribution lacking a resource is possible) and, when an account
    substring is supplied, applies the same account-filter predicate text the
    existing arms apply; the outer aggregate RETURN clause is unchanged
    (access_via, grant, iam_role, resource_count, resources).

    Validates: Requirements 4.1, 4.2, 4.3, 4.4
    """

    def test_property_4(self):
        rng = random.Random(_SEED + 13)
        pattern = re.compile(r"CAN_ASSUME\*1\.\.(\d+)")
        iterations = 0
        for _ in range(_ITERATIONS):
            principal = _random_role(rng)

            account_bucket = rng.random()
            account = None if account_bucket < 0.5 else _random_account(rng)

            # queries.principal_access_summary DOES accept max_hops (it
            # computes eff = effective_hops(max_hops) internally, exactly
            # like the other three Access_Builders), so exercise the same
            # below/in-range/above-cap/omitted bucket mix used by Properties
            # 1-3 above and assert every CAN_ASSUME*1..N occurrence matches
            # effective_hops(max_hops).
            hops_bucket = rng.choice(["below", "inrange", "above", "omitted"])
            if hops_bucket == "below":
                max_hops = rng.randint(-20, 0)
                query, params = queries.principal_access_summary(
                    principal, account, max_hops
                )
            elif hops_bucket == "inrange":
                max_hops = rng.randint(1, queries.MAX_HOPS_CAP)
                query, params = queries.principal_access_summary(
                    principal, account, max_hops
                )
            elif hops_bucket == "above":
                max_hops = rng.randint(
                    queries.MAX_HOPS_CAP + 1, queries.MAX_HOPS_CAP + 50
                )
                query, params = queries.principal_access_summary(
                    principal, account, max_hops
                )
            else:
                # Omitted -> exercise the default parameter.
                query, params = queries.principal_access_summary(principal, account)
                max_hops = queries.DEFAULT_HOPS

            eff = _expected_eff(max_hops)

            # Isolate the inner CALL {} block so role_chain arms can be
            # inspected independently of the (unchanged) outer wrapper.
            call_start = query.index("CALL {")
            call_end = query.index("\n}\n", call_start)
            call_block = query[call_start:call_end]
            arms = call_block.split("UNION\n")
            role_chain_arms = [a for a in arms if "'role_chain' AS access_via" in a]

            # (4.1) at least one role_chain-tagged arm inside the CALL {}
            # block - in practice this builder emits exactly two
            # (chain_ps_branch / chain_role_branch), mirroring the existing
            # arm-pair pattern used by ps_branch / role_branch.
            self.assertGreaterEqual(len(role_chain_arms), 1)
            self.assertEqual(len(role_chain_arms), 2)

            for arm in role_chain_arms:
                # Bounded CAN_ASSUME*1..N at the clamped eff value.
                self.assertIn(f"CAN_ASSUME*1..{eff}", arm)

                # (4.2) the GRANTS_ACCESS_TO match to a CriticalResources node
                # is mandatory (a plain MATCH), never an OPTIONAL MATCH - so no
                # role_chain contribution lacking a resource is possible.
                self.assertIn(
                    "MATCH (role)-[:GRANTS_ACCESS_TO]->(res:CriticalResources)",
                    arm,
                )
                self.assertNotIn(
                    "OPTIONAL MATCH (role)-[:GRANTS_ACCESS_TO]->(res:CriticalResources)",
                    arm,
                )

                # (4.3) hop count / chain-role columns are intentionally NOT
                # surfaced on this builder's role_chain arms (unlike
                # find_access_paths / who_can_access / principal_access_report)
                # since a single grouped row can be reached by chains of
                # different lengths across different resources.
                self.assertNotIn("chain_hops", arm)
                self.assertNotIn("chain_arns", arm)
                self.assertNotIn("chain_roles", arm)

                # (4.4) when an account substring is supplied, the same
                # account-filter predicate text the existing ps_branch /
                # role_branch arms apply is present verbatim; absent
                # otherwise.
                if account:
                    self.assertIn("$account", arm)
                    self.assertIn("AND acct.name CONTAINS $account", arm)
                else:
                    self.assertNotIn("$account", arm)

            # Every CAN_ASSUME*1..N occurrence in the whole query (only the
            # role_chain arms contain any) uses the same clamped eff value.
            matches = pattern.findall(query)
            self.assertTrue(len(matches) >= 1)
            for n in matches:
                self.assertEqual(int(n), eff)

            # $principal referenced/carried in params.
            self.assertIn("$principal", query)
            self.assertEqual(params["principal"], principal)

            if account:
                self.assertEqual(params["account"], account)
            else:
                self.assertNotIn("account", params)

            # The outer aggregate RETURN clause is unchanged.
            self.assertIn("RETURN access_via, grant, iam_role,", query)
            self.assertIn("count(DISTINCT resource) AS resource_count", query)
            self.assertIn("collect(DISTINCT resource) AS resources", query)
            self.assertIn("ORDER BY access_via, grant", query)

            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(
            f"\n[role-chaining-detection Property 4] executed {iterations} generated cases"
        )


class RoleChainHopBoundPropertyTests(unittest.TestCase):
    """Feature: role-chaining-detection, Property 5: Every Access_Builder's
    role_chain hop bound equals effective_hops(max_hops).

    For any of the four Access_Builders (find_access_paths, who_can_access,
    principal_access_report, principal_access_summary) and any max_hops value
    (including values below 1, above MAX_HOPS_CAP, and non-integer values):
    every CAN_ASSUME*1..N occurrence that builder's role_chain arm(s) generate
    has N == effective_hops(max_hops), and N always lies in
    [1, MAX_HOPS_CAP]. Omitting max_hops produces N == DEFAULT_HOPS.

    Validates: Requirements 1.5, 2.5, 3.6, 4.5, 5.1, 5.2, 5.3, 5.4, 5.5
    """

    _BUILDER_NAMES = (
        "find_access_paths",
        "who_can_access",
        "principal_access_report",
        "principal_access_summary",
    )

    def _call_builder(self, name, rng, hops_bucket, cap):
        """Call the named builder with random-but-appropriate args and a
        max_hops value drawn from ``hops_bucket``. Returns (query, params,
        max_hops_supplied) where max_hops_supplied is the raw value passed to
        the builder, or the sentinel ``_OMITTED`` when max_hops was left out
        of the call entirely (to exercise the builder's own default).
        """
        if hops_bucket == "below":
            max_hops = rng.randint(-20, 0)
        elif hops_bucket == "inrange":
            max_hops = rng.randint(1, cap)
        elif hops_bucket == "above":
            max_hops = rng.randint(cap + 1, cap + 50)
        elif hops_bucket == "float":
            # A non-integer float, e.g. 3.9 - int() truncates it.
            max_hops = round(rng.uniform(1, cap + 5), 1)
        elif hops_bucket == "numeric_string":
            # A numeric string, e.g. "7" - int() casts it successfully.
            max_hops = str(rng.randint(-5, cap + 10))
        elif hops_bucket == "invalid_string":
            # Not castable at all - falls back to DEFAULT_HOPS.
            max_hops = rng.choice(["abc", "", "n/a", "7x"])
        else:
            max_hops = None  # NaN-style non-castable value.

        if hops_bucket == "nan":
            max_hops = float("nan")

        if name == "find_access_paths":
            principal = _random_role(rng)
            resource = _random_resource(rng)
            query, params = queries.find_access_paths(
                principal, resource, None, max_hops
            )
        elif name == "who_can_access":
            resource = _random_resource(rng)
            query, params = queries.who_can_access(resource, None, max_hops)
        elif name == "principal_access_report":
            principal = _random_role(rng)
            account = None if rng.random() < 0.5 else _random_account(rng)
            query, params = queries.principal_access_report(
                principal, account, max_hops
            )
        else:  # principal_access_summary
            principal = _random_role(rng)
            account = None if rng.random() < 0.5 else _random_account(rng)
            query, params = queries.principal_access_summary(
                principal, account, max_hops
            )

        return query, params, max_hops

    def _call_builder_omitted(self, name, rng):
        """Call the named builder WITHOUT a max_hops argument at all, so it
        falls back to its own default parameter (DEFAULT_HOPS)."""
        if name == "find_access_paths":
            principal = _random_role(rng)
            resource = _random_resource(rng)
            query, params = queries.find_access_paths(principal, resource, None)
        elif name == "who_can_access":
            resource = _random_resource(rng)
            query, params = queries.who_can_access(resource, None)
        elif name == "principal_access_report":
            principal = _random_role(rng)
            account = None if rng.random() < 0.5 else _random_account(rng)
            query, params = queries.principal_access_report(principal, account)
        else:  # principal_access_summary
            principal = _random_role(rng)
            account = None if rng.random() < 0.5 else _random_account(rng)
            query, params = queries.principal_access_summary(principal, account)

        return query, params

    def test_property_5(self):
        rng = random.Random(_SEED + 14)
        cap = queries.MAX_HOPS_CAP
        pattern = re.compile(r"CAN_ASSUME\*1\.\.(\d+)")
        hop_buckets = [
            "below",
            "inrange",
            "above",
            "float",
            "numeric_string",
            "invalid_string",
            "nan",
            "omitted",
        ]
        iterations = 0
        for _ in range(_ITERATIONS):
            builder_name = rng.choice(self._BUILDER_NAMES)
            hops_bucket = rng.choice(hop_buckets)

            if hops_bucket == "omitted":
                query, _params = self._call_builder_omitted(builder_name, rng)
                expected = queries.DEFAULT_HOPS
                # Omitting max_hops must land on DEFAULT_HOPS specifically.
                self.assertEqual(expected, queries.effective_hops(queries.DEFAULT_HOPS))
            else:
                query, _params, max_hops = self._call_builder(
                    builder_name, rng, hops_bucket, cap
                )
                expected = queries.effective_hops(max_hops)

            # Every CAN_ASSUME*1..N occurrence in that builder's role_chain
            # arm(s) uses exactly the same clamped value.
            matches = pattern.findall(query)
            self.assertTrue(
                len(matches) >= 1,
                f"no CAN_ASSUME*1..N occurrence found for builder={builder_name!r} "
                f"hops_bucket={hops_bucket!r}",
            )
            for n in matches:
                self.assertEqual(
                    int(n),
                    expected,
                    f"builder={builder_name!r} hops_bucket={hops_bucket!r}",
                )

            # N always lies in [1, MAX_HOPS_CAP].
            self.assertGreaterEqual(expected, 1)
            self.assertLessEqual(expected, cap)

            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(f"\n[role-chaining-detection Property 5] executed {iterations} generated cases")


class RoleChainReadOnlyGuardPropertyTests(unittest.TestCase):
    """Feature: role-chaining-detection, Property 6: Every Access_Builder's
    generated query passes the read-only guard.

    For any of the four Access_Builders (find_access_paths, who_can_access,
    principal_access_report, principal_access_summary), any
    principal/resource/account substring (including strings containing
    openCypher keywords or metacharacters), any optional actions list, and any
    max_hops: calling assert_read_only on the generated query text does not
    raise ReadOnlyViolation.

    Validates: Requirements 7.5
    """

    _BUILDER_NAMES = (
        "find_access_paths",
        "who_can_access",
        "principal_access_report",
        "principal_access_summary",
    )

    _ACTION_CHOICES = [
        "s3:GetObject",
        "iam:PassRole",
        "sts:AssumeRole",
        "DELETE me",
        "action' OR '1'='1",
    ]

    def _random_actions(self, rng):
        bucket = rng.random()
        if bucket < 0.5:
            return None
        n_actions = rng.randint(1, 3)
        return [rng.choice(self._ACTION_CHOICES) for _ in range(n_actions)]

    def _random_max_hops(self, rng, cap):
        bucket = rng.choice(["below", "inrange", "above", "omitted"])
        if bucket == "below":
            return rng.randint(-20, 0), False
        if bucket == "inrange":
            return rng.randint(1, cap), False
        if bucket == "above":
            return rng.randint(cap + 1, cap + 50), False
        return None, True  # omitted -> caller uses the builder's default

    def _call_builder(
        self, name, rng, cap, forced_principal=None, forced_resource=None,
        forced_account=None,
    ):
        """Call the named builder with random-but-appropriate args, forcing a
        hostile substring into whichever positional argument(s) that builder
        accepts when a forced_* value is supplied. Returns (query, details)
        where details is a dict describing the call for failure messages.
        """
        actions = self._random_actions(rng)
        max_hops, omitted = self._random_max_hops(rng, cap)

        if name == "find_access_paths":
            principal = forced_principal if forced_principal is not None else _random_role(rng)
            resource = forced_resource if forced_resource is not None else _random_resource(rng)
            if omitted:
                query, _params = queries.find_access_paths(principal, resource, actions)
            else:
                query, _params = queries.find_access_paths(
                    principal, resource, actions, max_hops
                )
            details = {
                "builder": name,
                "principal": principal,
                "resource": resource,
                "actions": actions,
                "max_hops": "omitted" if omitted else max_hops,
            }
        elif name == "who_can_access":
            resource = forced_resource if forced_resource is not None else _random_resource(rng)
            if omitted:
                query, _params = queries.who_can_access(resource, actions)
            else:
                query, _params = queries.who_can_access(resource, actions, max_hops)
            details = {
                "builder": name,
                "resource": resource,
                "actions": actions,
                "max_hops": "omitted" if omitted else max_hops,
            }
        elif name == "principal_access_report":
            principal = forced_principal if forced_principal is not None else _random_role(rng)
            account = forced_account if forced_account is not None else (
                None if rng.random() < 0.5 else _random_account(rng)
            )
            if omitted:
                query, _params = queries.principal_access_report(principal, account)
            else:
                query, _params = queries.principal_access_report(
                    principal, account, max_hops
                )
            details = {
                "builder": name,
                "principal": principal,
                "account": account,
                "max_hops": "omitted" if omitted else max_hops,
            }
        else:  # principal_access_summary
            principal = forced_principal if forced_principal is not None else _random_role(rng)
            account = forced_account if forced_account is not None else (
                None if rng.random() < 0.5 else _random_account(rng)
            )
            if omitted:
                query, _params = queries.principal_access_summary(principal, account)
            else:
                query, _params = queries.principal_access_summary(
                    principal, account, max_hops
                )
            details = {
                "builder": name,
                "principal": principal,
                "account": account,
                "max_hops": "omitted" if omitted else max_hops,
            }

        return query, details

    def test_property_6(self):
        rng = random.Random(_SEED + 15)
        cap = queries.MAX_HOPS_CAP
        iterations = 0

        # (7.5) Force at least one hostile substring through each of the four
        # builders before falling back to fully-random cases, similar to how
        # Property3ParameterizationTests forces every hostile substring
        # through role_assumption_paths. Each forced call cycles through the
        # hostile list so every builder sees more than one hostile value
        # across the run.
        forced_calls = []
        for builder_name in self._BUILDER_NAMES:
            for hostile in _HOSTILE_ROLE_SUBSTRINGS:
                if builder_name in ("find_access_paths",):
                    forced_calls.append(
                        (builder_name, {"forced_principal": hostile, "forced_resource": hostile})
                    )
                elif builder_name == "who_can_access":
                    forced_calls.append((builder_name, {"forced_resource": hostile}))
                else:
                    forced_calls.append(
                        (builder_name, {"forced_principal": hostile, "forced_account": hostile})
                    )

        for builder_name, forced_kwargs in forced_calls:
            query, details = self._call_builder(builder_name, rng, cap, **forced_kwargs)
            try:
                assert_read_only(query)
            except ReadOnlyViolation as exc:  # pragma: no cover - failure path
                self.fail(
                    f"assert_read_only raised for forced hostile case {details}: {exc}"
                )
            iterations += 1

        # Remaining iterations: fully random builder + substrings (still
        # drawing from the hostile/benign mix via _random_role /
        # _random_resource / _random_account) until we reach >=100 total.
        while iterations < _ITERATIONS:
            builder_name = rng.choice(self._BUILDER_NAMES)
            query, details = self._call_builder(builder_name, rng, cap)
            try:
                assert_read_only(query)
            except ReadOnlyViolation as exc:  # pragma: no cover - failure path
                self.fail(
                    f"assert_read_only raised for random case {details}: {exc}"
                )
            iterations += 1

        self.assertGreaterEqual(iterations, 100)
        print(
            f"\n[role-chaining-detection Property 6] executed {iterations} generated cases"
        )


class ExampleTests(unittest.TestCase):
    """Task 5.7 - example/edge tests.

    - role_assumption_paths(role) with max_hops omitted produces CAN_ASSUME*1..5
      (the DEFAULT_HOPS default). (Req 4.2)
    - Invalid-direction bad_argument case is tool-level in server.py, which needs
      the mcp SDK. It is guarded with a try/except import + skip so the suite
      still runs without the mcp SDK. (Req 3.2)
    """

    def test_default_hops_is_five(self):
        # max_hops omitted -> DEFAULT_HOPS (5).
        self.assertEqual(queries.DEFAULT_HOPS, 5)
        query, params = queries.role_assumption_paths("Admin")
        self.assertIn("CAN_ASSUME*1..5", query)
        self.assertEqual(params, {"role": "Admin"})

    def test_default_direction_is_backward(self):
        # Omitted direction defaults to backward (target-anchored).
        query, _ = queries.role_assumption_paths("Admin")
        self.assertIn("(target:RoleName)", query)
        self.assertIn("toLower(target.`~id`) CONTAINS toLower($role)", query)

    def _try_import_server(self):
        """Return the server module or None if the mcp SDK is unavailable."""
        try:
            from aria_mcp_server import server  # type: ignore

            return server
        except Exception:  # ImportError or any mcp-SDK import-time failure.
            return None

    def test_invalid_direction_returns_bad_argument(self):
        server = self._try_import_server()
        if server is None:
            self.skipTest("server.py not importable (mcp SDK absent); tool-level test skipped")
        result = server.find_role_assumption_paths("Admin", direction="sideways")
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("error"), "bad_argument")

    def test_role_chain_default_hops_is_five(self):
        """Task 8.8 - max_hops omitted on every Access_Builder embeds
        DEFAULT_HOPS (CAN_ASSUME*1..5) in that builder's role_chain arm(s).
        (Req 8.1, 8.2)
        """
        self.assertEqual(queries.DEFAULT_HOPS, 5)

        query, _ = queries.find_access_paths("Admin", "bucket", None)
        self.assertIn("CAN_ASSUME*1..5", query)

        query, _ = queries.who_can_access("bucket", None)
        self.assertIn("CAN_ASSUME*1..5", query)

        query, _ = queries.principal_access_report("Admin", None)
        self.assertIn("CAN_ASSUME*1..5", query)

        query, _ = queries.principal_access_summary("Admin", None)
        self.assertIn("CAN_ASSUME*1..5", query)

    def test_tool_max_hops_threads_to_builder(self):
        """Task 8.8 - each of the four Access_Tools passes a supplied
        `max_hops` through to its builder unchanged. (Req 8.4)

        The tools call `_run`, which executes against a real Graph_Client -
        unavailable (and unsafe to reach) in this test environment. Rather
        than exercising that path, each of the four `queries` builders is
        temporarily monkeypatched to capture its call args and raise a
        sentinel exception, so the tool call short-circuits before `_run`
        ever touches the graph client, then the original builder is restored.
        """
        server = self._try_import_server()
        if server is None:
            self.skipTest("server.py not importable (mcp SDK absent); tool-level test skipped")

        from unittest.mock import patch

        distinctive_max_hops = 3

        class _CapturedCall(Exception):
            """Raised by the patched builder right after recording its call
            args, so the tool call never reaches _run()'s graph client."""

        cases = [
            (
                "find_access_paths",
                lambda: server.find_access_paths(
                    "Admin", "bucket", max_hops=distinctive_max_hops
                ),
            ),
            (
                "who_can_access",
                lambda: server.who_can_access("bucket", max_hops=distinctive_max_hops),
            ),
            (
                "principal_access_report",
                lambda: server.get_principal_access(
                    "Admin", max_hops=distinctive_max_hops
                ),
            ),
            (
                "principal_access_summary",
                lambda: server.get_principal_access_summary(
                    "Admin", max_hops=distinctive_max_hops
                ),
            ),
        ]

        for builder_name, invoke_tool in cases:
            with self.subTest(builder=builder_name):
                captured: dict = {}

                def _fake_builder(*args, **kwargs):
                    captured["args"] = args
                    captured["kwargs"] = kwargs
                    raise _CapturedCall()

                with patch.object(queries, builder_name, _fake_builder):
                    with self.assertRaises(_CapturedCall):
                        invoke_tool()

                passed_max_hops = captured["kwargs"].get("max_hops")
                if passed_max_hops is None and captured["args"]:
                    passed_max_hops = captured["args"][-1]
                self.assertEqual(passed_max_hops, distinctive_max_hops)


if __name__ == "__main__":
    unittest.main(verbosity=2)
