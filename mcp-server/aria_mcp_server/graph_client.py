"""Thin boto3 wrapper for the ARIA-gv Neptune Analytics graph.

Handles graph-id discovery, a read-only query guard, and execution of
openCypher queries via the neptune-graph data plane (`execute_query`).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


class GraphError(Exception):
    """Raised for anything that stops a query from succeeding."""


class ReadOnlyViolation(GraphError):
    """Raised when a query contains a mutating openCypher clause."""


# openCypher / Neptune clauses that mutate the graph. Matched as whole words,
# case-insensitively. This server is strictly read-only.
_MUTATING_CLAUSES = (
    "CREATE",
    "MERGE",
    "SET",
    "DELETE",
    "REMOVE",
    "DETACH",
    "DROP",
    "LOAD",
)
_MUTATING_RE = re.compile(
    r"\b(" + "|".join(_MUTATING_CLAUSES) + r")\b", re.IGNORECASE
)
# Neptune management procedures that reset/mutate state.
_FORBIDDEN_CALL_RE = re.compile(r"neptune\.(reset|load)", re.IGNORECASE)


def assert_read_only(query: str) -> None:
    """Reject queries that contain mutating clauses.

    Raises ReadOnlyViolation if the query would change the graph.
    """
    clause = _MUTATING_RE.search(query)
    if clause:
        raise ReadOnlyViolation(
            f"Refusing to run a query containing the mutating clause "
            f"'{clause.group(1).upper()}'. This server only runs read-only "
            f"(MATCH / RETURN) queries."
        )
    if _FORBIDDEN_CALL_RE.search(query):
        raise ReadOnlyViolation(
            "Refusing to run a Neptune management procedure that mutates graph state."
        )


class AriaGraphClient:
    """Lazily-initialised client for the ARIA-gv Neptune Analytics graph."""

    def __init__(
        self,
        graph_id: str | None = None,
        region: str | None = None,
        profile: str | None = None,
    ) -> None:
        self._graph_id = graph_id or os.environ.get("ARIA_GRAPH_ID") or None
        self._region = region or os.environ.get("AWS_REGION") or os.environ.get(
            "AWS_DEFAULT_REGION"
        )
        self._profile = profile or os.environ.get("AWS_PROFILE")
        self._client = None

    # -- boto3 plumbing -------------------------------------------------

    @property
    def client(self):
        if self._client is None:
            session = boto3.Session(
                profile_name=self._profile, region_name=self._region
            )
            self._client = session.client(
                "neptune-graph",
                config=Config(retries={"max_attempts": 3, "mode": "standard"}),
            )
        return self._client

    def resolve_graph_id(self) -> str:
        """Return the configured graph id, discovering it if not set.

        Discovery prefers a graph whose name looks like the ARIA graph
        (contains 'aria' or 'identitycenter'); if there is exactly one graph in
        the account/region, that one is used.
        """
        if self._graph_id:
            return self._graph_id

        try:
            graphs = self._list_graphs()
        except (ClientError, BotoCoreError) as exc:
            raise GraphError(
                f"Could not list Neptune Analytics graphs to discover the graph id: {exc}. "
                f"Set ARIA_GRAPH_ID explicitly."
            ) from exc

        def looks_like_aria(g: dict) -> bool:
            name = (g.get("name") or "").lower()
            return "aria" in name or "identitycenter" in name

        aria = [g for g in graphs if looks_like_aria(g)]
        if len(aria) == 1:
            self._graph_id = aria[0]["id"]
        elif len(graphs) == 1:
            self._graph_id = graphs[0]["id"]
        else:
            names = ", ".join(f"{g.get('name')} ({g['id']})" for g in graphs) or "none"
            raise GraphError(
                "Could not auto-discover the ARIA graph id. "
                f"Set ARIA_GRAPH_ID explicitly. Graphs found: {names}."
            )
        return self._graph_id

    def _list_graphs(self) -> list[dict]:
        graphs: list[dict] = []
        paginator = self.client.get_paginator("list_graphs")
        for page in paginator.paginate():
            graphs.extend(page.get("graphs", []))
        return graphs

    # -- query execution ------------------------------------------------

    def execute(
        self, query: str, parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Run a read-only openCypher query and return the parsed result.

        Returns a dict with the parsed `results` list plus metadata. Raises
        ReadOnlyViolation for mutating queries and GraphError for AWS/transport
        failures (including the common private-endpoint connectivity case).
        """
        assert_read_only(query)
        graph_id = self.resolve_graph_id()

        kwargs: dict[str, Any] = {
            "graphIdentifier": graph_id,
            "queryString": query,
            "language": "OPEN_CYPHER",
        }
        if parameters:
            kwargs["parameters"] = parameters

        try:
            resp = self.client.execute_query(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            raise GraphError(self._explain_transport_error(exc)) from exc

        payload = resp.get("payload")
        raw = payload.read() if hasattr(payload, "read") else payload
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw}

        results = parsed.get("results", parsed)
        return {
            "graph_id": graph_id,
            "count": len(results) if isinstance(results, list) else None,
            "results": results,
        }

    @staticmethod
    def _explain_transport_error(exc: Exception) -> str:
        msg = str(exc)
        hint = (
            " The ARIA graph is deployed with PublicConnectivity=false, so "
            "execute_query only works from a host with network reach to the "
            "private endpoint (Neptune notebook, in-VPC compute, SSM "
            "port-forward, or VPN). If you cannot reach it, run the generated "
            "openCypher in Neptune Graph Explorer instead."
        )
        lowered = msg.lower()
        if any(t in lowered for t in ("timeout", "could not connect", "endpoint", "connection")):
            return f"Could not reach the Neptune graph endpoint: {msg}.{hint}"
        return f"Query failed: {msg}.{hint}"
