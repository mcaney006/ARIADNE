"""Resolve identity atoms and links into principals.

A principal is a connected component of the identity graph. Within a component,
each identity's confidence is its own self-confidence scaled by the strength of
the *best* chain of links connecting it to the component's anchor (the
highest-confidence atom — typically an authoritative directory record). The
output preserves provenance for every identity so a reviewer can see not just
that two identifiers were merged, but why and how strongly.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import networkx as nx

from ariadne.identity.graph import (
    IdentityAssertion,
    IdentityLink,
    build_graph,
)


@dataclass(frozen=True)
class ResolvedIdentity:
    type: str
    value: str
    confidence: float
    sources: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "value": self.value,
            "confidence": round(self.confidence, 4),
            "source": ", ".join(sorted(self.sources)),
        }


@dataclass(frozen=True)
class Principal:
    principal_id: str
    identities: tuple[ResolvedIdentity, ...]

    def to_dict(self) -> dict:
        return {
            "principal_id": self.principal_id,
            "identities": [identity.to_dict() for identity in self.identities],
        }

    def has(self, type_: str, value: str) -> bool:
        return any(i.type == type_ and i.value == value for i in self.identities)


class IdentityResolver:
    """Builds principals from identity assertions and links."""

    def __init__(self) -> None:
        self._assertions: list[IdentityAssertion] = []
        self._links: list[IdentityLink] = []

    def add_assertion(self, assertion: IdentityAssertion) -> "IdentityResolver":
        self._assertions.append(assertion)
        return self

    def add_link(self, link: IdentityLink) -> "IdentityResolver":
        self._links.append(link)
        return self

    def resolve(self) -> list[Principal]:
        graph = build_graph(self._assertions, self._links)
        principals: list[Principal] = []

        for component in nx.connected_components(graph):
            anchor = max(
                component, key=lambda atom: (graph.nodes[atom]["confidence"], atom)
            )
            identities: list[ResolvedIdentity] = []
            for atom in sorted(component):
                self_conf = graph.nodes[atom]["confidence"]
                link_conf = _best_path_confidence(graph, atom, anchor)
                confidence = self_conf * link_conf
                identities.append(
                    ResolvedIdentity(
                        type=atom[0],
                        value=atom[1],
                        confidence=confidence,
                        sources=tuple(sorted(graph.nodes[atom]["sources"]))
                        or ("derived",),
                    )
                )
            principals.append(
                Principal(
                    principal_id=_principal_id(component),
                    identities=tuple(identities),
                )
            )

        principals.sort(key=lambda p: p.principal_id)
        return principals


def _best_path_confidence(
    graph: nx.Graph, source: tuple[str, str], target: tuple[str, str]
) -> float:
    """The strongest chain from ``source`` to ``target`` (max product of edges)."""

    if source == target:
        return 1.0
    best = 0.0
    try:
        paths = nx.all_simple_paths(graph, source, target, cutoff=6)
    except (nx.NodeNotFound, nx.NetworkXNoPath):
        return 0.0
    for path in paths:
        product = 1.0
        for a, b in zip(path, path[1:]):
            product *= graph.edges[a, b]["confidence"]
        best = max(best, product)
    return best


def _principal_id(component: set[tuple[str, str]]) -> str:
    seed = "|".join(sorted(f"{t}:{v}" for t, v in component))
    digest = hashlib.sha256(seed.encode()).hexdigest()[:6]
    return f"person-{digest}"
