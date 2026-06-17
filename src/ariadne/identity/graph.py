"""The identity graph: atoms, links, and the assertions that justify them.

Identity atoms are ``(type, value)`` pairs — ``("github_user", "mcaney006")``.
Links are evidence that two atoms are the same person, each with a confidence and
a source. The resolver treats connected components of this graph as principals;
this module just holds the typed building blocks and the graph construction.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx


@dataclass(frozen=True)
class IdentityAssertion:
    """An observed identifier for a principal, as reported by one source."""

    type: str
    value: str
    source: str
    confidence: float = 1.0

    @property
    def atom(self) -> tuple[str, str]:
        return (self.type, self.value)


@dataclass(frozen=True)
class IdentityLink:
    """Evidence that two identity atoms belong to the same principal."""

    left: tuple[str, str]
    right: tuple[str, str]
    confidence: float
    source: str
    reason: str = ""


def build_graph(
    assertions: list[IdentityAssertion], links: list[IdentityLink]
) -> nx.Graph:
    """Build the identity graph from assertions and links.

    Every asserted atom is a node carrying its strongest self-confidence and the
    sources that reported it. Links are weighted edges. Atoms that share a value
    of a type known to be globally unique (e.g. an email address) are implicitly
    linked, because the same email in two systems is strong evidence of one
    person.
    """

    graph = nx.Graph()
    for assertion in assertions:
        node = assertion.atom
        if node not in graph:
            graph.add_node(node, confidence=assertion.confidence, sources={assertion.source})
        else:
            data = graph.nodes[node]
            data["confidence"] = max(data["confidence"], assertion.confidence)
            data["sources"].add(assertion.source)

    for link in links:
        graph.add_node(link.left)
        graph.add_node(link.right)
        graph.add_edge(
            link.left,
            link.right,
            confidence=link.confidence,
            source=link.source,
            reason=link.reason,
        )

    _link_shared_unique_values(graph, assertions)
    return graph


_GLOBALLY_UNIQUE_TYPES = {"email"}


def _link_shared_unique_values(graph: nx.Graph, assertions: list[IdentityAssertion]) -> None:
    by_value: dict[str, list[tuple[str, str]]] = {}
    for assertion in assertions:
        if assertion.type in _GLOBALLY_UNIQUE_TYPES:
            by_value.setdefault(assertion.value, []).append(assertion.atom)
    for atoms in by_value.values():
        anchor = atoms[0]
        for other in atoms[1:]:
            if not graph.has_edge(anchor, other):
                graph.add_edge(
                    anchor,
                    other,
                    confidence=1.0,
                    source="shared-unique-value",
                    reason="identical email across sources",
                )
