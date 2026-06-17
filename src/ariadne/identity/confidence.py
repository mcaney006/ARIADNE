"""Confidence arithmetic for identity links.

Two small, explicit rules. Along a *chain* of links, confidence multiplies — a
weak link anywhere weakens the whole inference. Across *independent* pieces of
evidence for the same equivalence, confidence combines by noisy-OR — more
corroboration only ever raises confidence, never lowers it. Keeping these
explicit is what lets the resolver attach a defensible number to every identity
instead of a vibe.
"""

from __future__ import annotations

from collections.abc import Iterable


def path_confidence(edge_confidences: Iterable[float]) -> float:
    """Confidence of a chain of links = product of the link confidences."""

    result = 1.0
    for value in edge_confidences:
        result *= value
    return result


def merge_confidence(values: Iterable[float]) -> float:
    """Combine independent evidences for the same fact (noisy-OR).

    ``1 - Π(1 - v)``. Two independent 0.8 links yield 0.96, not 0.64.
    """

    complement = 1.0
    for value in values:
        complement *= 1.0 - value
    return 1.0 - complement
