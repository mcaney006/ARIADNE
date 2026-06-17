"""Minimal decisive evidence — the smallest event set that still fires the rule.

This is the feature that proves ARIADNE *understands* its own logic rather than
emitting a mystery score. Given the events that contributed to a firing, it
finds a 1-minimal subset: a set from which no single event can be removed without
the detection ceasing to fire. The reviewer can read those few event ids and see
exactly what was load-bearing.

The minimisation is delta-debugging style — greedily drop events and keep the
drop whenever the detection still triggers — and it *re-runs the real engine* to
check each candidate, so the result is verified, not asserted.
"""

from __future__ import annotations

from ariadne.engines.reference import ReferenceEngine
from ariadne.events.schema import Event
from ariadne.rules.ast import DetectionIR


def minimal_decisive_evidence(
    detection: DetectionIR, contributing_events: tuple[Event, ...]
) -> list[Event]:
    """Return a 1-minimal subset of ``contributing_events`` that still fires.

    The search starts from the events the match actually used and removes events
    one at a time, repeating until a full pass removes nothing. The result is the
    minimal decisive evidence set; its event ids are what the case reports.
    """

    engine = ReferenceEngine()

    def fires(candidate: list[Event]) -> bool:
        return engine.evaluate(candidate, detection).triggered

    candidate = list(contributing_events)
    if not fires(candidate):
        # Degenerate guard: if the supplied events do not fire on their own
        # there is nothing to minimise; report them as-is rather than lie.
        return sorted(candidate, key=Event.sort_key)

    changed = True
    while changed:
        changed = False
        for event in list(candidate):
            trial = [e for e in candidate if e.event_id != event.event_id]
            if trial and fires(trial):
                candidate = trial
                changed = True

    return sorted(candidate, key=Event.sort_key)
