"""Deterministic, adversarial event-stream mutations.

These are the perturbations a real telemetry pipeline inflicts on its own data:
reordering, duplication, lateness, clock drift, a dropped source, a missing
field. Each mutator is a pure function of its inputs and an explicit seed, so a
durability result is reproducible and a failing property-test case shrinks to
something a human can read.

The contract every *non-destructive* mutator upholds is that it preserves the
multiset of real observations — it changes how events arrive, not what happened —
which is exactly the class of change a correct detection must be invariant to.
The *destructive* mutators (:func:`drop_type`, :func:`drop_field`) deliberately
remove information; they are how we probe what telemetry a detection truly needs.
"""

from __future__ import annotations

from datetime import timedelta
from random import Random
from typing import Callable

from ariadne.events.schema import Event
from ariadne.timeutil import parse_duration


def shuffle(events: list[Event], *, seed: int = 0) -> list[Event]:
    """Return the events in a randomized arrival order (event-times unchanged)."""

    out = list(events)
    Random(seed).shuffle(out)
    return out


def duplicate(events: list[Event], *, fraction: float = 0.2, seed: int = 0) -> list[Event]:
    """Append exact duplicates of a random subset (same ids — true replays)."""

    rng = Random(seed)
    extra = [e for e in events if rng.random() < fraction]
    return list(events) + extra


def with_lateness(
    events: list[Event], *, max_lateness: str | timedelta = "10m", seed: int = 0
) -> list[Event]:
    """Stamp each event with a randomized ``observed_time`` after its event-time.

    Models late arrival without altering when the event actually happened, which
    is the distinction event-time semantics are built to respect.
    """

    rng = Random(seed)
    span = parse_duration(max_lateness).total_seconds()
    out: list[Event] = []
    for event in events:
        delay = timedelta(seconds=rng.random() * span)
        out.append(event.model_copy(update={"observed_time": event.event_time + delay}))
    return out


def clock_skew(
    events: list[Event], *, source: str, skew: str | timedelta = "5m"
) -> list[Event]:
    """Shift every event from ``source`` by ``skew`` (a drifting source clock).

    Intra-source spacing is preserved; only the offset relative to other sources
    changes. A robust detection tolerates this up to its window slack.
    """

    delta = parse_duration(skew)
    out: list[Event] = []
    for event in events:
        if event.provenance.source == source:
            out.append(event.model_copy(update={"event_time": event.event_time + delta}))
        else:
            out.append(event)
    return out


def reconnect(events: list[Event], *, window: int = 6, seed: int = 0) -> list[Event]:
    """Simulate a collector reconnect: re-emit a slice of events, then shuffle.

    The re-emitted events carry their original ids, so an idempotent engine must
    fold them away. Combined with reordering, this is the nastiest benign case a
    streaming detector faces.
    """

    if not events:
        return []
    replayed = events[:window]
    return shuffle(list(events) + replayed, seed=seed)


def drop_type(events: list[Event], event_type: str) -> list[Event]:
    """Remove every event of a type (a whole telemetry source going dark)."""

    return [e for e in events if e.event_type != event_type]


def drop_field(events: list[Event], field: str) -> list[Event]:
    """Strip an attribute from every event (a classification pipeline failing)."""

    out: list[Event] = []
    for event in events:
        if field in event.attributes:
            attributes = dict(event.attributes)
            attributes.pop(field, None)
            out.append(event.model_copy(update={"attributes": attributes}))
        else:
            out.append(event)
    return out


#: Mutators that must not change a correct detection's verdict.
NON_DESTRUCTIVE: dict[str, Callable[[list[Event]], list[Event]]] = {
    "shuffle": lambda ev: shuffle(ev, seed=1),
    "duplicate": lambda ev: duplicate(ev, fraction=0.3, seed=2),
    "lateness": lambda ev: with_lateness(ev, max_lateness="12m", seed=3),
    "reconnect": lambda ev: reconnect(ev, window=6, seed=4),
}
