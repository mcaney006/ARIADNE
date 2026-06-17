"""The greedy, earliest-match sequence matcher.

Given the canonically ordered events of a single join group, this finds an
assignment of events to the steps of a :class:`SequenceIR` that respects order,
the per-step count windows, and the overall sequence window.

The algorithm is *greedy earliest*: for each step it takes the earliest events
that satisfy the step after the previous step's anchor. Earliest-match minimizes
the end time of the chain, which makes it optimal for the only question that
matters — "does an admissible assignment exist within the window?" — and, because
the input is canonically sorted, it is fully deterministic. The same multiset of
events always yields the same assignment regardless of arrival order.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ariadne.engines.windows import earliest_count_window
from ariadne.events.schema import Event
from ariadne.rules.ast import CountStepIR, SequenceIR, StepIR


@dataclass(frozen=True)
class StepMatch:
    """The events assigned to one step of a matched sequence."""

    step_index: int
    events: tuple[Event, ...]

    @property
    def anchor(self) -> datetime:
        """The event-time at which this step is considered complete."""

        return self.events[-1].event_time


@dataclass(frozen=True)
class SequenceAssignment:
    """A complete, ordered assignment of events to every step in a sequence."""

    steps: tuple[StepMatch, ...]

    @property
    def start_time(self) -> datetime:
        return min(e.event_time for s in self.steps for e in s.events)

    @property
    def end_time(self) -> datetime:
        return max(e.event_time for s in self.steps for e in s.events)

    @property
    def events(self) -> tuple[Event, ...]:
        seen: dict[str, Event] = {}
        for step in self.steps:
            for event in step.events:
                seen.setdefault(event.event_id, event)
        return tuple(sorted(seen.values(), key=Event.sort_key))


def _match_count_step(
    events: list[Event],
    start_index: int,
    anchor: datetime | None,
    chain_start: datetime | None,
    overall_within: timedelta,
    step: CountStepIR,
) -> tuple[list[Event], int] | None:
    candidates: list[Event] = []
    indices: list[int] = []
    for index in range(start_index, len(events)):
        event = events[index]
        if anchor is not None and event.event_time < anchor:
            continue
        if not step.match.matches(event):
            continue
        candidates.append(event)
        indices.append(index)

    window = earliest_count_window(candidates, step.at_least, step.within)
    if window is None:
        return None

    first, last = window[0], window[-1]
    effective_start = chain_start if chain_start is not None else first.event_time
    if last.event_time > effective_start + overall_within:
        return None

    last_pos = candidates.index(last)
    next_index = indices[last_pos] + 1
    return window, next_index


def _match_event_step(
    events: list[Event],
    start_index: int,
    anchor: datetime | None,
    chain_start: datetime | None,
    overall_within: timedelta,
    step: StepIR,
) -> tuple[Event, int] | None:
    for index in range(start_index, len(events)):
        event = events[index]
        if anchor is not None and event.event_time < anchor:
            continue
        if not step.match.matches(event):
            continue
        if chain_start is not None and event.event_time > chain_start + overall_within:
            return None
        return event, index + 1
    return None


def match_sequence(events: list[Event], sequence: SequenceIR) -> SequenceAssignment | None:
    """Return the earliest admissible assignment, or ``None`` if none exists.

    ``events`` must be canonically ordered and already scoped to a single join
    group.
    """

    cursor = 0
    anchor: datetime | None = None
    chain_start: datetime | None = None
    step_matches: list[StepMatch] = []

    for step_index, step in enumerate(sequence.steps):
        if isinstance(step, CountStepIR):
            result = _match_count_step(
                events, cursor, anchor, chain_start, sequence.within, step
            )
            if result is None:
                return None
            window, cursor = result
            if chain_start is None:
                chain_start = window[0].event_time
            anchor = window[-1].event_time
            step_matches.append(StepMatch(step_index, tuple(window)))
        else:
            result = _match_event_step(
                events, cursor, anchor, chain_start, sequence.within, step
            )
            if result is None:
                return None
            event, cursor = result
            if chain_start is None:
                chain_start = event.event_time
            anchor = event.event_time
            step_matches.append(StepMatch(step_index, (event,)))

    return SequenceAssignment(tuple(step_matches))
