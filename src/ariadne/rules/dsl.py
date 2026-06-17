"""The surface detection language.

A detection is an ordinary Python object built from a handful of typed
combinators. The language is deliberately small — an event matcher, a sequence,
a count, and a negative condition — because the hard part is not the syntax, it
is giving each combinator precise event-time semantics. Those semantics live in
the engine; this module is the readable front door.

Example::

    from ariadne.rules import Detection, Sequence, Event, Count, Absence

    departing_engineer = Detection(
        id="ARI-IR-0042",
        title="Restricted repository collection followed by data staging",
        severity="critical",
        join_by=("actor.user_id", "device.id"),
        sequence=Sequence(
            within="45m",
            steps=[
                Count(
                    Event("github.repository.clone").where(
                        repository_sensitivity="restricted",
                        access_is_first_seen=True,
                    ),
                    at_least=8,
                    within="15m",
                ),
                Event("process.execution").where(process_name__in={"zip", "7z", "tar", "gpg"}),
                Event("filesystem.write").where(destination_type__in={"removable_media", "cloud_sync_folder"}),
                Event("security.telemetry_state").where(state__in={"stopped", "disabled", "degraded"}),
            ],
        ),
        exceptions=[
            Absence(Event("change_management.approval").where(approval_status="approved"), within="24h"),
        ],
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from ariadne.events.schema import Event as TelemetryEvent
from ariadne.rules.predicates import describe, evaluate, split_operator

Severity = str  # "info" | "low" | "medium" | "high" | "critical"


@dataclass(frozen=True)
class Condition:
    """One ``field op value`` predicate on an event."""

    field: str
    op: str
    value: Any

    def matches(self, event: TelemetryEvent) -> bool:
        return evaluate(self.field, self.op, self.value, event)

    def describe(self) -> str:
        return describe(self.field, self.op, self.value)


@dataclass(frozen=True)
class Event:
    """An event matcher: an event type plus zero or more field conditions.

    ``where`` is chainable and *functional* — each call returns a new matcher
    with the extra conditions appended, so a matcher can be safely reused and
    specialised without mutating a shared object.
    """

    event_type: str
    conditions: tuple[Condition, ...] = ()

    def where(self, **predicates: Any) -> Event:
        """Return a copy of this matcher with extra field conditions.

        Keyword names follow the ``field`` or ``field__op`` convention; the
        operator vocabulary is documented in :mod:`ariadne.rules.predicates`.
        """

        extra = tuple(
            Condition(*split_operator(key), value) for key, value in predicates.items()
        )
        return replace(self, conditions=self.conditions + extra)

    def matches(self, event: TelemetryEvent) -> bool:
        return event.event_type == self.event_type and all(
            c.matches(event) for c in self.conditions
        )


@dataclass(frozen=True)
class Count:
    """A sequence step satisfied by *at least* ``at_least`` matches within a window.

    The window is measured event-time-to-event-time across the qualifying
    events; the step is considered to complete at the moment the threshold is
    reached (the ``at_least``-th qualifying event), and that completion time is
    the anchor the next step must follow.
    """

    pattern: Event
    at_least: int = 1
    within: str = "15m"

    def __post_init__(self) -> None:
        if self.at_least < 1:
            raise ValueError("Count.at_least must be >= 1")


@dataclass(frozen=True)
class Absence:
    """A negative condition: the pattern must **not** occur within ``within``.

    Used both as a sequence-level exception (an authorising event that suppresses
    the alert) and, in principle, as an inline negative step. Absence is what
    lets ARIADNE reason about events that *should* exist but do not.
    """

    pattern: Event
    within: str = "24h"


# A sequence step is either a single event match or a count of matches.
Step = Event | Count


@dataclass(frozen=True)
class Sequence:
    """An ordered chain of steps that must occur within ``within``.

    Steps match in order on event-time: each step's anchor must be at or after
    the previous step's anchor, and the whole chain must fit inside ``within``.
    """

    within: str
    steps: tuple[Step, ...]

    def __init__(self, within: str, steps: list[Step] | tuple[Step, ...]):
        object.__setattr__(self, "within", within)
        object.__setattr__(self, "steps", tuple(steps))


@dataclass(frozen=True)
class Detection:
    """A complete, versioned behavioural detection.

    ``join_by`` is the set of fields whose equality binds events into one
    candidate chain — typically the resolved actor and the device. ``exceptions``
    are authorising conditions whose presence suppresses an otherwise-firing
    detection (the contextual half of "contextual detection, not keyword
    matching").
    """

    id: str
    title: str
    sequence: Sequence
    severity: Severity = "medium"
    join_by: tuple[str, ...] = ("actor.user_id",)
    exceptions: tuple[Absence, ...] = ()
    description: str | None = None
    version: str = "1"
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __init__(
        self,
        id: str,
        title: str,
        sequence: Sequence,
        severity: Severity = "medium",
        join_by: tuple[str, ...] = ("actor.user_id",),
        exceptions: list[Absence] | tuple[Absence, ...] = (),
        description: str | None = None,
        version: str = "1",
        tags: list[str] | tuple[str, ...] = (),
    ):
        object.__setattr__(self, "id", id)
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "sequence", sequence)
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "join_by", tuple(join_by))
        object.__setattr__(self, "exceptions", tuple(exceptions))
        object.__setattr__(self, "description", description)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "tags", tuple(tags))
