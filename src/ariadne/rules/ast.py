"""The detection intermediate representation (IR).

The surface DSL is convenient to write; the IR is convenient to *reason about*.
Lowering the DSL into this normalized tree — durations resolved to timedeltas,
predicates flattened to a uniform list, ordering made explicit — gives every
backend one stable structure to walk. The local engine evaluates it, the SIEM
compilers translate it, and :func:`render_tree` draws it.

Keeping evaluation on the IR (rather than the DSL) is the compiler discipline
that makes the project a compiler and not a bag of if-statements: there is one
canonical form, and everything downstream is a pass over it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from ariadne.events.schema import Event
from ariadne.rules.predicates import describe, evaluate
from ariadne.timeutil import format_duration


@dataclass(frozen=True)
class PredicateIR:
    """A normalized ``field op value`` condition."""

    field: str
    op: str
    value: object

    def matches(self, event: Event) -> bool:
        return evaluate(self.field, self.op, self.value, event)

    def describe(self) -> str:
        return describe(self.field, self.op, self.value)


@dataclass(frozen=True)
class EventMatchIR:
    """An event-type filter plus a conjunction of predicates."""

    event_type: str
    predicates: tuple[PredicateIR, ...] = ()

    def matches(self, event: Event) -> bool:
        return event.event_type == self.event_type and all(
            p.matches(event) for p in self.predicates
        )

    def describe(self) -> str:
        if not self.predicates:
            return self.event_type
        preds = " AND ".join(p.describe() for p in self.predicates)
        return f"{self.event_type} where {preds}"


@dataclass(frozen=True)
class StepIR:
    """Base class for sequence steps. Subclasses are the tagged variants."""

    match: EventMatchIR


@dataclass(frozen=True)
class EventStepIR(StepIR):
    """A single "followed by <event>" step."""


@dataclass(frozen=True)
class CountStepIR(StepIR):
    """A "followed by N or more <event> within W" step."""

    at_least: int = 1
    within: timedelta = timedelta(minutes=15)


@dataclass(frozen=True)
class AbsenceIR:
    """A negative condition: ``match`` must not occur within ``within``."""

    match: EventMatchIR
    within: timedelta


@dataclass(frozen=True)
class SequenceIR:
    """An ordered chain of steps constrained by an overall ``within`` window."""

    within: timedelta
    steps: tuple[StepIR, ...]


@dataclass(frozen=True)
class DetectionIR:
    """The fully lowered detection."""

    id: str
    title: str
    severity: str
    version: str
    join_by: tuple[str, ...]
    sequence: SequenceIR
    exceptions: tuple[AbsenceIR, ...] = ()
    description: str | None = None
    tags: tuple[str, ...] = ()

    @property
    def pinned_id(self) -> str:
        """The version-pinned identifier used when comparing rule versions."""

        return f"{self.id}@v{self.version}"


def render_tree(detection: DetectionIR) -> str:
    """Render a detection IR as the ASCII tree shown in the README and CLI."""

    lines: list[str] = [f"Detection {detection.id}  (v{detection.version}, {detection.severity})"]
    lines.append(f"  ├── Title: {detection.title}")
    lines.append(f"  ├── Join: {', '.join(detection.join_by)}")
    lines.append(f"  ├── Window: {format_duration(detection.sequence.within)}")

    steps = detection.sequence.steps
    for index, step in enumerate(steps):
        last_step = index == len(steps) - 1 and not detection.exceptions
        connector = "└──" if last_step else "├──"
        if isinstance(step, CountStepIR):
            lines.append(f"  {connector} Count: {step.match.event_type}")
            for pred in step.match.predicates:
                lines.append(f"  │     {pred.describe()}")
            lines.append(
                f"  │     threshold ≥ {step.at_least} within {format_duration(step.within)}"
            )
        else:
            verb = "Step" if index == 0 else "FollowedBy"
            lines.append(f"  {connector} {verb}: {step.match.describe()}")

    for index, absence in enumerate(detection.exceptions):
        last = index == len(detection.exceptions) - 1
        connector = "└──" if last else "├──"
        lines.append(
            f"  {connector} NegativeCondition: no {absence.match.describe()} "
            f"within {format_duration(absence.within)}"
        )

    return "\n".join(lines)
