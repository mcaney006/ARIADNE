"""Lower the surface DSL into the detection IR.

This is the front compiler pass: it walks the typed DSL objects and produces the
normalized :mod:`ariadne.rules.ast` tree, resolving duration strings to
timedeltas and flattening conditions into predicates. It performs the structural
validation that is cheap to do here (a sequence needs steps; a count needs a
positive threshold) and defers semantic linting to
:mod:`ariadne.rules.validation`.
"""

from __future__ import annotations

from ariadne.rules import dsl
from ariadne.rules.ast import (
    AbsenceIR,
    CountStepIR,
    DetectionIR,
    EventMatchIR,
    EventStepIR,
    PredicateIR,
    SequenceIR,
    StepIR,
)
from ariadne.timeutil import parse_duration


def _compile_match(pattern: dsl.Event) -> EventMatchIR:
    predicates = tuple(
        PredicateIR(field=c.field, op=c.op, value=c.value) for c in pattern.conditions
    )
    return EventMatchIR(event_type=pattern.event_type, predicates=predicates)


def _compile_step(step: dsl.Step) -> StepIR:
    if isinstance(step, dsl.Count):
        return CountStepIR(
            match=_compile_match(step.pattern),
            at_least=step.at_least,
            within=parse_duration(step.within),
        )
    if isinstance(step, dsl.Event):
        return EventStepIR(match=_compile_match(step))
    raise TypeError(f"unsupported sequence step: {type(step).__name__}")


def _compile_absence(absence: dsl.Absence) -> AbsenceIR:
    return AbsenceIR(
        match=_compile_match(absence.pattern),
        within=parse_duration(absence.within),
    )


def compile_detection(detection: dsl.Detection) -> DetectionIR:
    """Lower a :class:`ariadne.rules.dsl.Detection` into a :class:`DetectionIR`."""

    if not detection.sequence.steps:
        raise ValueError(f"detection {detection.id!r} has an empty sequence")

    sequence = SequenceIR(
        within=parse_duration(detection.sequence.within),
        steps=tuple(_compile_step(s) for s in detection.sequence.steps),
    )
    exceptions = tuple(_compile_absence(a) for a in detection.exceptions)

    return DetectionIR(
        id=detection.id,
        title=detection.title,
        severity=detection.severity,
        version=detection.version,
        join_by=detection.join_by,
        sequence=sequence,
        exceptions=exceptions,
        description=detection.description,
        tags=detection.tags,
    )
