"""Durability scoring and telemetry-coverage measurement.

:func:`durability_report` is what fills the case's "Detection durability" panel:
it re-evaluates a detection under each adversarial mutation and records whether
the set of fired cases is unchanged. Non-destructive mutations are expected to
pass; destructive ones reveal exactly which telemetry the detection cannot live
without. :func:`field_coverage` quantifies how much of the stream actually
carries each field a detection depends on — the number that explains a
regression.
"""

from __future__ import annotations

from dataclasses import dataclass

from ariadne.engines.reference import ReferenceEngine
from ariadne.events.schema import Event, resolve_field
from ariadne.investigation.case import DurabilityProfile
from ariadne.replay import mutation
from ariadne.rules.ast import CountStepIR, DetectionIR
from ariadne.rules.compiler import compile_detection
from ariadne.rules.dsl import Detection


def _ir(detection: Detection | DetectionIR) -> DetectionIR:
    return detection if isinstance(detection, DetectionIR) else compile_detection(detection)


def durability_report(
    detection: Detection | DetectionIR,
    events: list[Event],
    *,
    classification_field: str | None = "repository_sensitivity",
    optional_source_type: str = "dns.query",
) -> DurabilityProfile:
    """Probe a firing's robustness under mutation.

    The non-destructive mutations and the two ARIADNE-specific cases (a tolerable
    clock skew, a dropped optional source) should leave the verdict untouched.
    Dropping the classification field the count step depends on is expected to
    break it — and naming that failure is the point of the panel.
    """

    ir = _ir(detection)
    engine = ReferenceEngine()
    baseline = engine.evaluate(events, ir).case_ids
    profile = DurabilityProfile()

    if not baseline:
        return profile

    def check(label: str, mutated: list[Event]) -> None:
        result = engine.evaluate(mutated, ir).case_ids
        (profile.passes if result == baseline else profile.fails).append(label)

    check("Late events", mutation.with_lateness(events, max_lateness="12m", seed=7))
    check("Duplicate events", mutation.duplicate(events, fraction=0.3, seed=8))
    check("Collector reconnect", mutation.reconnect(events, window=6, seed=9))

    skew_source = _dominant_source(events)
    check("5-minute clock skew", mutation.clock_skew(events, source=skew_source, skew="5m"))
    check(f"Missing {optional_source_type} telemetry", mutation.drop_type(events, optional_source_type))

    if classification_field:
        check(
            f"Missing {classification_field} classification",
            mutation.drop_field(events, classification_field),
        )

    return profile


def field_coverage(events: list[Event], ir: DetectionIR) -> dict[str, float]:
    """Fraction of relevant events that actually carry each referenced field.

    "Relevant" is scoped per event type: a clone's ``repository_sensitivity`` is
    only expected on clone events, so coverage is computed against that type's
    population, not the whole stream.
    """

    coverage: dict[str, float] = {}
    for step in ir.sequence.steps:
        etype = step.match.event_type
        population = [e for e in events if e.event_type == etype]
        for predicate in step.match.predicates:
            present = sum(1 for e in population if resolve_field(e, predicate.field) is not None)
            coverage[f"{etype}.{predicate.field}"] = (
                present / len(population) if population else 0.0
            )
    return coverage


def _dominant_source(events: list[Event]) -> str:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.provenance.source] = counts.get(event.provenance.source, 0) + 1
    if not counts:
        return "unknown"
    return max(counts, key=lambda s: (counts[s], s))


def count_step_fields(ir: DetectionIR) -> list[str]:
    """The fields any count step depends on — the usual regression suspects."""

    fields: list[str] = []
    for step in ir.sequence.steps:
        if isinstance(step, CountStepIR):
            fields.extend(p.field for p in step.match.predicates)
    return fields
