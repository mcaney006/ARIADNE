"""Differential analysis across rule versions — find and *explain* regressions.

This powers ``ariadne diff``. Given the same incident and two versions of a
detection, it reports who fired and, when version 2 silently stops firing, it
diagnoses why: it aligns the two ASTs, finds the constraint version 2 added, and
measures how much of the scenario's telemetry can actually satisfy that new
constraint. A regression caused by 31% of events lacking a field is a very
different problem from a logic error, and the diff says which it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ariadne.engines.reference import ReferenceEngine
from ariadne.events.schema import Event
from ariadne.replay.metrics import field_coverage
from ariadne.rules.ast import CountStepIR, DetectionIR, PredicateIR
from ariadne.rules.compiler import compile_detection
from ariadne.rules.dsl import Detection


def _ir(detection: Detection | DetectionIR) -> DetectionIR:
    return detection if isinstance(detection, DetectionIR) else compile_detection(detection)


@dataclass
class RuleDiff:
    detection_id: str
    v1_version: str
    v2_version: str
    v1_triggered: bool
    v2_triggered: bool
    v1_support: int
    v2_support: int
    regression: bool
    improvement: bool
    cause: str | None = None
    impact: str | None = None
    recommendation: str | None = None
    added_predicates: list[str] = field(default_factory=list)
    removed_predicates: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines: list[str] = []
        if self.regression:
            lines.append("DETECTION REGRESSION FOUND")
        elif self.improvement:
            lines.append("DETECTION IMPROVEMENT FOUND")
        else:
            lines.append("NO BEHAVIOURAL CHANGE")
        lines.append("")
        lines.append(f"Rule:\n  {self.detection_id}")
        lines.append("")
        lines.append(
            f"Version {self.v1_version}:\n  "
            + (f"Triggered (supporting events: {self.v1_support})" if self.v1_triggered else "Did not trigger")
        )
        lines.append(
            f"Version {self.v2_version}:\n  "
            + (f"Triggered (supporting events: {self.v2_support})" if self.v2_triggered else "Did not trigger")
        )
        if self.cause:
            lines.append("")
            lines.append(f"Cause:\n  {self.cause}")
        if self.impact:
            lines.append("")
            lines.append(f"Impact:\n  {self.impact}")
        if self.recommendation:
            lines.append("")
            lines.append(f"Recommended correction:\n  {self.recommendation}")
        return "\n".join(lines)


def _predicate_signature(ir: DetectionIR) -> dict[str, PredicateIR]:
    sig: dict[str, PredicateIR] = {}
    for step in ir.sequence.steps:
        for predicate in step.match.predicates:
            key = f"{step.match.event_type}|{predicate.field}|{predicate.op}|{predicate.value!r}"
            sig[key] = predicate
    return sig


def diff_detections(
    events: list[Event],
    v1: Detection | DetectionIR,
    v2: Detection | DetectionIR,
) -> RuleDiff:
    """Compare two rule versions against one incident and explain any regression."""

    ir1, ir2 = _ir(v1), _ir(v2)
    engine = ReferenceEngine()
    r1 = engine.evaluate(events, ir1)
    r2 = engine.evaluate(events, ir2)

    v1_alert = r1.alerts[0] if r1.alerts else None
    v2_alert = r2.alerts[0] if r2.alerts else None
    v1_support = len(v1_alert.contributing_events) if v1_alert else 0
    v2_support = len(v2_alert.contributing_events) if v2_alert else 0

    sig1 = _predicate_signature(ir1)
    sig2 = _predicate_signature(ir2)
    added = [sig2[k] for k in sig2.keys() - sig1.keys()]
    removed = [sig1[k] for k in sig1.keys() - sig2.keys()]

    diff = RuleDiff(
        detection_id=ir1.id,
        v1_version=ir1.version,
        v2_version=ir2.version,
        v1_triggered=r1.triggered,
        v2_triggered=r2.triggered,
        v1_support=v1_support,
        v2_support=v2_support,
        regression=r1.triggered and not r2.triggered,
        improvement=r2.triggered and not r1.triggered,
        added_predicates=[p.describe() for p in added],
        removed_predicates=[p.describe() for p in removed],
    )

    if diff.regression:
        _diagnose_regression(diff, events, ir1, ir2, added)
    return diff


def _diagnose_regression(
    diff: RuleDiff,
    events: list[Event],
    ir1: DetectionIR,
    ir2: DetectionIR,
    added: list[PredicateIR],
) -> None:
    coverage = field_coverage(events, ir2)

    # 1) A newly-required field that the telemetry frequently lacks.
    worst_field: tuple[str, float] | None = None
    for step in ir2.sequence.steps:
        for predicate in step.match.predicates:
            if not any(
                p.field == predicate.field and p.op == predicate.op and p.value == predicate.value
                for p in added
            ):
                continue
            key = f"{step.match.event_type}.{predicate.field}"
            cov = coverage.get(key, 1.0)
            if worst_field is None or cov < worst_field[1]:
                worst_field = (key, cov)

    if worst_field and worst_field[1] < 1.0:
        key, cov = worst_field
        etype, _, fieldname = key.rpartition(".")
        missing_pct = (1.0 - cov) * 100.0
        diff.cause = (
            f"Version {ir2.version} requires {fieldname} on {etype}; "
            f"{missing_pct:.1f}% of those events lacked the classification telemetry"
        )
        diff.impact = "False-negative introduced"
        diff.recommendation = (
            f"Permit an alternate signal (e.g. repository sensitivity) to satisfy the "
            f"{fieldname} condition when per-event classification is unavailable"
        )
        return

    # 2) A raised count threshold.
    for s1, s2 in zip(ir1.sequence.steps, ir2.sequence.steps):
        if isinstance(s1, CountStepIR) and isinstance(s2, CountStepIR) and s2.at_least > s1.at_least:
            diff.cause = (
                f"Version {ir2.version} raised the count threshold from {s1.at_least} "
                f"to {s2.at_least}; the incident no longer reaches it"
            )
            diff.impact = "False-negative introduced"
            diff.recommendation = (
                f"Lower the threshold or widen the count window from "
                f"{s1.within} to admit the observed volume"
            )
            return

    # 3) A narrowed window.
    if ir2.sequence.within < ir1.sequence.within:
        diff.cause = (
            f"Version {ir2.version} narrowed the sequence window from "
            f"{ir1.sequence.within} to {ir2.sequence.within}"
        )
        diff.impact = "False-negative introduced"
        diff.recommendation = "Restore a window wide enough to contain the observed chain"
        return

    diff.cause = "Version 2 changed the detection logic such that the incident no longer matches"
    diff.impact = "False-negative introduced"
    diff.recommendation = "Review the added constraints against the scenario's telemetry"
