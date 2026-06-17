"""Human-readable "why this fired" expansion of a matched detection.

Walks the detection IR alongside the events the engine actually assigned to each
step and produces one plain sentence per condition. This is the panel that lets a
reviewer audit the firing line by line instead of trusting a score.
"""

from __future__ import annotations

from ariadne.engines.reference import SequenceMatch
from ariadne.engines.sequence import StepMatch
from ariadne.rules.ast import CountStepIR, DetectionIR
from ariadne.timeutil import format_duration


def _event_span(step: StepMatch) -> str:
    times = [e.event_time for e in step.events]
    span = max(times) - min(times)
    return format_duration(span)


def explain_match(detection: DetectionIR, match: SequenceMatch) -> list[str]:
    """Return one explanation line per rule condition for a firing."""

    lines: list[str] = []
    steps = detection.sequence.steps

    for step_ir, step_match in zip(steps, match.assignment.steps):
        ids = ", ".join(e.event_id for e in step_match.events)
        if isinstance(step_ir, CountStepIR):
            lines.append(
                f"Step {step_match.step_index + 1} — at least {step_ir.at_least} "
                f"{step_ir.match.event_type} within {format_duration(step_ir.within)}: "
                f"satisfied by {len(step_match.events)} events spanning {_event_span(step_match)} "
                f"[{ids}]"
            )
            for predicate in step_ir.match.predicates:
                lines.append(f"    · {predicate.describe()}")
        else:
            lines.append(
                f"Step {step_match.step_index + 1} — {step_ir.match.describe()}: "
                f"matched by [{ids}]"
            )

    for absence in detection.exceptions:
        suppressed = absence.match.describe() in match.suppressed_by
        verdict = (
            "an authorising event was found, so the detection was SUPPRESSED"
            if suppressed
            else "no authorising event within window, so the negative condition holds"
        )
        lines.append(
            f"Exception — no {absence.match.describe()} within "
            f"{format_duration(absence.within)}: {verdict}"
        )

    return lines
