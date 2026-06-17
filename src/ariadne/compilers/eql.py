"""Compile a detection IR to Elastic EQL.

EQL's ``sequence by ... with maxspan`` maps cleanly onto ARIADNE sequences, and
its ``until`` clause is a natural home for a suppressing exception: if the
authorising event occurs, the sequence is abandoned. EQL has no first-class
"N occurrences within a sub-window" inside a sequence, so a count step is
emitted as its event bracket with the threshold preserved as an inline
annotation for the rule author to enforce with ``with runs`` or a downstream
aggregation.
"""

from __future__ import annotations

from ariadne.compilers.base import render_conjunction
from ariadne.rules.ast import CountStepIR, DetectionIR
from ariadne.timeutil import format_duration


def compile_eql(detection: DetectionIR) -> str:
    by = ", ".join(detection.join_by)
    maxspan = format_duration(detection.sequence.within)
    lines = [f"sequence by {by} with maxspan={maxspan}"]

    for step in detection.sequence.steps:
        where = render_conjunction(step.match.predicates, "eql")
        bracket = f"  [{step.match.event_type} where {where}]"
        if isinstance(step, CountStepIR):
            bracket += (
                f"  /* ARIADNE: >= {step.at_least} occurrences within "
                f"{format_duration(step.within)} */"
            )
        lines.append(bracket)

    for absence in detection.exceptions:
        where = render_conjunction(absence.match.predicates, "eql")
        lines.append(f"until [{absence.match.event_type} where {where}]")

    return "\n".join(lines)
