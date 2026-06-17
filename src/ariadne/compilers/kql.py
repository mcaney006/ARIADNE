"""Compile a detection IR to Microsoft Sentinel / Kusto KQL.

Kusto's ``scan`` operator walks an ordered stream through a small state machine,
which is the closest native analogue to an ARIADNE sequence. Each step becomes a
``scan`` step guarded by its predicate; the overall window is enforced with a
post-filter on the time between the first and last matched rows. Count thresholds
are annotated, since ``scan`` matches one row per step.
"""

from __future__ import annotations

from ariadne.compilers.base import render_conjunction
from ariadne.rules.ast import CountStepIR, DetectionIR
from ariadne.timeutil import format_duration


def compile_kql(detection: DetectionIR) -> str:
    by = ", ".join(detection.join_by)
    event_types = sorted({step.match.event_type for step in detection.sequence.steps})
    type_list = ", ".join(f'"{t}"' for t in event_types)
    within = format_duration(detection.sequence.within)

    lines = [
        "Events",
        f"| where event_type in ({type_list})",
        f"| partition by {by} (",
        "    order by event_time asc",
        "    | scan with (",
    ]

    for index, step in enumerate(detection.sequence.steps):
        cond = render_conjunction(step.match.predicates, "kql")
        guard = f'event_type == "{step.match.event_type}" and {cond}'
        annotation = ""
        if isinstance(step, CountStepIR):
            annotation = (
                f" // ARIADNE: >= {step.at_least} within {format_duration(step.within)}"
            )
        lines.append(f"        step s{index} : {guard};{annotation}")

    lines.append("    )")
    lines.append(")")
    lines.append(f"| where matched_end - matched_start <= {within}")

    for absence in detection.exceptions:
        cond = render_conjunction(absence.match.predicates, "kql")
        lines.append(
            f'| where not (event_type == "{absence.match.event_type}" and {cond})'
            "  // suppressing exception"
        )

    return "\n".join(lines)
