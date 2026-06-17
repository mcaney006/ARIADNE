"""Compile a detection IR to Splunk SPL.

Splunk has no sequence operator, so the standard idiom is to gather the relevant
events, ``transaction`` them by the join keys within ``maxspan``, and then assert
the per-phase conditions with ``eval`` flags and a final ``where``. Count
thresholds become an ``eval`` count of qualifying events inside the transaction.
The result is verbose but faithful to the join-and-window semantics.
"""

from __future__ import annotations

from ariadne.compilers.base import render_conjunction, sql_column
from ariadne.rules.ast import CountStepIR, DetectionIR
from ariadne.timeutil import format_duration


def _spl_seconds(detection: DetectionIR) -> int:
    return int(detection.sequence.within.total_seconds())


def compile_spl(detection: DetectionIR) -> str:
    event_types = sorted({step.match.event_type for step in detection.sequence.steps})
    type_filter = " OR ".join(f'event_type="{t}"' for t in event_types)
    by = " ".join(sql_column(f) for f in detection.join_by)
    maxspan = _spl_seconds(detection)

    lines = [f"search ({type_filter})"]
    lines.append(f"| transaction {by} maxspan={maxspan}s")

    flags: list[str] = []
    checks: list[str] = []
    for index, step in enumerate(detection.sequence.steps):
        cond = render_conjunction(step.match.predicates, "spl", joiner=" AND ")
        base = f'event_type="{step.match.event_type}" AND {cond}'
        if isinstance(step, CountStepIR):
            flags.append(f'| eval phase{index}=mvcount(mvfilter(match(_raw, "{step.match.event_type}")))')
            checks.append(f"phase{index} >= {step.at_least}")
            lines.append(
                f"| eval phase{index}_count=if(searchmatch(\"{base}\"), 1, 0)  "
                f"`comment(\"ARIADNE count step: >= {step.at_least} within {format_duration(step.within)}\")`"
            )
            checks[-1] = f"phase{index}_count >= {step.at_least}"
        else:
            lines.append(f'| eval phase{index}=if(searchmatch("{base}"), 1, 0)')
            checks.append(f"phase{index} >= 1")

    for absence in detection.exceptions:
        cond = render_conjunction(absence.match.predicates, "spl", joiner=" AND ")
        lines.append(
            f'| eval suppress=if(searchmatch("event_type=\\"{absence.match.event_type}\\" AND {cond}"), 1, 0)'
        )
        checks.append("suppress = 0")

    lines.append("| where " + " AND ".join(checks))
    return "\n".join(lines)
