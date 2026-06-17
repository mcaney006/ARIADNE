"""Compile a detection IR to ClickHouse SQL.

ClickHouse is the best structural fit of the four backends: ``windowFunnel``
enforces an ordered sequence inside a time window, and ``sequenceCount`` /
``countIf`` express the count threshold directly. The compiler groups by the join
keys and emits one ``HAVING`` per semantic: the funnel reaching its final step,
the count step meeting its threshold, and the absence of any authorising event.
This is the high-volume execution path referenced in the architecture diagram.
"""

from __future__ import annotations

from ariadne.compilers.base import render_conjunction, sql_column
from ariadne.rules.ast import CountStepIR, DetectionIR


def compile_clickhouse(detection: DetectionIR, table: str = "events") -> str:
    window_seconds = int(detection.sequence.within.total_seconds())
    group_cols = [sql_column(f) for f in detection.join_by]

    conditions: list[str] = []
    for step in detection.sequence.steps:
        cond = render_conjunction(step.match.predicates, "sql", joiner=" AND ")
        conditions.append(f'event_type = \'{step.match.event_type}\' AND ({cond})')

    funnel_args = ",\n        ".join(conditions)
    select_cols = ", ".join(group_cols)

    lines = [
        f"SELECT {select_cols}",
        f"FROM {table}",
        f"GROUP BY {select_cols}",
        "HAVING",
        f"    windowFunnel({window_seconds})(",
        "        toUnixTimestamp(event_time),",
        f"        {funnel_args}",
        f"    ) = {len(conditions)}",
    ]

    for index, step in enumerate(detection.sequence.steps):
        if isinstance(step, CountStepIR):
            cond = render_conjunction(step.match.predicates, "sql", joiner=" AND ")
            within = int(step.within.total_seconds())
            lines.append(
                f"    AND countIf(event_type = '{step.match.event_type}' AND ({cond})) "
                f">= {step.at_least}  -- count step {index}, within {within}s"
            )

    for absence in detection.exceptions:
        cond = render_conjunction(absence.match.predicates, "sql", joiner=" AND ")
        lines.append(
            f"    AND countIf(event_type = '{absence.match.event_type}' AND ({cond})) = 0"
            "  -- suppressing exception"
        )

    return "\n".join(lines)
