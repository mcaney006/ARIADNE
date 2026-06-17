"""Static linting of compiled detections.

These checks run after lowering and before evaluation. They catch the mistakes
that turn into silent false negatives in production: a count window wider than
the sequence window, a step that can never fire, an absence window of zero. Each
finding has a severity so the CLI can warn without necessarily failing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from ariadne.rules.ast import CountStepIR, DetectionIR


@dataclass(frozen=True)
class Finding:
    level: str  # "error" | "warning" | "info"
    code: str
    message: str


def lint(detection: DetectionIR) -> list[Finding]:
    """Return a list of lint findings for a compiled detection."""

    findings: list[Finding] = []
    seq = detection.sequence

    if seq.within <= timedelta(0):
        findings.append(
            Finding("error", "empty-window", "sequence window must be positive")
        )

    if not detection.join_by:
        findings.append(
            Finding(
                "warning",
                "no-join",
                "detection has no join keys; chains will not be actor/device scoped",
            )
        )

    for index, step in enumerate(seq.steps):
        if isinstance(step, CountStepIR):
            if step.within > seq.within:
                findings.append(
                    Finding(
                        "warning",
                        "count-window-too-wide",
                        f"step {index} count window exceeds the sequence window; "
                        "the sequence window will dominate",
                    )
                )
            if step.at_least < 1:
                findings.append(
                    Finding(
                        "error",
                        "bad-threshold",
                        f"step {index} count threshold must be >= 1",
                    )
                )

    severities = {"info", "low", "medium", "high", "critical"}
    if detection.severity not in severities:
        findings.append(
            Finding(
                "warning",
                "unknown-severity",
                f"severity {detection.severity!r} is not one of {sorted(severities)}",
            )
        )

    return findings


def has_errors(findings: list[Finding]) -> bool:
    return any(f.level == "error" for f in findings)
