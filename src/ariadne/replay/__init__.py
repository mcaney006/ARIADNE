"""Replay and regression lab.

Run a recorded incident through a detection pack (:mod:`runner`), mutate event
streams adversarially (:mod:`mutation`), measure how a firing holds up and how
complete the telemetry is (:mod:`metrics`), and compare two rule versions to find
and explain regressions (:mod:`differential`). This is the half of ARIADNE that
proves the rules are correct rather than merely present.
"""

from ariadne.replay.differential import RuleDiff, diff_detections
from ariadne.replay.metrics import durability_report, field_coverage
from ariadne.replay.runner import ReplayReport, ScenarioRunner, load_events
from ariadne.replay import mutation

__all__ = [
    "ReplayReport",
    "RuleDiff",
    "ScenarioRunner",
    "diff_detections",
    "durability_report",
    "field_coverage",
    "load_events",
    "mutation",
]
