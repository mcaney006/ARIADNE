"""The ARIADNE detection language, its intermediate representation, and compilers.

Detections are written as typed Python objects (:mod:`ariadne.rules.dsl`), lowered
to an inspectable intermediate representation (:mod:`ariadne.rules.ast`) by
:mod:`ariadne.rules.compiler`, and validated by :mod:`ariadne.rules.validation`.
Everything that consumes a detection — the local engine, the SIEM exporters, the
graph renderer, the explanation builder — consumes the IR, never the surface
syntax.
"""

from ariadne.rules.ast import (
    AbsenceIR,
    CountStepIR,
    DetectionIR,
    EventMatchIR,
    EventStepIR,
    PredicateIR,
    SequenceIR,
    render_tree,
)
from ariadne.rules.compiler import compile_detection
from ariadne.rules.dsl import Absence, Count, Detection, Event, Sequence

__all__ = [
    "Absence",
    "AbsenceIR",
    "Count",
    "CountStepIR",
    "Detection",
    "DetectionIR",
    "Event",
    "EventMatchIR",
    "EventStepIR",
    "PredicateIR",
    "Sequence",
    "SequenceIR",
    "compile_detection",
    "render_tree",
]
