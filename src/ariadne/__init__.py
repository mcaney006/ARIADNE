"""ARIADNE — a deterministic insider-risk detection compiler and forensic replay engine.

ARIADNE treats behavioural security detections as *stateful programs*. The same
detection, written once in Python, can be evaluated locally against recorded
telemetry, compiled into SIEM query languages, replayed against historical
incidents, and tested for determinism under duplicate, delayed, missing, and
out-of-order events.

The public surface that most callers need lives here::

    from ariadne import Detection, Sequence, Event, Count, Absence
    from ariadne import ReferenceEngine, Investigator

Everything else is reachable through the sub-packages documented in
``docs/architecture.md``.
"""

from __future__ import annotations

from ariadne.engines.reference import EvaluationResult, ReferenceEngine, SequenceMatch
from ariadne.events.schema import Actor, Device, Event, Provenance
from ariadne.investigation.case import Case
from ariadne.investigation.investigator import Investigator
from ariadne.rules.dsl import Absence, Count, Detection, Event as EventPattern, Sequence

__all__ = [
    "Absence",
    "Actor",
    "Case",
    "Count",
    "Detection",
    "Device",
    "EvaluationResult",
    "Event",
    "EventPattern",
    "Investigator",
    "Provenance",
    "ReferenceEngine",
    "Sequence",
    "SequenceMatch",
]

__version__ = "0.1.0"
