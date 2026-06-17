"""The investigation engine.

Turns a raw detection firing into an analyst-grade case: a timeline, an explicit
ranking of competing explanations, the evidence for and against each, the
*minimal* set of events that was decisive, and the evidence that is conspicuously
missing. No probabilistic fog — every number traces to a stated indicator.
"""

from ariadne.investigation.case import Case
from ariadne.investigation.evidence import EvidenceItem
from ariadne.investigation.hypotheses import (
    Hypothesis,
    HypothesisScore,
    Indicator,
    default_hypotheses,
    evaluate_hypotheses,
)
from ariadne.investigation.investigator import Investigator
from ariadne.investigation.minimal import minimal_decisive_evidence
from ariadne.investigation.timeline import Timeline, TimelineEntry

__all__ = [
    "Case",
    "EvidenceItem",
    "Hypothesis",
    "HypothesisScore",
    "Indicator",
    "Investigator",
    "Timeline",
    "TimelineEntry",
    "default_hypotheses",
    "evaluate_hypotheses",
    "minimal_decisive_evidence",
]
