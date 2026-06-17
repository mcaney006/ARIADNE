"""The case aggregate and its analyst-facing rendering.

A :class:`Case` is the whole investigation in one object: the firing, the ranked
explanations, the four registers of evidence, the minimal decisive set, the
timeline, and the durability profile. :meth:`render` produces the text block the
README shows; the FastAPI console renders the same fields into the five panels.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ariadne.engines.reference import SequenceMatch
from ariadne.investigation.evidence import EvidenceItem
from ariadne.investigation.hypotheses import HypothesisScore
from ariadne.investigation.timeline import Timeline


@dataclass
class DurabilityProfile:
    """How the firing held up under adversarial event-stream mutation."""

    passes: list[str] = field(default_factory=list)
    fails: list[str] = field(default_factory=list)


@dataclass
class Case:
    """A fully built investigation case."""

    id: str
    detection_id: str
    version: str
    title: str
    risk: int
    confidence: str
    thesis: str
    primary_hypothesis: HypothesisScore
    leading_alternative: HypothesisScore | None
    hypothesis_scores: list[HypothesisScore]
    supporting: list[EvidenceItem]
    contradictory: list[EvidenceItem]
    missing: list[EvidenceItem]
    minimal_evidence: tuple[str, ...]
    explanation: list[str]
    timeline: Timeline
    match: SequenceMatch
    durability: DurabilityProfile | None = None

    def render(self) -> str:
        lines: list[str] = []
        lines.append(f"CASE {self.id}")
        lines.append(f"Detection: {self.detection_id}@v{self.version} — {self.title}")
        lines.append(f"Risk: {self.risk} / 100")
        lines.append(f"Confidence: {self.confidence}")
        lines.append("")
        lines.append("Primary hypothesis:")
        lines.append(
            f"  {self.primary_hypothesis.label} "
            f"(p={self.primary_hypothesis.probability:.2f})"
        )
        if self.leading_alternative is not None:
            lines.append("")
            lines.append("Competing hypothesis:")
            lines.append(
                f"  {self.leading_alternative.label} "
                f"(p={self.leading_alternative.probability:.2f})"
            )
        lines.append("")
        lines.append("Supporting evidence:")
        for item in self.supporting:
            lines.append(f"  {item.render()}")
        if self.contradictory:
            lines.append("")
            lines.append("Contradictory evidence:")
            for item in self.contradictory:
                lines.append(f"  {item.render()}")
        if self.missing:
            lines.append("")
            lines.append("Missing evidence:")
            for item in self.missing:
                lines.append(f"  {item.render()}")
        lines.append("")
        lines.append("Minimal decisive evidence:")
        lines.append("  " + ", ".join(self.minimal_evidence))
        if self.durability is not None:
            lines.append("")
            lines.append("Detection durability:")
            for label in self.durability.passes:
                lines.append(f"  passes: {label}")
            for label in self.durability.fails:
                lines.append(f"  FAILS:  {label}")
        return "\n".join(lines)
