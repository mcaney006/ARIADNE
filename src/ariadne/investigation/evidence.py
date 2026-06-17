"""Evidence items: the for, the against, and the conspicuously absent.

ARIADNE's evidence model has four registers. *Supporting* evidence is what made
the detection fire. *Contradictory* evidence is the benign context that argues
against the worst reading. *Missing* evidence is the authorising or classifying
telemetry that, were it present, would settle the question — its absence is
itself a finding. *Neutral* facts provide grounding without leaning either way.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EvidenceItem:
    """A single piece of evidence, tied back to the events that ground it."""

    register: str  # "supporting" | "contradictory" | "missing" | "neutral"
    text: str
    event_ids: tuple[str, ...] = field(default_factory=tuple)

    def render(self) -> str:
        if self.event_ids:
            return f"{self.text}  [{', '.join(self.event_ids)}]"
        return self.text


def supporting(text: str, event_ids: tuple[str, ...] = ()) -> EvidenceItem:
    return EvidenceItem("supporting", text, event_ids)


def contradictory(text: str, event_ids: tuple[str, ...] = ()) -> EvidenceItem:
    return EvidenceItem("contradictory", text, event_ids)


def missing(text: str) -> EvidenceItem:
    return EvidenceItem("missing", text, ())


def neutral(text: str, event_ids: tuple[str, ...] = ()) -> EvidenceItem:
    return EvidenceItem("neutral", text, event_ids)
