"""The orchestrator that turns a detection firing into a :class:`Case`.

The investigator runs the reference engine, takes the leading alert, and then
assembles every analyst-facing artifact around it: signals, ranked hypotheses, a
transparent risk score, the four evidence registers, the minimal decisive set,
the per-condition explanation, and the timeline. It deliberately holds no
opinions of its own — it only arranges what the engine and the explicit
hypothesis model produce.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ariadne.engines.reference import ReferenceEngine, SequenceMatch
from ariadne.events.normalization import prepare
from ariadne.events.schema import Event, resolve_field
from ariadne.investigation.case import Case, DurabilityProfile
from ariadne.investigation.evidence import (
    EvidenceItem,
    contradictory,
    missing,
    supporting,
)
from ariadne.investigation.explanations import explain_match
from ariadne.investigation.hypotheses import (
    Hypothesis,
    HypothesisScore,
    default_hypotheses,
    evaluate_hypotheses,
)
from ariadne.investigation.minimal import minimal_decisive_evidence
from ariadne.investigation.signals import compute_signals
from ariadne.investigation.timeline import Timeline
from ariadne.rules.ast import DetectionIR
from ariadne.rules.compiler import compile_detection
from ariadne.rules.dsl import Detection
from ariadne.timeutil import format_duration

_SEVERITY_WEIGHT = {"critical": 100, "high": 85, "medium": 65, "low": 40, "info": 20}


@dataclass
class Investigator:
    """Builds cases. Reusable across a whole detection pack."""

    hypotheses: list[Hypothesis] | None = None
    case_year: int = 2026

    def __post_init__(self) -> None:
        self.engine = ReferenceEngine()
        if self.hypotheses is None:
            self.hypotheses = default_hypotheses()

    def investigate(
        self,
        events: list[Event],
        detection: Detection | DetectionIR,
        *,
        facts: dict[str, Any] | None = None,
        case_id: str | None = None,
        durability: DurabilityProfile | None = None,
    ) -> Case | None:
        """Return a built :class:`Case`, or ``None`` if nothing fired."""

        ir = detection if isinstance(detection, DetectionIR) else compile_detection(detection)
        result = self.engine.evaluate(events, ir)
        if not result.alerts:
            return None

        match = result.alerts[0]
        prepared = prepare(events)
        actor_events = _actor_scope(prepared, match)

        signals = compute_signals(match, actor_events, facts)
        scores = evaluate_hypotheses(self.hypotheses or [], signals)
        primary = scores[0]
        alternative = _leading_alternative(scores, primary)

        risk = _risk_score(primary, ir.severity)
        confidence = _confidence(primary)

        support = _supporting_evidence(ir, match, signals, actor_events)
        against = _contradictory_evidence(primary, signals, actor_events, facts)
        gaps = _missing_evidence(ir, match, facts)

        minimal_events = minimal_decisive_evidence(ir, match.contributing_events)
        minimal_ids = tuple(e.event_id for e in minimal_events)

        explanation = explain_match(ir, match)
        timeline = Timeline.from_events(actor_events)

        resolved_case_id = case_id or _mint_case_id(self.case_year, match)
        thesis = _thesis(primary, ir)

        return Case(
            id=resolved_case_id,
            detection_id=ir.id,
            version=ir.version,
            title=ir.title,
            risk=risk,
            confidence=confidence,
            thesis=thesis,
            primary_hypothesis=primary,
            leading_alternative=alternative,
            hypothesis_scores=scores,
            supporting=support,
            contradictory=against,
            missing=gaps,
            minimal_evidence=minimal_ids,
            explanation=explanation,
            timeline=timeline,
            match=match,
            durability=durability,
        )


def _actor_scope(prepared: list[Event], match: SequenceMatch) -> list[Event]:
    if "actor.user_id" not in match.join_by:
        return prepared
    anchor = match.assignment.steps[0].events[0]
    actor_value = resolve_field(anchor, "actor.user_id")
    if actor_value is None:
        return prepared
    return [e for e in prepared if resolve_field(e, "actor.user_id") == actor_value]


def _leading_alternative(
    scores: list[HypothesisScore], primary: HypothesisScore
) -> HypothesisScore | None:
    # The most *relevant* alternative of the opposite class: the explanation that
    # best accounts for the same observed activity (greatest supporting evidence
    # present), even if heavy contradicting evidence then sinks its probability.
    # That is precisely the hypothesis whose contradictions are worth showing.
    opposite = [s for s in scores[1:] if s.hypothesis.malicious != primary.hypothesis.malicious]
    if opposite:
        return max(
            opposite,
            key=lambda s: (
                sum(i.weight for i in s.supporting),
                len(s.supporting),
                s.probability,
            ),
        )
    return scores[1] if len(scores) > 1 else None


def _risk_score(primary: HypothesisScore, severity: str) -> int:
    weight = _SEVERITY_WEIGHT.get(severity, 65)
    if not primary.hypothesis.malicious:
        # A benign leading explanation should not produce a high-risk case.
        return round(weight * primary.probability * 0.25)
    return round(weight * primary.probability)


def _confidence(primary: HypothesisScore) -> str:
    p = primary.probability
    if p >= 0.85:
        return "High"
    if p >= 0.6:
        return "Medium"
    return "Low"


def _supporting_evidence(
    ir: DetectionIR,
    match: SequenceMatch,
    signals: dict[str, Any],
    actor_events: list[Event],
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    from ariadne.rules.ast import CountStepIR

    for step_ir, step_match in zip(ir.sequence.steps, match.assignment.steps):
        ids = tuple(e.event_id for e in step_match.events)
        if isinstance(step_ir, CountStepIR):
            span = max(e.event_time for e in step_match.events) - min(
                e.event_time for e in step_match.events
            )
            items.append(
                supporting(
                    f"{len(step_match.events)} {step_ir.match.event_type} events "
                    f"within {format_duration(span)}",
                    ids,
                )
            )
        elif step_ir.match.event_type == "process.execution":
            tool = step_match.events[0].attributes.get("process_name", "archive tool")
            items.append(supporting(f"Encrypted archive created using {tool}", ids))
        elif step_ir.match.event_type == "filesystem.write":
            dest = step_match.events[0].attributes.get("destination_type", "external destination")
            items.append(supporting(f"Data staged to {dest}", ids))
        elif step_ir.match.event_type == "security.telemetry_state":
            state = step_match.events[0].attributes.get("state", "altered")
            items.append(supporting(f"Endpoint telemetry {state}", ids))
        else:
            items.append(supporting(step_ir.match.describe(), ids))

    if signals.get("first_seen_access"):
        first_seen_ids = tuple(
            e.event_id
            for e in actor_events
            if e.event_type == "github.repository.clone"
            and e.attributes.get("access_is_first_seen")
        )
        if first_seen_ids:
            items.append(supporting("First-ever access to restricted repositories", first_seen_ids))
    if signals.get("new_token_created"):
        token_ids = tuple(
            e.event_id
            for e in actor_events
            if e.event_type in {"github.token.create", "identity.token.create"}
        )
        items.append(supporting("New access token created shortly before activity", token_ids))
    if signals.get("shell_history_deleted"):
        del_ids = tuple(
            e.event_id
            for e in actor_events
            if e.event_type in {"filesystem.delete", "shell.history.clear"}
            and "history" in str(e.attributes.get("path", e.event_type))
        )
        items.append(supporting("Shell history deleted", del_ids))
    return items


def _contradictory_evidence(
    primary: HypothesisScore,
    signals: dict[str, Any],
    actor_events: list[Event],
    facts: dict[str, Any] | None,
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    seen: set[str] = set()

    def add(text: str) -> None:
        key = text.strip().lower()
        if key not in seen:
            seen.add(key)
            items.append(contradictory(text))

    for indicator in primary.contradicting:
        text = indicator.note or indicator.signal.replace("_", " ")
        add(text.capitalize())
    if signals.get("device_enrolled"):
        add("Activity originated from an enrolled corporate device")
    if facts:
        for text in facts.get("contradictory", []):
            add(text)
    return items


def _missing_evidence(
    ir: DetectionIR, match: SequenceMatch, facts: dict[str, Any] | None
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for absence in ir.exceptions:
        if absence.match.describe() not in match.suppressed_by:
            label = absence.match.event_type.replace(".", " ").replace("_", " ")
            items.append(missing(f"No {label} (would authorise this activity)"))
    if facts:
        for text in facts.get("missing_evidence", []):
            items.append(missing(text))
    return items


_THESIS_OVERRIDES = {
    "H2": "More consistent with compromised credentials than deliberate insider activity",
    "H5": "Anomalous privileged-administrator activity outside the approved maintenance window",
}


def _thesis(primary: HypothesisScore, ir: DetectionIR) -> str:
    override = _THESIS_OVERRIDES.get(primary.hypothesis.id)
    if override:
        return override
    if primary.hypothesis.malicious:
        return primary.hypothesis.label
    return f"Most consistent with: {primary.hypothesis.label}"


def _mint_case_id(year: int, match: SequenceMatch) -> str:
    # Deterministic four-digit suffix derived from the engine signature so the
    # same incident always mints the same human-facing case number.
    digits = "".join(ch for ch in match.case_id if ch.isdigit())
    suffix = (digits + "0000")[:4]
    return f"ARI-{year}-{suffix}"
