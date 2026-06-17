"""The reference engine — ARIADNE's deterministic ground truth.

Everything else in the system is measured against this evaluator. It takes a
detection and a pile of events that may be shuffled, duplicated, or late, and
produces the same matches every time by:

1. canonicalizing and deduplicating the events (so arrival order and duplicates
   cannot matter),
2. partitioning them into join groups (the actor/device scope of a chain),
3. running the greedy earliest-match sequence matcher on each group, and
4. evaluating negative *exceptions* to decide whether a positive match is
   actually an alert or is suppressed by an authorising event.

The :class:`StreamingEvaluator` puts a watermark in front of the same core so a
live, out-of-order, reconnecting feed lands on the identical result.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from ariadne.engines.sequence import SequenceAssignment, match_sequence
from ariadne.engines.state import JoinBuffer
from ariadne.engines.windows import WatermarkTracker
from ariadne.events.normalization import prepare
from ariadne.events.schema import Event, resolve_field
from ariadne.rules.ast import AbsenceIR, DetectionIR
from ariadne.rules.compiler import compile_detection
from ariadne.rules.dsl import Detection


def _as_ir(detection: Detection | DetectionIR) -> DetectionIR:
    return detection if isinstance(detection, DetectionIR) else compile_detection(detection)


def _join_key(event: Event, join_by: tuple[str, ...]) -> tuple[object, ...]:
    return tuple(resolve_field(event, field) for field in join_by)


@dataclass(frozen=True)
class SequenceMatch:
    """One detection firing (or suppressed firing) for one join group."""

    detection_id: str
    version: str
    join_by: tuple[str, ...]
    join_key: tuple[object, ...]
    assignment: SequenceAssignment
    suppressed_by: tuple[str, ...] = ()

    @property
    def triggered(self) -> bool:
        """Whether this is a real alert (matched and not suppressed)."""

        return not self.suppressed_by

    @property
    def contributing_events(self) -> tuple[Event, ...]:
        return self.assignment.events

    @property
    def start_time(self) -> datetime:
        return self.assignment.start_time

    @property
    def end_time(self) -> datetime:
        return self.assignment.end_time

    @property
    def join_values(self) -> dict[str, object]:
        return dict(zip(self.join_by, self.join_key))

    @property
    def case_id(self) -> str:
        """A deterministic signature for this firing.

        Stable across runs and across input orderings so that two evaluations of
        the same incident produce identical case ids — the invariant the property
        tests assert.
        """

        seed = "|".join(
            [
                self.detection_id,
                self.version,
                ";".join(f"{k}={v}" for k, v in zip(self.join_by, self.join_key)),
                self.start_time.isoformat(),
            ]
        )
        digest = hashlib.sha256(seed.encode()).hexdigest()[:10]
        return f"ARI-{digest}"


@dataclass(frozen=True)
class EvaluationResult:
    """The outcome of evaluating one detection against one event set."""

    detection_id: str
    version: str
    matches: tuple[SequenceMatch, ...]

    @property
    def alerts(self) -> tuple[SequenceMatch, ...]:
        return tuple(m for m in self.matches if m.triggered)

    @property
    def suppressed(self) -> tuple[SequenceMatch, ...]:
        return tuple(m for m in self.matches if not m.triggered)

    @property
    def triggered(self) -> bool:
        return bool(self.alerts)

    @property
    def case_ids(self) -> tuple[str, ...]:
        """Deterministic, order-independent set of fired case ids."""

        return tuple(sorted(m.case_id for m in self.alerts))


class ReferenceEngine:
    """Deterministic event-time batch evaluator.

    Construct with a dedup ``strategy`` of ``"event_id"`` (idempotent on surrogate
    id) or ``"fingerprint"`` (idempotent on content, for reconnecting collectors
    that re-id their backlog).
    """

    def __init__(self, *, dedup_strategy: str = "event_id") -> None:
        self.dedup_strategy = dedup_strategy

    def evaluate(
        self, events: Iterable[Event], detection: Detection | DetectionIR
    ) -> EvaluationResult:
        ir = _as_ir(detection)
        prepared = prepare(events, strategy=self.dedup_strategy)  # type: ignore[arg-type]
        matches = self._evaluate_prepared(prepared, ir)
        return EvaluationResult(detection_id=ir.id, version=ir.version, matches=tuple(matches))

    def evaluate_prepared(
        self, prepared: list[Event], detection: Detection | DetectionIR
    ) -> EvaluationResult:
        """Evaluate over events that are already canonicalized and deduplicated.

        This is the steady-state path: normalize once, then match many detections
        without re-paying for ordering and dedup. Callers are responsible for
        having run :func:`ariadne.events.normalization.prepare` first.
        """

        ir = _as_ir(detection)
        matches = self._evaluate_prepared(prepared, ir)
        return EvaluationResult(detection_id=ir.id, version=ir.version, matches=tuple(matches))

    def evaluate_pack(
        self, events: Iterable[Event], detections: Iterable[Detection | DetectionIR]
    ) -> list[EvaluationResult]:
        prepared = prepare(events, strategy=self.dedup_strategy)  # type: ignore[arg-type]
        results: list[EvaluationResult] = []
        for detection in detections:
            ir = _as_ir(detection)
            matches = self._evaluate_prepared(prepared, ir)
            results.append(
                EvaluationResult(detection_id=ir.id, version=ir.version, matches=tuple(matches))
            )
        return results

    # -- internals --------------------------------------------------------

    def _evaluate_prepared(
        self, prepared: list[Event], ir: DetectionIR
    ) -> list[SequenceMatch]:
        groups: dict[tuple[object, ...], list[Event]] = {}
        for event in prepared:
            groups.setdefault(_join_key(event, ir.join_by), []).append(event)

        matches: list[SequenceMatch] = []
        for key, group_events in groups.items():
            assignment = match_sequence(group_events, ir.sequence)
            if assignment is None:
                continue
            suppressed_by = self._evaluate_exceptions(prepared, ir, assignment)
            matches.append(
                SequenceMatch(
                    detection_id=ir.id,
                    version=ir.version,
                    join_by=ir.join_by,
                    join_key=key,
                    assignment=assignment,
                    suppressed_by=suppressed_by,
                )
            )

        matches.sort(key=lambda m: (m.start_time, m.case_id))
        return matches

    def _evaluate_exceptions(
        self, prepared: list[Event], ir: DetectionIR, assignment: SequenceAssignment
    ) -> tuple[str, ...]:
        if not ir.exceptions:
            return ()

        # Exceptions are authorising context and are scoped to the actor, not the
        # device: an approval ticket is bound to the person, not their laptop.
        actor_value = None
        if "actor.user_id" in ir.join_by:
            anchor_event = assignment.steps[0].events[0]
            actor_value = resolve_field(anchor_event, "actor.user_id")

        suppressed: list[str] = []
        for absence in ir.exceptions:
            if self._authorising_event_present(prepared, absence, assignment, actor_value):
                suppressed.append(self._describe_exception(absence))
        return tuple(suppressed)

    @staticmethod
    def _authorising_event_present(
        prepared: list[Event],
        absence: AbsenceIR,
        assignment: SequenceAssignment,
        actor_value: object,
    ) -> bool:
        low = assignment.start_time - absence.within
        high = assignment.end_time
        for event in prepared:
            if actor_value is not None and resolve_field(event, "actor.user_id") != actor_value:
                continue
            if not (low <= event.event_time <= high):
                continue
            if absence.match.matches(event):
                return True
        return False

    @staticmethod
    def _describe_exception(absence: AbsenceIR) -> str:
        return absence.match.describe()


class StreamingEvaluator:
    """Watermark-fronted streaming wrapper over :class:`ReferenceEngine`.

    Events are ``ingest``-ed in arrival order. Duplicates are dropped idempotently
    and events older than ``watermark - allowed_lateness`` are rejected as too
    late. At any point :meth:`result` runs the deterministic batch core over the
    admitted set, so the streaming answer is exactly the batch answer over the
    events that were admissible.
    """

    def __init__(
        self,
        detection: Detection | DetectionIR,
        *,
        allowed_lateness: str | timedelta = timedelta(minutes=5),
        dedup_strategy: str = "event_id",
    ) -> None:
        from ariadne.timeutil import parse_duration

        self.ir = _as_ir(detection)
        self.engine = ReferenceEngine(dedup_strategy=dedup_strategy)
        self.watermark = WatermarkTracker(allowed_lateness=parse_duration(allowed_lateness))
        self.buffer = JoinBuffer()
        self.dropped_late: list[Event] = []

    def ingest(self, event: Event) -> bool:
        """Admit one event. Returns whether it was admitted (vs. duplicate/late)."""

        if self.watermark.is_too_late(event):
            self.dropped_late.append(event)
            return False
        admitted = self.buffer.admit(event)
        # Advance the watermark only with admitted, in-order progress.
        self.watermark.observe(event)
        return admitted

    def ingest_all(self, events: Iterable[Event]) -> None:
        for event in events:
            self.ingest(event)

    def result(self) -> EvaluationResult:
        return self.engine.evaluate(self.buffer.ordered(), self.ir)
