"""Replay a recorded scenario through a detection pack.

The runner reads a scenario's normalized events and manifest, evaluates the pack,
and produces the headline replay numbers plus a built case per firing. It is the
engine behind ``ariadne replay <scenario>``: deterministic, measured, and honest
about latency (it times the real evaluation rather than printing a slogan).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ariadne.events.normalization import normalize_record, prepare
from ariadne.events.schema import Event
from ariadne.investigation.case import Case
from ariadne.investigation.investigator import Investigator
from ariadne.replay.metrics import durability_report
from ariadne.rules.dsl import Detection


def load_events(path: str | Path) -> list[Event]:
    """Load a JSON-lines event file into normalized :class:`Event` objects."""

    events: list[Event] = []
    with Path(path).open() as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            events.append(normalize_record(json.loads(line)))
    return events


@dataclass
class Scenario:
    """A replayable incident: events plus the manifest that frames them."""

    id: str
    title: str
    description: str
    events: list[Event]
    facts: dict[str, Any] = field(default_factory=dict)
    detection_ids: list[str] = field(default_factory=list)
    expected: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, directory: str | Path) -> "Scenario":
        root = Path(directory)
        manifest = json.loads((root / "scenario.json").read_text())
        events = load_events(root / "events.jsonl")
        return cls(
            id=manifest.get("id", root.name),
            title=manifest.get("title", root.name),
            description=manifest.get("description", ""),
            events=events,
            facts=manifest.get("facts", {}),
            detection_ids=manifest.get("detections", []),
            expected=manifest.get("expected", {}),
        )


@dataclass
class ReplayReport:
    """The outcome of replaying a scenario through a pack."""

    scenario_id: str
    events_processed: int
    detections_triggered: int
    behavior_chains_matched: int
    cases: list[Case]
    latency_seconds: float

    @property
    def case_ids(self) -> list[str]:
        return [case.id for case in self.cases]

    def render(self) -> str:
        lines = [
            f"Scenario: {self.scenario_id}",
            f"Events processed: {self.events_processed:,}",
            f"Detections triggered: {self.detections_triggered}",
            f"Behavior chains matched: {self.behavior_chains_matched}",
        ]
        for case in self.cases:
            lines.append(f"Case opened: {case.id}")
        lines.append(f"Detection latency: {self.latency_seconds:.2f} seconds")
        return "\n".join(lines)


class ScenarioRunner:
    """Runs a detection pack over a scenario and builds cases."""

    def __init__(
        self,
        detections: list[Detection],
        *,
        investigator: Investigator | None = None,
        with_durability: bool = True,
    ) -> None:
        self.detections = detections
        self.investigator = investigator or Investigator()
        self.with_durability = with_durability

    def run(self, scenario: Scenario) -> ReplayReport:
        prepared = prepare(scenario.events)
        applicable = self._applicable_detections(scenario)

        start = time.perf_counter()
        cases: list[Case] = []
        chains = 0
        triggered = 0
        for detection in applicable:
            result = self.investigator.engine.evaluate(prepared, detection)
            if not result.triggered:
                continue
            triggered += 1
            chains += len(result.alerts)
            durability = (
                durability_report(detection, prepared) if self.with_durability else None
            )
            case = self.investigator.investigate(
                prepared, detection, facts=scenario.facts, durability=durability
            )
            if case is not None:
                cases.append(case)
        latency = time.perf_counter() - start

        cases.sort(key=lambda c: c.id)
        return ReplayReport(
            scenario_id=scenario.id,
            events_processed=len(prepared),
            detections_triggered=triggered,
            behavior_chains_matched=chains,
            cases=cases,
            latency_seconds=latency,
        )

    def _applicable_detections(self, scenario: Scenario) -> list[Detection]:
        if not scenario.detection_ids:
            return self.detections
        wanted = set(scenario.detection_ids)
        return [d for d in self.detections if d.id in wanted]
