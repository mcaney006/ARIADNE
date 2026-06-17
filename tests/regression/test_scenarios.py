"""Regression tests over the three flagship scenarios.

These pin the end-to-end behaviour the README promises: each recorded incident
opens exactly the expected case, lands on the expected primary hypothesis,
remains deterministic across replays, and — for the departing engineer — both
fails durability on the missing classification field and surfaces the v2 rule
regression through ``ariadne diff``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ariadne.replay.differential import diff_detections
from ariadne.replay.runner import Scenario, ScenarioRunner
from ariadne.rules.loader import index_by_id, load_detections

ROOT = Path(__file__).resolve().parents[2]
RULES = load_detections(ROOT / "rules")
SCENARIO_DIRS = sorted(p.parent for p in (ROOT / "scenarios").glob("*/scenario.json"))


@pytest.mark.parametrize("scenario_dir", SCENARIO_DIRS, ids=lambda p: p.name)
def test_scenario_opens_expected_case(scenario_dir):
    scenario = Scenario.load(scenario_dir)
    runner = ScenarioRunner(RULES, with_durability=False)
    report = runner.run(scenario)

    expected = scenario.expected
    assert report.detections_triggered == expected["detections_triggered"]
    assert len(report.cases) == expected["cases"]
    case = report.cases[0]
    assert case.primary_hypothesis.hypothesis.id == expected["primary_hypothesis"]
    assert case.risk >= 60


@pytest.mark.parametrize("scenario_dir", SCENARIO_DIRS, ids=lambda p: p.name)
def test_replay_is_deterministic(scenario_dir):
    scenario = Scenario.load(scenario_dir)
    runner = ScenarioRunner(RULES, with_durability=False)
    first = runner.run(scenario).case_ids
    second = runner.run(scenario).case_ids
    assert first == second


def _departing():
    return next(p for p in SCENARIO_DIRS if p.name == "departing_engineer")


def test_departing_durability_fails_on_missing_classification():
    scenario = Scenario.load(_departing())
    runner = ScenarioRunner(RULES, with_durability=True)
    case = runner.run(scenario).cases[0]
    assert case.durability is not None
    assert any("repository_sensitivity" in label for label in case.durability.fails)
    assert "Late events" in case.durability.passes
    assert "Duplicate events" in case.durability.passes


def test_departing_v2_regression_is_detected():
    scenario = Scenario.load(_departing())
    v1 = index_by_id(load_detections(ROOT / "rules/insider_risk/repository_collection.py"))
    v2 = index_by_id(load_detections(ROOT / "rules/insider_risk/_repository_collection_v2.py"))
    diff = diff_detections(scenario.events, v1["ARI-IR-0042"], v2["ARI-IR-0042"])
    assert diff.regression
    assert diff.v1_triggered and not diff.v2_triggered
    assert "file_sensitivity" in (diff.cause or "")
    assert diff.recommendation


def test_authorized_migration_does_not_alert():
    """The benign mirror: same activity plus an approval opens no case."""

    from ariadne.lab.synthetic import make_event

    scenario = Scenario.load(_departing())
    approval = make_event(
        "APPROVAL", "change_management.approval", 30, source="servicenow",
        user_id="mcaney", approval_status="approved", ticket="CHG-1001",
    )
    events = scenario.events + [approval]
    runner = ScenarioRunner(RULES, with_durability=False)
    report = runner.run(Scenario(
        id=scenario.id, title=scenario.title, description=scenario.description,
        events=events, facts=scenario.facts, detection_ids=scenario.detection_ids,
        expected=scenario.expected,
    ))
    assert report.detections_triggered == 0
