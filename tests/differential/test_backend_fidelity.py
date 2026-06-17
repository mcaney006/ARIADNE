"""Differential checks across the four query backends.

We cannot run Splunk, Elastic, Sentinel, and ClickHouse in CI, so instead we
assert *structural fidelity*: every backend must mention every event type the
detection uses and must preserve each count threshold. A backend that silently
drops a step or a threshold would diverge from the reference engine, and this is
where we catch it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ariadne.compilers import COMPILERS
from ariadne.rules.ast import CountStepIR
from ariadne.rules.compiler import compile_detection
from ariadne.rules.loader import load_detections

ROOT = Path(__file__).resolve().parents[2]
DETECTIONS = load_detections(ROOT / "rules")


@pytest.mark.parametrize("detection", DETECTIONS, ids=lambda d: f"{d.id}")
def test_every_backend_mentions_every_event_type(detection):
    ir = compile_detection(detection)
    event_types = {step.match.event_type for step in ir.sequence.steps}
    for compiler in COMPILERS.values():
        rendered = compiler(ir)
        for event_type in event_types:
            assert event_type in rendered


@pytest.mark.parametrize("detection", DETECTIONS, ids=lambda d: f"{d.id}")
def test_every_backend_preserves_count_thresholds(detection):
    ir = compile_detection(detection)
    thresholds = [s.at_least for s in ir.sequence.steps if isinstance(s, CountStepIR)]
    for compiler in COMPILERS.values():
        rendered = compiler(ir)
        for threshold in thresholds:
            assert str(threshold) in rendered
