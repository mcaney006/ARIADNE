"""The shipped rule pack must always load and lint clean."""

from __future__ import annotations

from pathlib import Path

import pytest

from ariadne.rules.compiler import compile_detection
from ariadne.rules.loader import load_detections
from ariadne.rules.validation import has_errors, lint

ROOT = Path(__file__).resolve().parents[2]
DETECTIONS = load_detections(ROOT / "rules")


def test_pack_is_non_empty():
    assert {d.id for d in DETECTIONS} >= {"ARI-IR-0042", "ARI-CC-0017", "ARI-TT-0009"}


@pytest.mark.parametrize("detection", DETECTIONS, ids=lambda d: d.id)
def test_rule_compiles_and_lints_clean(detection):
    findings = lint(compile_detection(detection))
    assert not has_errors(findings), findings
