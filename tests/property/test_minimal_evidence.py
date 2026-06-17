"""Properties of the minimal decisive evidence set.

The set ARIADNE reports must actually fire the detection on its own, and it must
be 1-minimal: removing any single event breaks the firing. That is what makes it
a *proof* of the load-bearing evidence rather than a guess.
"""

from __future__ import annotations

from hypothesis import given, settings

from ariadne.engines.reference import ReferenceEngine
from ariadne.investigation.minimal import minimal_decisive_evidence
from ariadne.rules.compiler import compile_detection
from tests.conftest import repository_collection_detection
from tests.property.strategies import firing_streams

DETECTION = compile_detection(repository_collection_detection())
ENGINE = ReferenceEngine()


@given(firing_streams())
@settings(max_examples=60, deadline=None)
def test_minimal_set_still_fires(events):
    result = ENGINE.evaluate(events, DETECTION)
    assert result.triggered
    minimal = minimal_decisive_evidence(DETECTION, result.alerts[0].contributing_events)
    assert ENGINE.evaluate(minimal, DETECTION).triggered


@given(firing_streams())
@settings(max_examples=60, deadline=None)
def test_minimal_set_is_one_minimal(events):
    result = ENGINE.evaluate(events, DETECTION)
    minimal = minimal_decisive_evidence(DETECTION, result.alerts[0].contributing_events)
    # The count step needs exactly 8, plus the three single steps => 11 events.
    assert len(minimal) == 11
    for event in minimal:
        without = [e for e in minimal if e.event_id != event.event_id]
        assert not ENGINE.evaluate(without, DETECTION).triggered
