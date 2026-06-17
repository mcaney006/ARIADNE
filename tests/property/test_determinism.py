"""The central property: evaluation is invariant to how events arrive.

A behavioural detection is only trustworthy if duplicate, late, reordered, and
replayed telemetry cannot change its verdict. These tests assert exactly that
over a wide space of synthesised streams — the property the whole project is
built to guarantee.
"""

from __future__ import annotations

from hypothesis import given, settings

from ariadne.engines.reference import ReferenceEngine
from ariadne.replay import mutation
from tests.conftest import repository_collection_detection
from tests.property.strategies import event_streams

DETECTION = repository_collection_detection()
ENGINE = ReferenceEngine()


@given(event_streams())
@settings(max_examples=200, deadline=None)
def test_stable_under_shuffle_and_duplication(events):
    baseline = ENGINE.evaluate(events, DETECTION).case_ids
    mutated = mutation.duplicate(mutation.shuffle(events, seed=1), fraction=0.4, seed=2)
    assert ENGINE.evaluate(mutated, DETECTION).case_ids == baseline


@given(event_streams())
@settings(max_examples=100, deadline=None)
def test_stable_under_lateness(events):
    baseline = ENGINE.evaluate(events, DETECTION).case_ids
    late = mutation.with_lateness(events, max_lateness="20m", seed=5)
    assert ENGINE.evaluate(late, DETECTION).case_ids == baseline


@given(event_streams())
@settings(max_examples=100, deadline=None)
def test_stable_under_collector_reconnect(events):
    baseline = ENGINE.evaluate(events, DETECTION).case_ids
    reconnected = mutation.reconnect(events, window=8, seed=6)
    assert ENGINE.evaluate(reconnected, DETECTION).case_ids == baseline


@given(event_streams())
@settings(max_examples=100, deadline=None)
def test_evaluation_is_idempotent(events):
    a = ENGINE.evaluate(events, DETECTION).case_ids
    b = ENGINE.evaluate(events, DETECTION).case_ids
    assert a == b
