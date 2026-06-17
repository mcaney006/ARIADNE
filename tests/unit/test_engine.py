from ariadne.engines.reference import ReferenceEngine, StreamingEvaluator
from tests.conftest import ev, firing_chain


def test_basic_firing(detection, chain):
    result = ReferenceEngine().evaluate(chain, detection)
    assert result.triggered
    assert len(result.alerts) == 1
    alert = result.alerts[0]
    assert alert.join_values == {"actor.user_id": "mcaney", "device.id": "WS-1"}


def test_count_threshold_not_met(detection):
    result = ReferenceEngine().evaluate(firing_chain(clones=7), detection)
    assert not result.triggered


def test_count_window_too_wide_fails(detection):
    # 8 clones but spread across 40 minutes — outside the 15m count window.
    events = []
    for index in range(8):
        events.append(
            ev(f"E{index}", "github.repository.clone", index * 5, source="github_audit",
               repository_sensitivity="restricted", access_is_first_seen=True)
        )
    events.append(ev("P", "process.execution", 41, process_name="gpg"))
    events.append(ev("W", "filesystem.write", 42, destination_type="removable_media"))
    events.append(ev("T", "security.telemetry_state", 43, state="stopped"))
    assert not ReferenceEngine().evaluate(events, detection).triggered


def test_out_of_order_step_does_not_match(detection):
    # Telemetry stop happens BEFORE staging — the ordered sequence must not match.
    events = firing_chain()
    reordered = [e for e in events if e.event_id != "E2002"]
    reordered.append(ev("E2002", "security.telemetry_state", 1, state="stopped"))
    assert not ReferenceEngine().evaluate(reordered, detection).triggered


def test_absence_exception_suppresses(detection, chain):
    approval = ev("AP", "change_management.approval", -30, approval_status="approved")
    result = ReferenceEngine().evaluate(chain + [approval], detection)
    assert not result.triggered
    assert result.suppressed and result.suppressed[0].suppressed_by


def test_join_scoping_separates_actors(detection):
    # Two actors each contribute half a chain; neither completes alone.
    a = firing_chain(clones=8)
    b = [
        ev(e.event_id + "b", e.event_type, 0, user="other")
        for e in a
        if e.event_type != "github.repository.clone"
    ]
    mixed = a[:4] + b  # actor "mcaney" has too few clones; "other" has no clones
    assert not ReferenceEngine().evaluate(mixed, detection).triggered


def test_streaming_matches_batch(detection, chain):
    batch = ReferenceEngine().evaluate(chain, detection).case_ids
    stream = StreamingEvaluator(detection, allowed_lateness="30m")
    # Ingest shuffled and duplicated, as a live feed would deliver.
    import random

    feed = chain + chain[:5]
    random.Random(3).shuffle(feed)
    stream.ingest_all(feed)
    assert stream.result().case_ids == batch
