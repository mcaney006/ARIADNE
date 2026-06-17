from datetime import datetime, timezone

from ariadne.events.normalization import canonical_order, deduplicate, normalize_record
from ariadne.events.schema import Event, resolve_field


def test_dotted_field_resolution(chain):
    clone = chain[0]
    assert resolve_field(clone, "actor.user_id") == "mcaney"
    assert resolve_field(clone, "device.id") == "WS-1"
    assert resolve_field(clone, "device.enrolled") is True
    assert resolve_field(clone, "repository_sensitivity") == "restricted"
    assert resolve_field(clone, "event_type") == "github.repository.clone"
    assert resolve_field(clone, "nonexistent.path") is None


def test_naive_datetime_is_coerced_to_utc():
    event = Event(event_id="x", event_type="t", event_time=datetime(2026, 1, 1, 0, 0, 0))
    assert event.event_time.tzinfo is timezone.utc


def test_dedup_by_event_id_keeps_one(chain):
    duplicated = chain + chain
    deduped = deduplicate(duplicated, strategy="event_id")
    assert len(deduped) == len(chain)


def test_content_fingerprint_ignores_id():
    a = Event(event_id="a", event_type="t", event_time=datetime(2026, 1, 1, tzinfo=timezone.utc))
    b = Event(event_id="b", event_type="t", event_time=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert a.content_fingerprint() == b.content_fingerprint()
    deduped = deduplicate([a, b], strategy="fingerprint")
    assert len(deduped) == 1


def test_canonical_order_is_total_and_stable(chain):
    import random

    shuffled = chain[:]
    random.Random(0).shuffle(shuffled)
    assert [e.event_id for e in canonical_order(shuffled)] == [
        e.event_id for e in canonical_order(chain)
    ]


def test_normalize_record_sweeps_unknown_keys_into_attributes():
    event = normalize_record(
        {
            "event_id": "z",
            "event_type": "process.execution",
            "event_time": "2026-02-02T22:00:00Z",
            "process_name": "gpg",
        }
    )
    assert event.attributes["process_name"] == "gpg"
    assert resolve_field(event, "process_name") == "gpg"


def test_lateness_seconds():
    event = Event(
        event_id="l",
        event_type="t",
        event_time=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        observed_time=datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc),
    )
    assert event.lateness_seconds == 300.0
