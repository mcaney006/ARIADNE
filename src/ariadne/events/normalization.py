"""Turning messy collector output into canonical :class:`Event` streams.

Normalization is where ARIADNE makes telemetry *comparable*: it validates the
shape, pins timestamps to UTC, stamps provenance, and — crucially — produces a
single canonical ordering and deduplication so that the downstream engine sees
the same stream no matter how the events arrived.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Literal

from ariadne.events.schema import Event

DedupStrategy = Literal["event_id", "fingerprint"]


def normalize_record(raw: Mapping[str, Any]) -> Event:
    """Validate and normalize a single raw record into an :class:`Event`.

    Raw records may carry the structured spine inline (``actor``/``device`` as
    nested maps) or leave it out entirely; anything not part of the spine is
    swept into ``attributes`` untouched so detections can address it.
    """

    spine = {"event_id", "event_type", "event_time", "observed_time", "provenance"}
    structured = {"actor", "device"}
    payload: dict[str, Any] = {}
    attributes: dict[str, Any] = dict(raw.get("attributes", {}))

    for key, value in raw.items():
        if key in spine or key in structured or key == "attributes":
            payload[key] = value
        else:
            attributes.setdefault(key, value)

    payload["attributes"] = attributes
    return Event.model_validate(payload)


def normalize_stream(records: Iterable[Mapping[str, Any]]) -> list[Event]:
    """Normalize an iterable of raw records, preserving input order."""

    return [normalize_record(r) for r in records]


def deduplicate(
    events: Iterable[Event], *, strategy: DedupStrategy = "event_id"
) -> list[Event]:
    """Drop duplicate events idempotently.

    With ``strategy="event_id"`` two records are the same iff they share a
    surrogate id — the normal case. With ``strategy="fingerprint"`` they are the
    same iff their content matches, which collapses a reconnecting collector's
    re-emitted window even when it assigns fresh ids.

    The *first* occurrence in canonical order is kept, so the result does not
    depend on which physical copy arrived first.
    """

    seen: set[str] = set()
    kept: list[Event] = []
    for event in canonical_order(events):
        key = event.dedup_key if strategy == "event_id" else event.content_fingerprint()
        if key in seen:
            continue
        seen.add(key)
        kept.append(event)
    return kept


def canonical_order(events: Iterable[Event]) -> list[Event]:
    """Sort events into the one total order the engine reasons about.

    This is the lever that makes evaluation invariant to arrival order: every
    permutation of the same multiset of events sorts to the same sequence.
    """

    return sorted(events, key=Event.sort_key)


def prepare(
    events: Iterable[Event], *, strategy: DedupStrategy = "event_id"
) -> list[Event]:
    """Canonicalize and deduplicate in one step — the engine's front door."""

    return deduplicate(events, strategy=strategy)
