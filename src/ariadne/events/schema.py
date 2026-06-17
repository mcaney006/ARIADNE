"""The normalized ARIADNE event model.

Every collector — osquery, auditd, Zeek, GitHub audit, CloudTrail, identity — is
expected to emit objects that validate against :class:`Event`. The model keeps a
small, stable, structured spine (who, what, when, where, provenance) and pushes
everything source-specific into a flat ``attributes`` namespace so that detection
authors can address fields uniformly.

Two timestamps matter and they are kept deliberately distinct:

``event_time``
    When the thing actually happened, according to the originating system. This
    is the only clock detections reason about. All windowing and sequencing is
    *event-time* semantics.

``observed_time``
    When ARIADNE first saw the event. The gap between the two is *lateness*; a
    large gap is what "the event arrived late" means, and it is what the
    streaming evaluator uses to decide whether an event is still admissible.

Field addressing is dotted. ``actor.user_id`` and ``device.id`` reach the
structured spine; a bare ``repository_sensitivity`` reaches ``attributes``. The
single :func:`resolve_field` helper is the only place that mapping lives, so the
DSL, the engine, the compilers, and the explanations all agree on what a field
name means.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

_SCALAR_TOP: frozenset[str] = frozenset(
    {"event_id", "event_type", "event_time", "observed_time"}
)
_STRUCTURED_ROOTS: frozenset[str] = frozenset({"actor", "device", "provenance"})


def _ensure_utc(value: datetime) -> datetime:
    """Coerce a datetime to timezone-aware UTC.

    Naive datetimes are interpreted as UTC rather than rejected; recorded
    telemetry is routinely naive and forcing tz on the way in keeps every
    downstream comparison total and deterministic.
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _descend(obj: Any, key: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, BaseModel):
        return getattr(obj, key, None)
    if isinstance(obj, dict):
        return obj.get(key)
    return None


class Provenance(BaseModel):
    """Where an event came from and how much we trust it.

    ``raw_ref`` points at the immutable evidence object (a MinIO key, a file
    offset) so that any conclusion ARIADNE draws can be walked back to the bytes
    that produced it. ``confidence`` is the collector's own trust in the record,
    independent of identity-resolution confidence.
    """

    model_config = ConfigDict(frozen=True)

    source: str
    collector: str | None = None
    ingested_at: datetime | None = None
    confidence: float = 1.0
    raw_ref: str | None = None

    @field_validator("ingested_at")
    @classmethod
    def _utc(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _ensure_utc(v)


class Actor(BaseModel):
    """The human or service principal an event is attributed to.

    ``principal_id`` is the *resolved* identity — the output of
    :mod:`ariadne.identity`. It may be absent in raw telemetry and filled in by
    normalization. ``user_id`` is whatever local identifier the source knew.
    """

    model_config = ConfigDict(frozen=True)

    user_id: str | None = None
    principal_id: str | None = None
    username: str | None = None
    email: str | None = None
    source_identity: str | None = None


class Device(BaseModel):
    """The endpoint, host, or infrastructure an event originated from."""

    model_config = ConfigDict(frozen=True)

    id: str | None = None
    hostname: str | None = None
    os: str | None = None
    enrolled: bool | None = None
    ip: str | None = None


class Event(BaseModel):
    """A single normalized telemetry record.

    Equality and hashing are by ``event_id`` so events drop cleanly into sets and
    deduplicate by identity. Use :meth:`content_fingerprint` when the *same*
    logical event is re-emitted under different ids by a flapping collector.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str
    event_type: str
    event_time: datetime
    observed_time: datetime | None = None
    actor: Actor = Field(default_factory=Actor)
    device: Device = Field(default_factory=Device)
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Field(
        default_factory=lambda: Provenance(source="unknown")
    )

    @field_validator("event_time")
    @classmethod
    def _utc_event_time(cls, v: datetime) -> datetime:
        return _ensure_utc(v)

    @field_validator("observed_time")
    @classmethod
    def _utc_observed_time(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _ensure_utc(v)

    # -- identity ---------------------------------------------------------

    def __hash__(self) -> int:  # noqa: D105 - hash by stable id
        return hash(self.event_id)

    def __eq__(self, other: object) -> bool:  # noqa: D105
        return isinstance(other, Event) and other.event_id == self.event_id

    @property
    def dedup_key(self) -> str:
        """Idempotency key. Two events with the same key are the same event."""

        return self.event_id

    def content_fingerprint(self) -> str:
        """A content hash that ignores ``event_id``.

        Collectors that reconnect sometimes replay a window of events with fresh
        ids. Deduplicating on this fingerprint collapses those true duplicates
        even though their surrogate ids differ.
        """

        payload = {
            "event_type": self.event_type,
            "event_time": self.event_time.isoformat(),
            "actor": self.actor.model_dump(exclude_none=True),
            "device": self.device.model_dump(exclude_none=True),
            "attributes": self.attributes,
        }
        blob = json.dumps(payload, sort_keys=True, default=str).encode()
        return hashlib.sha256(blob).hexdigest()

    @property
    def lateness_seconds(self) -> float | None:
        """How late this event was observed relative to when it happened."""

        if self.observed_time is None:
            return None
        return (self.observed_time - self.event_time).total_seconds()

    # -- field addressing -------------------------------------------------

    def resolve(self, path: str) -> Any:
        """Resolve a dotted field path against this event. See :func:`resolve_field`."""

        return resolve_field(self, path)

    def sort_key(self) -> tuple[datetime, str]:
        """The canonical ordering key.

        Sorting by ``(event_time, event_id)`` gives every collection of events a
        single deterministic order regardless of arrival order, which is what
        makes the engine's output invariant under shuffling.
        """

        return (self.event_time, self.event_id)


def resolve_field(event: Event, path: str) -> Any:
    """Resolve a dotted ``path`` against an :class:`Event`.

    Resolution order:

    1. Bare scalar spine fields (``event_type``, ``event_time``, ...).
    2. Dotted structured roots (``actor.*``, ``device.*``, ``provenance.*``).
    3. The flat ``attributes`` namespace, first by exact key then by descent.

    Returns ``None`` for anything absent. ``None`` is *meaningful*: it is how the
    engine learns that a field a detection depends on is missing, which is the
    raw material for "missing telemetry" reasoning.
    """

    parts = path.split(".")
    root = parts[0]

    if root in _SCALAR_TOP and len(parts) == 1:
        return getattr(event, root)

    if root in _STRUCTURED_ROOTS:
        cur: Any = getattr(event, root)
        for segment in parts[1:]:
            cur = _descend(cur, segment)
            if cur is None:
                return None
        return cur

    attributes = event.attributes
    if path in attributes:
        return attributes[path]

    cur = attributes
    for segment in parts:
        cur = _descend(cur, segment)
        if cur is None:
            return None
    return cur
