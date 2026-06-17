"""Idempotent per-join-key accumulation for the streaming evaluator.

The streaming path must be idempotent: replaying the same event — a duplicate, a
collector that reconnected and re-sent its buffer — must not change state. The
:class:`JoinBuffer` enforces that by keying admitted events on their dedup key,
so a second copy is a no-op. The buffer holds events in arbitrary arrival order;
canonical ordering happens at read time, which is what lets the streaming and
batch paths converge on the same answer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ariadne.events.schema import Event
from ariadne.events.normalization import canonical_order


@dataclass
class JoinBuffer:
    """An idempotent set of admitted events, grouped logically by join key."""

    _events: dict[str, Event] = field(default_factory=dict)

    def admit(self, event: Event) -> bool:
        """Admit an event. Returns ``False`` if it was already present."""

        key = event.dedup_key
        if key in self._events:
            return False
        self._events[key] = event
        return True

    def __len__(self) -> int:
        return len(self._events)

    def ordered(self) -> list[Event]:
        """The admitted events in canonical (event-time) order."""

        return canonical_order(self._events.values())
