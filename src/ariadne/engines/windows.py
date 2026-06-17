"""Event-time windowing and watermark tracking.

Security telemetry does not arrive in order. The watermark is ARIADNE's estimate
of "event-time has progressed at least this far"; anything older than
``watermark - allowed_lateness`` is considered unrecoverably late and is dropped
rather than allowed to retroactively change a closed window. Everything inside
the allowed-lateness band is admitted and folded into the deterministic batch
core, so late-but-admissible events change the result the same way no matter when
they show up.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ariadne.events.schema import Event


@dataclass
class WatermarkTracker:
    """Tracks event-time progress and decides what is too late to admit.

    The watermark is ``max(event_time seen) - allowed_lateness``. An event is
    *too late* when its own event_time is strictly below the current watermark:
    by then the window it belonged to is assumed closed.
    """

    allowed_lateness: timedelta = timedelta(0)
    _max_event_time: datetime | None = field(default=None, init=False)

    @property
    def watermark(self) -> datetime | None:
        if self._max_event_time is None:
            return None
        return self._max_event_time - self.allowed_lateness

    def observe(self, event: Event) -> None:
        """Advance the watermark by folding in a newly seen event."""

        if self._max_event_time is None or event.event_time > self._max_event_time:
            self._max_event_time = event.event_time

    def is_too_late(self, event: Event) -> bool:
        """Whether ``event`` arrived after its window is assumed closed."""

        mark = self.watermark
        return mark is not None and event.event_time < mark


def within_span(events: list[Event], span: timedelta) -> bool:
    """Whether all events fit inside a single ``span``-wide window."""

    if not events:
        return True
    times = [e.event_time for e in events]
    return (max(times) - min(times)) <= span


def earliest_count_window(
    candidates: list[Event], at_least: int, within: timedelta
) -> list[Event] | None:
    """Find the earliest run of ``at_least`` events spanning at most ``within``.

    ``candidates`` must already be in canonical (event-time) order. Because the
    tightest window over a sorted series is always a contiguous slice, scanning
    consecutive slices and returning the first admissible one yields both the
    *earliest* completion time and a deterministic choice of events.
    """

    if at_least <= 0:
        return []
    n = len(candidates)
    if n < at_least:
        return None
    for start in range(0, n - at_least + 1):
        window = candidates[start : start + at_least]
        if (window[-1].event_time - window[0].event_time) <= within:
            return window
    return None
