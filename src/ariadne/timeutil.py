"""Duration parsing and formatting shared across the DSL, engine, and replay lab.

Detections are written with compact duration strings — ``"45m"``, ``"15m"``,
``"24h"`` — and ARIADNE normalizes them to :class:`datetime.timedelta` exactly
once, here, so every component agrees on what ``"45m"`` means.
"""

from __future__ import annotations

import re
from datetime import timedelta

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)\s*$")

_UNIT_SECONDS: dict[str, float] = {
    "ms": 0.001,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 604800.0,
}


def parse_duration(value: str | timedelta | int | float) -> timedelta:
    """Parse a compact duration into a :class:`~datetime.timedelta`.

    Accepts an existing ``timedelta`` (returned unchanged), a number of seconds,
    or a string like ``"30s"``, ``"15m"``, ``"24h"``, ``"7d"``.
    """

    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)):
        return timedelta(seconds=float(value))
    match = _DURATION_RE.match(value)
    if not match:
        raise ValueError(f"invalid duration: {value!r} (try '45m', '24h', '7d')")
    magnitude, unit = match.groups()
    return timedelta(seconds=float(magnitude) * _UNIT_SECONDS[unit])


def format_duration(delta: timedelta) -> str:
    """Render a ``timedelta`` back into a compact unit (or compound h/m/s)."""

    total = delta.total_seconds()
    if total == 0:
        return "0s"
    # Prefer an exact single unit when the duration divides cleanly.
    for unit in ("w", "d", "h", "m", "s"):
        size = _UNIT_SECONDS[unit]
        if total % size == 0 and total >= size:
            return f"{int(total // size)}{unit}"
    # Otherwise fall back to a compound h/m/s rendering.
    seconds = int(round(total))
    parts: list[str] = []
    for unit in ("h", "m", "s"):
        size = int(_UNIT_SECONDS[unit])
        if seconds >= size:
            quantity, seconds = divmod(seconds, size)
            parts.append(f"{quantity}{unit}")
    return "".join(parts) if parts else f"{total:g}s"
