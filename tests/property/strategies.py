"""Hypothesis strategies that synthesise plausible, messy event streams.

These generate the inputs the determinism properties hammer on: streams that may
or may not fire, built from randomized clone bursts, optional staging steps,
multiple actors, and benign noise. The point is breadth — the engine must be
deterministic over *any* of these, firing or not.
"""

from __future__ import annotations

from datetime import timedelta

from hypothesis import strategies as st

from tests.conftest import BASE, ev


@st.composite
def event_streams(draw):
    """A randomized stream of events for one or more actors."""

    events = []
    actors = draw(st.lists(st.sampled_from(["mcaney", "rlee", "jdoe"]), min_size=1, max_size=3, unique=True))

    for actor in actors:
        n_clones = draw(st.integers(min_value=0, max_value=14))
        sensitivity = draw(st.sampled_from(["restricted", "normal"]))
        first_seen = draw(st.booleans())
        spread = draw(st.floats(min_value=1.0, max_value=20.0))
        for index in range(n_clones):
            offset = index * (spread / max(n_clones, 1))
            events.append(
                ev(
                    f"{actor}-C{index}",
                    "github.repository.clone",
                    offset,
                    user=actor,
                    device=f"WS-{actor}",
                    source="github_audit",
                    repository_sensitivity=sensitivity,
                    access_is_first_seen=first_seen,
                )
            )
        if draw(st.booleans()):
            events.append(ev(f"{actor}-P", "process.execution", draw(st.floats(16, 30)), user=actor, device=f"WS-{actor}", process_name="gpg"))
        if draw(st.booleans()):
            events.append(ev(f"{actor}-W", "filesystem.write", draw(st.floats(31, 40)), user=actor, device=f"WS-{actor}", destination_type="removable_media"))
        if draw(st.booleans()):
            events.append(ev(f"{actor}-T", "security.telemetry_state", draw(st.floats(41, 44)), user=actor, device=f"WS-{actor}", state="stopped"))

    # Benign noise that should never affect a verdict.
    for index in range(draw(st.integers(min_value=0, max_value=20))):
        events.append(
            ev(
                f"noise-{index}",
                "process.execution",
                draw(st.floats(0, 44)),
                user=draw(st.sampled_from(["zoe", "amir", "lin"])),
                device="WS-noise",
                process_name="bash",
            )
        )
    return events


@st.composite
def firing_streams(draw):
    """A stream guaranteed to fire the flagship detection (for minimality tests)."""

    n_clones = draw(st.integers(min_value=8, max_value=16))
    spread = draw(st.floats(min_value=1.0, max_value=14.0))
    events = []
    for index in range(n_clones):
        offset = index * (spread / n_clones)
        events.append(
            ev(
                f"C{index}",
                "github.repository.clone",
                offset,
                source="github_audit",
                repository_sensitivity="restricted",
                access_is_first_seen=True,
            )
        )
    events.append(ev("P", "process.execution", 16, process_name="gpg"))
    events.append(ev("W", "filesystem.write", 18, destination_type="removable_media"))
    events.append(ev("T", "security.telemetry_state", 20, state="stopped"))
    return events
