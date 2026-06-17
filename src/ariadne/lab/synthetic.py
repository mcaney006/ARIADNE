"""Deterministic synthetic telemetry: a small enterprise and its noise.

Everything here is seeded so a scenario regenerates byte-for-byte. The goal is
not volume for its own sake but *plausible ambiguity*: enough benign clones,
logins, processes, DNS lookups, and network flows from enough people and devices
that the malicious chain has to be found rather than handed over. The flagship
builders layer their incident on top of this background.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import Random
from typing import Any, Iterable

from ariadne.events.schema import Actor, Device, Event, Provenance

EPOCH = datetime(2026, 2, 2, 21, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str,
    event_type: str,
    offset_minutes: float,
    *,
    source: str,
    user_id: str | None = None,
    device_id: str | None = None,
    device_enrolled: bool | None = None,
    observed_offset_minutes: float | None = None,
    base: datetime = EPOCH,
    **attributes: Any,
) -> Event:
    """Construct one normalized event at ``base + offset_minutes``."""

    event_time = base + timedelta(minutes=offset_minutes)
    observed = (
        base + timedelta(minutes=observed_offset_minutes)
        if observed_offset_minutes is not None
        else event_time
    )
    return Event(
        event_id=event_id,
        event_type=event_type,
        event_time=event_time,
        observed_time=observed,
        actor=Actor(user_id=user_id) if user_id else Actor(),
        device=Device(id=device_id, enrolled=device_enrolled) if device_id else Device(),
        attributes=attributes,
        provenance=Provenance(source=source, collector=source),
    )


def write_jsonl(events: Iterable[Event], path: str | Path) -> int:
    """Write events as JSON lines in canonical order; return the count written."""

    ordered = sorted(events, key=Event.sort_key)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w") as handle:
        for event in ordered:
            handle.write(json.dumps(event.model_dump(mode="json"), default=str))
            handle.write("\n")
    return len(ordered)


class SyntheticEnterprise:
    """A seeded population of employees and devices that emits benign telemetry."""

    def __init__(self, seed: int = 1337, employees: int = 40) -> None:
        self.rng = Random(seed)
        self.people = [f"emp{idx:03d}" for idx in range(employees)]
        self.devices = {person: f"WS-{idx:03d}" for idx, person in enumerate(self.people)}
        self.repos_public = [f"svc-{name}" for name in ("api", "web", "billing", "auth", "infra", "data")]
        self._counter = 0

    def _eid(self) -> str:
        self._counter += 1
        return f"N{self._counter:06d}"

    def background_noise(self, count: int, *, window_minutes: int = 240) -> list[Event]:
        """Emit ``count`` benign events spread across the population and window."""

        events: list[Event] = []
        for _ in range(count):
            person = self.rng.choice(self.people)
            device = self.devices[person]
            offset = self.rng.uniform(0, window_minutes)
            events.append(self._noise_event(person, device, offset))
        return events

    def _noise_event(self, person: str, device: str, offset: float) -> Event:
        kind = self.rng.choices(
            ["login", "process", "clone", "dns", "network", "sudo"],
            weights=[2, 5, 2, 3, 3, 1],
        )[0]
        if kind == "login":
            return make_event(
                self._eid(), "identity.authentication", offset, source="okta",
                user_id=person, device_id=device, device_enrolled=True,
                result="success", infrastructure_is_unusual=False,
            )
        if kind == "process":
            return make_event(
                self._eid(), "process.execution", offset, source="osquery",
                user_id=person, device_id=device, device_enrolled=True,
                process_name=self.rng.choice(["git", "python", "node", "bash", "ls", "code"]),
            )
        if kind == "clone":
            return make_event(
                self._eid(), "github.repository.clone", offset, source="github_audit",
                user_id=person, device_id=device, device_enrolled=True,
                repository=self.rng.choice(self.repos_public),
                repository_sensitivity="normal", access_is_first_seen=False,
            )
        if kind == "dns":
            return make_event(
                self._eid(), "dns.query", offset, source="zeek",
                user_id=person, device_id=device,
                query=self.rng.choice(["github.com", "pypi.org", "slack.com", "datadog.com"]),
            )
        if kind == "network":
            return make_event(
                self._eid(), "network.connection", offset, source="zeek",
                user_id=person, device_id=device,
                bytes_out=self.rng.randint(1_000, 200_000),
                destination="corp-internal",
            )
        return make_event(
            self._eid(), "sudo.command", offset, source="auditd",
            user_id=person, device_id=device, device_enrolled=True,
            command=self.rng.choice(["apt", "systemctl", "docker"]),
        )


def background_noise(count: int, *, seed: int = 1337) -> list[Event]:
    """Convenience: a fresh enterprise's benign noise."""

    return SyntheticEnterprise(seed=seed).background_noise(count)
