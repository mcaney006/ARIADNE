"""Shared fixtures and builders for the ARIADNE test suite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ariadne.events.schema import Actor, Device, Event, Provenance
from ariadne.rules import Absence, Count, Detection, Event as Pattern, Sequence

BASE = datetime(2026, 2, 2, 22, 0, 0, tzinfo=timezone.utc)


def ev(
    event_id: str,
    event_type: str,
    minute: float,
    *,
    user: str = "mcaney",
    device: str = "WS-1",
    enrolled: bool = True,
    source: str = "osquery",
    **attrs,
) -> Event:
    """Construct a normalized event at ``BASE + minute`` minutes."""

    return Event(
        event_id=event_id,
        event_type=event_type,
        event_time=BASE + timedelta(minutes=minute),
        actor=Actor(user_id=user),
        device=Device(id=device, enrolled=enrolled),
        attributes=attrs,
        provenance=Provenance(source=source),
    )


def repository_collection_detection() -> Detection:
    """The flagship detection, built in-process so unit tests don't touch disk."""

    return Detection(
        id="ARI-IR-0042",
        title="Restricted repository collection followed by data staging",
        severity="critical",
        join_by=("actor.user_id", "device.id"),
        sequence=Sequence(
            within="45m",
            steps=[
                Count(
                    Pattern("github.repository.clone").where(
                        repository_sensitivity="restricted",
                        access_is_first_seen=True,
                    ),
                    at_least=8,
                    within="15m",
                ),
                Pattern("process.execution").where(process_name__in={"zip", "7z", "tar", "gpg"}),
                Pattern("filesystem.write").where(
                    destination_type__in={"removable_media", "cloud_sync_folder"}
                ),
                Pattern("security.telemetry_state").where(
                    state__in={"stopped", "disabled", "degraded"}
                ),
            ],
        ),
        exceptions=[
            Absence(
                Pattern("change_management.approval").where(approval_status="approved"),
                within="24h",
            )
        ],
    )


def firing_chain(*, clones: int = 10) -> list[Event]:
    """A minimal event stream that fires the flagship detection."""

    events: list[Event] = []
    for index in range(clones):
        events.append(
            ev(
                f"E{1000 + index}",
                "github.repository.clone",
                index * 0.5,
                source="github_audit",
                repository=f"restricted/proj-{index}",
                repository_sensitivity="restricted",
                access_is_first_seen=True,
            )
        )
    events.append(ev("E2000", "process.execution", 16, process_name="gpg"))
    events.append(ev("E2001", "filesystem.write", 18, destination_type="removable_media"))
    events.append(ev("E2002", "security.telemetry_state", 20, state="stopped", telemetry_source="endpoint"))
    return events


@pytest.fixture
def detection() -> Detection:
    return repository_collection_detection()


@pytest.fixture
def chain() -> list[Event]:
    return firing_chain()
