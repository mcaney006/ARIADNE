"""Deriving the named signals that hypotheses reason over.

Signals are the bridge between raw events and the explainable hypothesis model.
Most are read straight off the events that contributed to (or surround) a
firing; some — "the auth came from unusual infrastructure", "the enrolled device
showed no endpoint activity", "this is the security team testing" — are context
that the engine cannot know from telemetry alone and must be supplied as
scenario *facts*. Facts always win over computed values so an investigator can
assert ground truth the sensors missed.
"""

from __future__ import annotations

from typing import Any

from ariadne.engines.reference import SequenceMatch
from ariadne.events.schema import Event, resolve_field

_ARCHIVE_TOOLS = {"zip", "7z", "tar", "gpg", "rar", "openssl"}
_TELEMETRY_STOP = {"stopped", "disabled", "degraded"}
_REMOVABLE = {"removable_media", "cloud_sync_folder", "usb"}


def compute_signals(
    match: SequenceMatch,
    actor_events: list[Event],
    facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute the signal dictionary for a firing.

    ``actor_events`` is the actor-scoped event slice (everything attributed to
    the same person within the data), which lets signals see context beyond the
    minimal chain — a token created before collection began, for instance.
    """

    contributing = match.contributing_events
    signals: dict[str, Any] = {}

    clones = [e for e in actor_events if e.event_type == "github.repository.clone"]
    restricted = [e for e in clones if e.attributes.get("repository_sensitivity") == "restricted"]
    signals["bulk_restricted_clone"] = len(restricted) >= 5 or any(
        e.event_type == "github.repository.clone" for e in contributing
    )
    signals["first_seen_access"] = any(e.attributes.get("access_is_first_seen") for e in clones)

    signals["archive_created"] = any(
        e.event_type == "process.execution"
        and e.attributes.get("process_name") in _ARCHIVE_TOOLS
        for e in actor_events
    )
    signals["removable_media_write"] = any(
        e.event_type == "filesystem.write"
        and e.attributes.get("destination_type") in _REMOVABLE
        for e in actor_events
    )

    telemetry_stops = [
        e
        for e in actor_events
        if e.event_type == "security.telemetry_state"
        and e.attributes.get("state") in _TELEMETRY_STOP
    ]
    signals["endpoint_telemetry_stopped"] = any(
        e.attributes.get("telemetry_source", "endpoint") in {"endpoint", "osquery", "edr"}
        for e in telemetry_stops
    )
    signals["logging_disabled"] = bool(telemetry_stops)

    signals["shell_history_deleted"] = any(
        (e.event_type in {"filesystem.delete", "shell.history.clear"})
        and "history" in str(e.attributes.get("path", e.event_type))
        for e in actor_events
    )
    signals["new_token_created"] = any(
        e.event_type in {"github.token.create", "identity.token.create"} for e in actor_events
    )
    signals["cloud_object_retrieval"] = any(
        e.event_type in {"aws.s3.get_object", "cloud.object.retrieve"}
        or "GetObject" in e.event_type
        for e in actor_events
    )
    signals["temp_identity_created"] = any(
        e.event_type in {"iam.user.create", "identity.principal.create"} for e in actor_events
    )
    signals["temp_identity_deleted"] = any(
        e.event_type in {"iam.user.delete", "identity.principal.delete"} for e in actor_events
    )

    device_enrolled = any(
        resolve_field(e, "device.enrolled") is True for e in contributing
    )
    signals["device_enrolled"] = device_enrolled

    if facts:
        signals.update(facts)
    return signals
