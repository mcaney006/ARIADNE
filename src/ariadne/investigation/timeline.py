"""Timeline reconstruction and telemetry-gap detection.

The timeline is the ordered event thread an analyst reads. Beyond simply sorting
events, it surfaces *negative* structure: moments where one telemetry source went
dark while another kept reporting. An endpoint agent that stops while the network
sensor still sees the same device upload data is not "the machine turned off" —
it is selective blinding, which is a strong insider-risk signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ariadne.events.schema import Event

#: Event types that indicate a telemetry source stopped reporting.
_TELEMETRY_STOP_STATES = {"stopped", "disabled", "degraded"}
#: Sources that, if still emitting after a stop, prove the device stayed active.
_LIVE_SOURCES = {"zeek", "network", "cloudtrail", "github_audit", "okta"}


@dataclass(frozen=True)
class TimelineEntry:
    """One row in the reconstructed timeline."""

    at: datetime
    event_id: str
    event_type: str
    summary: str
    is_gap: bool = False

    def render(self) -> str:
        marker = "  ⚠ " if self.is_gap else "    "
        return f"{self.at.isoformat()}{marker}{self.summary}  [{self.event_id}]"


@dataclass
class Timeline:
    """An ordered timeline with telemetry-gap annotations."""

    entries: list[TimelineEntry] = field(default_factory=list)

    @classmethod
    def from_events(cls, events: list[Event]) -> "Timeline":
        ordered = sorted(events, key=Event.sort_key)
        entries = [
            TimelineEntry(
                at=event.event_time,
                event_id=event.event_id,
                event_type=event.event_type,
                summary=_summarise(event),
            )
            for event in ordered
        ]
        entries.extend(_detect_telemetry_gaps(ordered))
        entries.sort(key=lambda e: (e.at, e.is_gap, e.event_id))
        return cls(entries=entries)

    def render(self) -> str:
        return "\n".join(entry.render() for entry in self.entries)


def _summarise(event: Event) -> str:
    attrs = event.attributes
    if event.event_type == "github.repository.clone":
        repo = attrs.get("repository") or attrs.get("repository_name") or "?"
        return f"clone {repo} (sensitivity={attrs.get('repository_sensitivity', '?')})"
    if event.event_type == "process.execution":
        return f"process {attrs.get('process_name', '?')}"
    if event.event_type == "filesystem.write":
        return f"write to {attrs.get('destination_type', '?')} {attrs.get('path', '')}".strip()
    if event.event_type == "security.telemetry_state":
        return f"telemetry {attrs.get('state', '?')} ({attrs.get('source', '?')})"
    if event.event_type == "github.token.create":
        return "GitHub access token created"
    if event.event_type == "filesystem.delete" and "history" in str(attrs.get("path", "")):
        return f"shell history deleted ({attrs.get('path')})"
    return event.event_type


def _detect_telemetry_gaps(ordered: list[Event]) -> list[TimelineEntry]:
    gaps: list[TimelineEntry] = []
    for index, event in enumerate(ordered):
        if event.event_type != "security.telemetry_state":
            continue
        if event.attributes.get("state") not in _TELEMETRY_STOP_STATES:
            continue
        stopped_source = event.attributes.get("telemetry_source", "endpoint")
        still_live = [
            later
            for later in ordered[index + 1 :]
            if (later.provenance.source in _LIVE_SOURCES)
            and later.attributes.get("telemetry_source") != stopped_source
        ]
        if still_live:
            survivor = still_live[0]
            gaps.append(
                TimelineEntry(
                    at=event.event_time,
                    event_id=event.event_id,
                    event_type="telemetry.gap",
                    summary=(
                        f"{stopped_source} telemetry stopped while "
                        f"{survivor.provenance.source} stayed live — selective blinding"
                    ),
                    is_gap=True,
                )
            )
    return gaps
