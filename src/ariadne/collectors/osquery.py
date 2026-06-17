"""osquery -> normalized event.

osquery emits one JSON object per scheduled-query row, with the interesting
fields under ``columns`` and the wall-clock under ``unixTime``. This maps a
process-events row onto ``process.execution`` and carries the ancestry and
working directory into attributes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ariadne.events.schema import Actor, Device, Event, Provenance


def from_osquery_row(row: dict[str, Any]) -> Event:
    columns = row.get("columns", {})
    event_time = datetime.fromtimestamp(int(row.get("unixTime", 0)), tz=timezone.utc)
    return Event(
        event_id=row.get("eventid") or f"osq-{row.get('unixTime')}-{columns.get('pid', '')}",
        event_type="process.execution",
        event_time=event_time,
        actor=Actor(user_id=columns.get("username"), source_identity=columns.get("uid")),
        device=Device(id=row.get("hostIdentifier"), hostname=row.get("hostIdentifier"), os="linux", enrolled=True),
        attributes={
            "process_name": columns.get("name") or columns.get("path", "").rsplit("/", 1)[-1],
            "command_line": columns.get("cmdline"),
            "pid": columns.get("pid"),
            "parent_pid": columns.get("parent"),
            "cwd": columns.get("cwd"),
        },
        provenance=Provenance(source="osquery", collector="osquery", raw_ref=row.get("name")),
    )
