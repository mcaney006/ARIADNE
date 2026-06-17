"""Zeek conn.log -> normalized event.

Zeek's ``conn.log`` records one row per connection with ``ts`` (epoch seconds),
endpoints, and byte counts. This maps it onto ``network.connection`` and keeps
the upload volume, which is what the upload-volume and first-seen-destination
signals read.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ariadne.events.schema import Device, Event, Provenance


def from_zeek_conn(row: dict[str, Any]) -> Event:
    event_time = datetime.fromtimestamp(float(row.get("ts", 0)), tz=timezone.utc)
    return Event(
        event_id=row.get("uid") or f"zeek-{row.get('ts')}",
        event_type="network.connection",
        event_time=event_time,
        device=Device(id=row.get("id.orig_h"), ip=row.get("id.orig_h")),
        attributes={
            "destination": row.get("id.resp_h"),
            "destination_port": row.get("id.resp_p"),
            "bytes_out": row.get("orig_bytes"),
            "bytes_in": row.get("resp_bytes"),
            "proto": row.get("proto"),
        },
        provenance=Provenance(source="zeek", collector="zeek", raw_ref=row.get("uid")),
    )
