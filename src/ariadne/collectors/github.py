"""GitHub audit log -> normalized event.

The GitHub audit log keys each entry on an ``action`` (``git.clone``,
``personal_access_token.create``, ...) with an ``@timestamp`` in milliseconds.
This maps the two actions ARIADNE's insider and compromise rules care about and
leaves the rest as a generic passthrough.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ariadne.events.schema import Actor, Event, Provenance

_ACTION_MAP = {
    "git.clone": "github.repository.clone",
    "personal_access_token.create": "github.token.create",
}


def from_github_audit_record(record: dict[str, Any]) -> Event:
    action = record.get("action", "")
    event_type = _ACTION_MAP.get(action, f"github.{action}")
    millis = int(record.get("@timestamp", 0))
    event_time = datetime.fromtimestamp(millis / 1000.0, tz=timezone.utc)

    attributes: dict[str, Any] = {}
    if event_type == "github.repository.clone":
        attributes["repository"] = record.get("repo")
        attributes["repository_sensitivity"] = record.get("repository_visibility", "normal")
    if event_type == "github.token.create":
        attributes["token_name"] = record.get("token_name")
        attributes["scopes"] = record.get("scopes")

    return Event(
        event_id=record.get("_document_id") or f"gh-{millis}-{record.get('actor')}",
        event_type=event_type,
        event_time=event_time,
        actor=Actor(user_id=record.get("actor"), email=record.get("actor_email")),
        attributes=attributes,
        provenance=Provenance(source="github_audit", collector="github", raw_ref=record.get("_document_id")),
    )
