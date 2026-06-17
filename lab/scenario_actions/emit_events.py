"""Map a log of real benign lab actions onto normalized ARIADNE events.

The lab scenario script performs actual activity against disposable decoy
resources and appends one structured line per action to ``actions.jsonl``. This
script reads that log and emits the corresponding normalized event stream plus a
scenario manifest, so the *real activity* — not a hand-written fixture — is what
the detection then has to catch.

Usage::

    python emit_events.py <actions.jsonl> <output_scenario_dir> [actor] [device]
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from ariadne.events.schema import Actor, Device, Event, Provenance


def _event(action: dict, index: int, actor: str, device: str) -> Event | None:
    kind = action["kind"]
    ts = datetime.fromtimestamp(float(action["ts"]), tz=timezone.utc)
    eid = f"LAB{index:04d}"
    common = dict(
        event_id=eid,
        event_time=ts,
        actor=Actor(user_id=actor),
        device=Device(id=device, enrolled=True),
    )

    if kind == "clone":
        return Event(
            event_type="github.repository.clone",
            attributes={
                "repository": action.get("repo"),
                "repository_sensitivity": "restricted",
                "access_is_first_seen": True,
            },
            provenance=Provenance(source="github_audit"),
            **common,
        )
    if kind == "archive":
        return Event(
            event_type="process.execution",
            attributes={"process_name": action.get("tool", "tar"), "command_line": action.get("cmd")},
            provenance=Provenance(source="osquery"),
            **common,
        )
    if kind == "stage":
        return Event(
            event_type="filesystem.write",
            attributes={"destination_type": "removable_media", "path": action.get("path")},
            provenance=Provenance(source="osquery"),
            **common,
        )
    if kind == "telemetry_stop":
        return Event(
            event_type="security.telemetry_state",
            attributes={"state": "stopped", "telemetry_source": "endpoint"},
            provenance=Provenance(source="osquery"),
            **common,
        )
    if kind == "history_delete":
        return Event(
            event_type="filesystem.delete",
            attributes={"path": action.get("path", "~/.bash_history")},
            provenance=Provenance(source="osquery"),
            **common,
        )
    return None


def main() -> None:
    actions_path = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    actor = sys.argv[3] if len(sys.argv) > 3 else "lab-user"
    device = sys.argv[4] if len(sys.argv) > 4 else "LAB-WS-01"

    events: list[Event] = []
    for index, line in enumerate(actions_path.read_text().splitlines()):
        line = line.strip()
        if not line:
            continue
        event = _event(json.loads(line), index, actor, device)
        if event is not None:
            events.append(event)

    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "events.jsonl").open("w") as handle:
        for event in sorted(events, key=Event.sort_key):
            handle.write(json.dumps(event.model_dump(mode="json"), default=str) + "\n")

    manifest = {
        "id": "lab-source-code-exfiltration",
        "title": "Lab: source-code exfiltration (real decoy activity)",
        "description": "Events emitted from real benign actions against disposable decoys.",
        "detections": ["ARI-IR-0042"],
        "facts": {"legitimate_access": True},
        "expected": {"cases": 1, "detections_triggered": 1, "primary_hypothesis": "H1"},
    }
    (out_dir / "scenario.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"emitted {len(events)} events to {out_dir}")


if __name__ == "__main__":
    main()
